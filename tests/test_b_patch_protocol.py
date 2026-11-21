import json
import shutil
import tempfile
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import ast_semantic_sha256, clang_ast, clang_token_sha256
from varyroot.b_prompt import render_messages
from varyroot.b_static_retry import apply_local_patch, run


def spec(symbol):
    return {"clauses": [{"field": "Guard", "direction": "iff", "bindings": {symbol: "bool"},
                         "applicability": True, "antecedent": {"var": symbol}}]}


class LocalPatchProtocolTest(unittest.TestCase):
    def test_ast_exclusion_requires_ast_fingerprint_producer(self):
        policy = {"model": "offline", "max_tokens": 100, "max_retries": 0,
                  "max_proposals_per_round": 1, "min_divergent": 1,
                  "excluded_ast_sha256": ["0" * 64]}
        with self.assertRaisesRegex(ValueError, "ast_fingerprint_producer_required"):
            run("int f(){return 0;}", "int f(){return 1;}",
                {"object": "span", "operation": "read"}, spec("width"), spec("capacity"),
                policy, lambda request: self.fail("provider should not be called"),
                lambda source, parent: self.fail("inspector should not be called"))

    def test_static_extractor_gap_is_counted_even_with_specific_reason(self):
        proposal = {"parent": "before", "factor": "guard", "intent": "unresolved bound",
                    "old_code": "n>0", "new_code": "n>sizeof(n)"}
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                    "predictions": None, "static_error": "unevaluated_interval_bound"}
        result = run("int f(int n){if(n>0)return 1;return 0;}",
                     "int f(int n){if(n>4)return 1;return 0;}",
                     {"object": "span", "operation": "read"}, spec("width"), spec("capacity"),
                     {"model": "offline", "max_tokens": 100, "max_retries": 0,
                      "max_proposals_per_round": 1, "min_divergent": 1},
                     lambda request: {"proposals": [proposal]}, inspect)
        self.assertEqual(result["rows"][0]["reason"], "unevaluated_interval_bound")
        self.assertEqual(result["backend_gap"], 1)

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_ast_equivalent_history_and_round_duplicates_share_one_gate(self):
        before = "int parse(int n){if(n>0)return 1;return 0;}\n"
        after = before.replace("n>0", "n>4")
        with tempfile.TemporaryDirectory() as folder:
            serial = 0
            def fingerprint(source):
                nonlocal serial
                serial += 1
                path = Path(folder) / f"source-{serial}.c"
                path.write_text(source)
                ast, status = clang_ast(["clang-18", "-c", str(path), "-o", str(path) + ".o"],
                                        folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                return {"token_sha256": clang_token_sha256(source),
                        "ast_sha256": ast_semantic_sha256(ast)}
            history = fingerprint("int parse(int n) { if ((n > 1)) return 1; return 0; }\n")
            proposal = {"parent": "before", "factor": "guard", "intent": "bound",
                        "old_code": "n>0", "new_code": "(n>1)"}
            policy = {"model": "offline", "max_tokens": 100, "max_retries": 0,
                      "max_proposals_per_round": 1, "min_divergent": 1,
                      "excluded_ast_sha256": [history["ast_sha256"]]}
            def no_inspect(source, parent):
                self.fail("historically equivalent source entered factor gate")
            contract = {"object": "slot", "operation": "read"}
            result = run(before, after, contract, spec("check_seen"), spec("blocked"), policy,
                         lambda request: {"proposals": [proposal]}, no_inspect,
                         semantic_fingerprint=fingerprint)
            self.assertEqual(result["rows"][0]["reason"], "historical_excluded")
            policy.pop("excluded_ast_sha256")
            policy["max_retries"] = 1
            policy["min_divergent"] = 2
            proposals = iter([proposal, dict(proposal, new_code="n>1")])
            def inspect(source, parent):
                return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                        "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                        "predictions": ["report", "quiet"]}
            result = run(before, after, contract, spec("check_seen"), spec("blocked"), policy,
                         lambda request: {"proposals": [next(proposals)]}, inspect,
                         semantic_fingerprint=fingerprint)
            self.assertEqual([row["status"] for row in result["rows"]], ["admitted", "rejected"])
            self.assertEqual(result["rows"][1]["reason"], "duplicate_or_unchanged_source")

    def test_fact_semantics_ground_only_bound_symbols(self):
        task = json.loads(render_messages("int f(void){return 0;}", "int f(void){return 1;}",
                                          {"object": "slot", "operation": "read"},
                                          spec("check_seen"), spec("blocked"))[1]["content"])
        self.assertEqual(set(task["fact_semantics"]), {"check_seen", "blocked"})
        self.assertIn("analysis", task["fact_semantics"]["check_seen"].lower())
        self.assertIn("old_code", task["instructions"])
        self.assertIn("new_code", task["instructions"])
        self.assertNotIn("source", task["instructions"].split("Each proposal")[1])

    def test_unique_patch_reconstructs_source_and_rejects_ambiguous_target(self):
        self.assertEqual(apply_local_patch("a\nb\nc\n", "b\n", "x\n"),
                         ("a\nx\nc\n", None))
        self.assertEqual(apply_local_patch("a\na\n", "a\n", "x\n")[1],
                         "patch_target_not_unique")
        self.assertEqual(apply_local_patch("a\n", "missing", "x")[1],
                         "patch_target_not_unique")
        self.assertEqual(apply_local_patch("a\n", "a", "a")[1],
                         "duplicate_or_unchanged_source")

    def test_retry_keeps_patch_fields_and_full_source(self):
        proposal = {"parent": "before", "factor": "guard", "intent": "one change",
                    "old_code": "if (a)", "new_code": "if (b)"}
        def inspect(source, parent):
            self.assertEqual(source, "int f(){if (b) return 0;}")
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                    "predictions": ["report", "quiet"]}
        result = run("int f(){if (a) return 0;}", "int f(){if (c) return 0;}",
                     {"object": "slot", "operation": "read"},
                     spec("check_seen"), spec("blocked"),
                     {"model": "offline", "max_tokens": 100, "max_retries": 0,
                      "max_proposals_per_round": 1, "min_divergent": 1},
                     lambda request: {"proposals": [proposal]}, inspect)
        row = result["rows"][0]
        self.assertEqual(row["source"], "int f(){if (b) return 0;}")
        self.assertEqual((row["old_code"], row["new_code"]), ("if (a)", "if (b)"))


if __name__ == "__main__":
    unittest.main()
