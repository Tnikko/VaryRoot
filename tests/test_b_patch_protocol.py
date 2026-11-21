import json
import unittest

from varyroot.b_prompt import render_messages
from varyroot.b_static_retry import apply_local_patch, run


def spec(symbol):
    return {"clauses": [{"field": "Guard", "direction": "iff", "bindings": {symbol: "bool"},
                         "applicability": True, "antecedent": {"var": symbol}}]}


class LocalPatchProtocolTest(unittest.TestCase):
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
