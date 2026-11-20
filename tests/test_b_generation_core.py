import json
import hashlib
import unittest

from varyroot.b_prompt import render_messages, hypothesis_pair
from varyroot.b_factor_gate import classify
from varyroot.b_static_retry import run


def spec(op):
    return {"clauses": [{"id": "private", "field": "Guard", "direction": "iff",
                         "bindings": {"reaches": "bool"},
                         "applicability": True,
                         "antecedent": {"op": op, "args": [{"var": "reaches"}, True]},
                         "source_lock": {"url": "https://audit.invalid"}}]}


CONTRACT = {"object": "output slot", "extent": "declared bound",
            "unit": "bytes", "operation": "read", "source_lock": "audit only"}


class BGenerationCoreTest(unittest.TestCase):
    def test_prompt_uses_only_reasoning_view(self):
        messages = render_messages("int before(void) { return 0; }",
                                   "int after(void) { return 1; }", CONTRACT,
                                   spec("and"), spec("or"))
        payload = json.loads(messages[1]["content"])
        self.assertEqual(set(payload), {"before", "after", "contract", "hypotheses", "instructions"})
        serialized = json.dumps(messages)
        for audit in ("source_lock", "https://audit.invalid", '"id": "private"'):
            self.assertNotIn(audit, serialized)
        self.assertEqual(payload["hypotheses"]["difference"]["Guard"]["first_only"][0]["antecedent"]["op"], "and")
        self.assertEqual(payload["hypotheses"]["first"]["Guard"][0]["bindings"], {"reaches": "bool"})

    def test_gate_keeps_uncertain_goto_out_of_admitted(self):
        base = {"producer": "clang_ast", "compile_ok": True,
                "target_binding": "exact_1to1",
                "edit_groups": [{"roles": ["control_flow"], "contains_goto": True}]}
        self.assertEqual(classify(base)["status"], "undetermined")
        base["cfg"] = {"producer": "clang_cfg", "target_reachability_changed": False,
                       "equivalent_blocking": True}
        self.assertEqual(classify(base)["status"], "admitted")
        base["edit_groups"].append({"roles": ["guard"]})
        self.assertEqual(classify(base)["status"], "confounded")

    def test_static_retry_tracks_every_candidate_without_oracle_labels(self):
        requests = []
        def invoke(request):
            requests.append(request)
            return {"proposals": [{"parent": "before", "factor": "guard",
                                   "intent": "local", "source": "variant" + str(len(requests))}]}
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                    "predictions": ("report", "quiet") if len(requests) == 2 else ("quiet", "quiet")}
        result = run("before", "after", CONTRACT, spec("and"), spec("or"),
                     {"max_retries": 1, "min_hard_divergent": 1,
                      "model": "fixture-model", "max_tokens": 1024,
                      "max_proposals_per_round": 4}, invoke, inspect)
        self.assertEqual((result["raw"], result["admitted"], result["hard_divergent"],
                          result["retry_rounds"]), (2, 2, 1, 1))
        self.assertEqual(json.loads(requests[1]["messages"][1]["content"])["static_feedback"],
                         [{"index": 0, "intent": "local", "reason": "same_static_prediction",
                           "touched_roles": ["guard"], "predictions": ["quiet", "quiet"]}])
        self.assertNotIn('\\"label\\":', json.dumps(requests))

    def test_deduplicates_across_rounds_and_preserves_source_fields(self):
        responses = [
            {"proposals": [{"parent": "before", "factor": "guard", "intent": "a", "source": "before"},
                           {"parent": "else", "factor": "guard", "intent": "b", "source": "new"},
                           {"parent": "after", "factor": "guard", "intent": "c", "source": "unique\r\n"}]},
            {"proposals": [{"parent": "after", "factor": "guard", "intent": "d", "source": "unique\n"}]},
        ]
        calls = []
        def invoke(request):
            calls.append(request)
            return responses[len(calls)-1]
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                    "predictions": ["report", "uncovered"]}
        policy = {"max_retries": 1, "min_divergent": 2, "divergence_target": "coverage",
                  "coverage_evidence_ref": "prereg-entry-1",
                  "coverage_pair_sha256": hashlib.sha256(json.dumps(hypothesis_pair(spec("and"), spec("or")), sort_keys=True).encode()).hexdigest(),
                  "model": "fixture-model", "max_tokens": 1024,
                  "max_proposals_per_round": 4}
        result = run("before", "after", CONTRACT, spec("and"), spec("or"), policy, invoke, inspect)
        self.assertEqual((result["raw"], result["admitted"], result["rejected"], result["confounded"],
                          result["coverage_divergent"], result["hard_divergent"]), (4, 1, 3, 0, 1, 0))
        self.assertTrue(result["unresolved"])
        self.assertEqual(result["rows"][2]["source"], "unique\r\n")
        self.assertEqual(result["rows"][2]["source_sha256"], result["rows"][3]["source_sha256"])
        self.assertEqual(result["rows"][3]["reason"], "duplicate_or_unchanged_source")
        with self.assertRaisesRegex(ValueError, "unregistered_divergence_target"):
            run("before", "after", CONTRACT, spec("and"), spec("or"),
                dict(policy, coverage_pair_sha256="0" * 64), invoke, inspect)

    def test_four_role_projection_and_contract_families(self):
        first, second = spec("and"), spec("or")
        for role in ("Source", "Propagation", "Sink"):
            first["clauses"].append({"field": role, "bindings": {}, "direction": "sufficient",
                                     "applicability": True, "antecedent": True})
            second["clauses"].append(dict(first["clauses"][-1]))
        second["clauses"][-1]["antecedent"] = False
        npd = {"object": "returned pointer", "operation": "read", "nullability": "may be null",
               "success": "status success"}
        oob = {"object": "payload", "operation": "copy", "capacity": "logical bytes",
               "unit": "bytes"}
        for contract in (npd, oob):
            payload = json.loads(render_messages("before", "after", contract, first, second)[1]["content"])
            self.assertEqual(set(payload["hypotheses"]["first"]),
                             {"Source", "Propagation", "Guard", "Sink"})
            self.assertTrue(payload["hypotheses"]["difference"]["Sink"]["second_only"])
            self.assertIn("at most 6", payload["instructions"])

    def test_retry_feedback_names_protected_role_and_enforces_limit(self):
        requests = []
        def invoke(request):
            requests.append(request)
            if len(requests) == 1:
                return {"proposals": [
                    {"parent": "before", "factor": "guard", "intent": "touch call", "source": "variant-1"},
                    {"parent": "after", "factor": "guard", "intent": "extra", "source": "variant-2"}]}
            return {"proposals": []}
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["contract_call"]}]},
                    "predictions": ["report", "quiet"]}
        result = run("before", "after", CONTRACT, spec("and"), spec("or"),
                     {"max_retries": 1, "min_divergent": 1, "model": "fixture-model",
                      "max_tokens": 128, "max_proposals_per_round": 1}, invoke, inspect)
        self.assertEqual((result["raw"], result["rejected"], result["confounded"],
                          result["unresolved"]), (2, 1, 1, True))
        feedback = json.loads(requests[1]["messages"][1]["content"])["static_feedback"]
        self.assertEqual(feedback[0]["touched_roles"], ["contract_call"])
        self.assertEqual(feedback[0]["reason"], "protected_semantics_changed")
        self.assertEqual(feedback[1]["reason"], "proposal_limit_exceeded")

    def test_protocol_rejections_and_semantic_confounding_are_disjoint(self):
        proposals = [
            {"parent": "before", "factor": "guard", "intent": "same", "source": "before"},
            {"parent": "other", "factor": "guard", "intent": "invalid", "source": "variant-a"},
            {"parent": "after", "factor": "guard", "intent": "effect", "source": "variant-b"},
            {"parent": "after", "factor": "guard", "intent": "excess", "source": "variant-c"},
        ]
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["unrelated"]}]}}
        result = run("before", "after", CONTRACT, spec("and"), spec("or"),
                     {"max_retries": 0, "min_divergent": 1, "model": "fixture-model",
                      "max_tokens": 128, "max_proposals_per_round": 3},
                     lambda request: {"proposals": proposals}, inspect)
        self.assertEqual((result["raw"], result["rejected"], result["confounded"],
                          result["admitted"], result["undetermined"]), (4, 3, 1, 0, 0))
        self.assertEqual(result["protocol_rejected"], 3)
        self.assertEqual(result["semantic_confounded"], 1)
        self.assertEqual([row["status"] for row in result["rows"]],
                         ["rejected", "rejected", "confounded", "rejected"])


if __name__ == "__main__":
    unittest.main()
