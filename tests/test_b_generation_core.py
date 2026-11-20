import json
import unittest

from varyroot.b_prompt import render_messages
from varyroot.b_factor_gate import classify
from varyroot.b_static_retry import run


def spec(op):
    return {"clauses": [{"id": "private", "field": "Guard", "direction": "iff",
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
        self.assertEqual(payload["hypotheses"]["difference"]["first_only"][0]["antecedent"]["op"], "and")

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
                                   "intent": "local", "source": "variant"}]}
        def inspect(source, parent):
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": True,
                    "target_binding": "exact_1to1", "edit_groups": [{"roles": ["guard"]}]},
                    "predictions": ("report", "quiet") if len(requests) == 2 else ("quiet", "quiet")}
        result = run("before", "after", CONTRACT, spec("and"), spec("or"),
                     {"max_retries": 1, "min_hard_divergent": 1,
                      "model": "fixture-model", "max_tokens": 1024}, invoke, inspect)
        self.assertEqual((result["raw"], result["admitted"], result["hard_divergent"],
                          result["retry_rounds"]), (2, 2, 1, 1))
        self.assertEqual(json.loads(requests[1]["messages"][1]["content"])["static_feedback"],
                         [{"index": 0, "reason": "same_or_uncovered_prediction"}])
        self.assertNotIn('\\"label\\":', json.dumps(requests))


if __name__ == "__main__":
    unittest.main()
