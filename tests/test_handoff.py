import copy
import tempfile
import unittest
from fixtures_m1 import example, record, write
from varyroot.artifacts import load_bundle, validate_bundle


def handoff_records(action):
    rows = example()
    other = copy.deepcopy(next(r for r in rows if r["kind"] == "Spec"))
    other["version"] = 2
    rows.append(other)
    rows.append(record("Decision", "dec", prediction_refs=[], verdict_refs=[], parent_spec_ref="s@1",
                       action=action, reason="contract fixture", remaining_disagreements=[],
                       next_state="unresolved" if action == "unresolved" else "spec_ready"))
    if action == "revise":
        rows.extend([record("Evidence", "list", description="test manifest"),
                     record("Revision", "rev", trigger_decision_id="dec@1", parent_spec_ref="s@1",
                            new_spec_ref="s@2", clause_diff=["guard"], regression_manifest_ref="list@1",
                            changed_judgments=[], preserved_judgments=[], new_fact_requirements=[])])
    rows.append(record("Handoff", "handoff", decision_ref="dec@1", initial_spec_ref="s@1",
                       final_spec_ref={"keep": "s@1", "revise": "s@2", "unresolved": None}[action],
                       revision_ref="rev@1" if action == "revise" else None))
    return rows


class HandoffTests(unittest.TestCase):
    def validate(self, rows):
        with tempfile.TemporaryDirectory() as d:
            return validate_bundle(load_bundle(write(d, rows)))

    def test_routes(self):
        for action in ("keep", "revise", "unresolved"):
            with self.subTest(action=action):
                self.assertEqual(self.validate(handoff_records(action)), [])

    def test_null_is_required_and_keep_identity_is_strict(self):
        rows = handoff_records("keep")
        rows[-1] = dict(reversed(rows[-1].items()))
        self.assertFalse(self.validate(rows))
        rows[-1]["final_spec_ref"] = "s@2"
        self.assertTrue(self.validate(rows))
        rows[-1]["final_spec_ref"] = "s@1"
        del rows[-1]["revision_ref"]
        self.assertTrue(self.validate(rows))

    def test_unresolved_and_revision_mismatch(self):
        rows = handoff_records("unresolved")
        rows[-2]["next_state"] = "spec_ready"
        self.assertTrue(self.validate(rows))
        for ref in ("s@2", "s@3"):
            rows = handoff_records("revise")
            rows[-2]["parent_spec_ref"] = ref
            self.assertTrue(self.validate(rows))

    def test_revision_judgments_use_the_same_target_and_verdict(self):
        rows = handoff_records("revise")
        revision = rows[-2]
        rows.extend([
            record("Observation", "obs", request_ref="list@1", input_ref="list@1", path_ref="list@1",
                   target_ref="t@1", contract_ref="k@1", domain_ref="d@1", reached=True,
                   observed_state="intent", execution_status="completed"),
            record("Verdict", "v", target_ref="t@1", contract_ref="k@1", domain_ref="d@1",
                   observation_refs=["obs@1"], label="positive", justification="synthetic witness")])
        assertion = ["t@1", "quiet", "report", "v@1"]
        revision["changed_judgments"] = [assertion]
        self.assertEqual(self.validate(rows), [])
        revision["preserved_judgments"] = [assertion]
        self.assertTrue(self.validate(rows))
        revision["changed_judgments"] = []
        self.assertTrue(self.validate(rows))
        revision["preserved_judgments"] = [["t@1", "report", "report", "v@2"]]
        self.assertTrue(self.validate(rows))
