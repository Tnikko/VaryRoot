import json
import unittest
import os
import time
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTIAL = ROOT.parent / "interface3c-review" / "out"
sys.path.insert(0, str(ROOT / "src"))
from check import check
from case_runner import run_case

def crash_case(_):
    os._exit(77)

def timeout_case(_):
    time.sleep(3)

class ObservationCompletion(unittest.TestCase):
    def test_all_four_cases_and_safe_read(self):
        for side, expected in (("before", "positive"), ("after", "negative")):
            path = ROOT / "out" / f"{side}-receipt.json"
            if not path.exists():
                path = PARTIAL / f"{side}-receipt.json"
            receipt = json.loads(path.read_bytes())
            self.assertEqual(receipt["verdict"]["label"], expected)
            self.assertEqual(receipt["verdict"]["coverage_basis"], "exhaustive_finite_domain")
            rows = {row["cell"]: row for row in receipt["rows"]}
            self.assertEqual(set(rows), {1, 2, 3, 4})
            self.assertTrue(all(row["status"] == "observed" for row in rows.values()))
            self.assertEqual(rows[2]["classification_input"]["event"], "used")
            self.assertEqual(rows[2]["actual_reads"], 2)
            self.assertIn(2, receipt["verdict"]["normal_witnesses"])
            self.assertEqual(rows[4]["attribute_traversal_truncated"],
                             None if side == "before" else True)
            if side == "before":
                self.assertEqual(rows[4]["actual_reads"], 0)
                self.assertTrue(rows[4]["calls"][1]["after_violation"])
                self.assertEqual(rows[1]["classification_input"]["event"], "violation")
                self.assertEqual(rows[1]["actual_reads"], 0)
            else:
                self.assertEqual(rows[1]["classification_input"]["event"], "blocked")
                self.assertEqual(rows[1]["actual_reads"], 0)

    def test_case_process_failures_are_classified(self):
        self.assertEqual(run_case(crash_case, 1)["status"], "case_exec_failure")
        self.assertEqual(run_case(timeout_case, 1, timeout=0.1)["reason"], "case_timeout")

    def test_classification_must_match_pre_access_events(self):
        receipt = json.loads((ROOT / "out/before-receipt.json").read_bytes())
        expected = {key: receipt[key] for key in
                    ("request_id", "attempt_id", "manifest_sha256", "domain_sha256", "binding")}
        expected["mapping_status"] = "exact_1to1"
        changed = copy.deepcopy(receipt)
        changed["rows"][0]["events"][0]["kind"] = "read"
        with self.assertRaises(ValueError):
            check(changed, expected)

if __name__ == "__main__":
    unittest.main()
