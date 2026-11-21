import hashlib
import json
import unittest
from pathlib import Path


class V3PreregTest(unittest.TestCase):
    def test_locked_requests_project_fact_meanings_and_patch_only_protocol(self):
        root = Path(__file__).resolve().parents[1] / "data/prereg-blind-v3"
        lock = json.loads((root / "seed-ir-lock.json").read_text())
        exclusions = (root / "historical-exclusions.json").read_bytes()
        self.assertEqual(hashlib.sha256(exclusions).hexdigest(), lock["exclusions_sha256"])
        self.assertEqual(lock["v2_dynamic_verifications"], 0)
        for seed, symbols in (("openldap", {"check_seen", "blocked", "operand"}),
                              ("ettercap", {"total_guard", "remaining_guard", "capacity", "offset", "width"})):
            policy = lock["policy"][seed]
            self.assertEqual((policy["model"], policy["max_proposals_per_round"],
                              policy["max_retries"], policy["min_admitted"],
                              policy["min_divergent"]), ("deepseek-flash", 6, 2, 5, 2))
            pair = json.loads((root / f"{seed}-pair.json").read_text())
            self.assertEqual(hashlib.sha256(json.dumps(pair, sort_keys=True).encode()).hexdigest(),
                             lock["hypotheses"][seed]["projection_sha256"])
            request = json.loads((root / f"{seed}-request-sample.json").read_text())
            task = json.loads(request["messages"][1]["content"])
            self.assertTrue(symbols <= task["fact_semantics"].keys())
            self.assertIn("old_code", task["instructions"])
            self.assertIn("new_code", task["instructions"])
            self.assertNotIn("complete source", task["instructions"])
            self.assertEqual(request["model"], "deepseek-flash")
            lowered = json.dumps(request).lower()
            for token in ("source_lock", "sha256", "https://", "http://", "ghsa-", "cve-"):
                self.assertNotIn(token, lowered)


if __name__ == "__main__":
    unittest.main()
