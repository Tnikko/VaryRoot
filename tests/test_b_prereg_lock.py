import hashlib
import json
import unittest
from pathlib import Path


class PreregLockTest(unittest.TestCase):
    def test_seed_pair_and_exclusion_digests_match_locked_artifacts(self):
        root = Path(__file__).resolve().parents[1] / "data/prereg-blind-v1"
        lock = json.loads((root / "seed-ir-lock.json").read_text())
        policies = lock["policy"]
        for seed, (retries, per_round) in {"openldap": (2, 6), "ettercap": (5, 3)}.items():
            policy = policies[seed]
            self.assertEqual((policy["min_admitted"], policy["min_divergent"],
                              policy["require_mixed_scores"], policy["max_retries"],
                              policy["max_proposals_per_round"]),
                             (5, 2, True, retries, per_round))
            self.assertEqual((retries + 1) * per_round, 18)
        for seed in ("openldap", "ettercap"):
            pair = json.loads((root / f"{seed}-pair.json").read_text())
            digest = hashlib.sha256(json.dumps(pair, sort_keys=True).encode()).hexdigest()
            self.assertEqual(digest, lock["hypotheses"][seed]["projection_sha256"])
            request = json.loads((root / f"{seed}-request-sample.json").read_text())
            self.assertEqual(request["model"], "deepseek-flash")
            self.assertEqual((request["temperature"], request["top_p"], request["max_tokens"]),
                             (0.7, 1.0, 16384))
            self.assertIn(f"at most {policies[seed]['max_proposals_per_round']}",
                          request["messages"][1]["content"])
            serialized = json.dumps(request).lower()
            for audit in ("source_lock", "sha256", "https://", "http://", "ghsa-"):
                self.assertNotIn(audit, serialized)
        self.assertEqual(hashlib.sha256((root / "historical-exclusions.json").read_bytes()).hexdigest(),
                         lock["exclusions_sha256"])


if __name__ == "__main__":
    unittest.main()
