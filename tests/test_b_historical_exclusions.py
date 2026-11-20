import json
import unittest
from pathlib import Path


class HistoricalExclusionsTest(unittest.TestCase):
    def test_locked_observed_sources_are_unique_and_provenanced(self):
        path = Path(__file__).resolve().parents[1] / "data/prereg-blind-v1/historical-exclusions.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data["entries"]
        hashes = [row["source_sha256"] for row in entries]
        self.assertEqual(hashes, sorted(set(hashes)))
        self.assertEqual(len(entries), data["sources"]["unique_source_hashes"])
        self.assertEqual(data["sources"]["step4d_raw_model_responses"], 3)
        self.assertEqual(sum(len(row["origins"]) for row in entries),
                         data["sources"]["observed_source_rows"])
        self.assertTrue(any(any(origin.startswith("step4f:source/parent/") for origin in row["origins"])
                            for row in entries))
        self.assertTrue(any(any(origin.startswith("step4d:model-03.response.json") for origin in row["origins"])
                            for row in entries))


if __name__ == "__main__":
    unittest.main()
