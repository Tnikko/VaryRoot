"""Independent logical-capacity and physical-allocation observation gates."""

import unittest

from tools.oob_feasibility.observe import assess_domain, classify_target


def row(length, offset, reached=True, asan=False, version="parent"):
    base = 0x10000
    return {
        "version": version, "initial_status": "WAIT_AUTH", "auth": "00 00 00 02",
        "L": length, "C": length + 1,
        "B": hex(base), "end": hex(base + length),
        "ptr": hex(base + offset) if reached else None,
        "offset": offset if reached else None, "width": 16 if reached else None,
        "target_reached": reached,
        "asan_heap_read_at_target": asan,
        "unrelated_failure": False,
        "target_source_sha256": "a" * 64,
        "producer_source_sha256": "b" * 64,
    }


class OobObserveTest(unittest.TestCase):
    def test_target_span_separates_logical_and_physical(self):
        for length in (16, 18):
            with self.subTest(length=length):
                verdict = classify_target(row(length, 4, asan=True))
                self.assertEqual(verdict["logical"], "violation")
                self.assertEqual(verdict["physical"], "asan_source_read")
        verdict = classify_target(row(19, 4))
        self.assertEqual(verdict["logical"], "violation")
        self.assertEqual(verdict["physical"], "within_allocation")
        verdict = classify_target(row(20, 4))
        self.assertEqual(verdict["logical"], "safe")
        self.assertEqual(verdict["physical"], "within_allocation")

    def test_incomplete_domain_cannot_be_definite_negative(self):
        registration = {
            "domain": {"initial_status": ["WAIT_AUTH"],
                       "auth_type": ["00 00 00 02"], "length_bytes": [16, 20],
                       "combinations": 2}
        }
        result = assess_domain(registration, [row(20, 4, version="fixed")])
        self.assertEqual(result["fixed"]["decision"], "pending")
        self.assertEqual(result["fixed"]["safe_reached"], 1)
        self.assertEqual(result["fixed"]["missing"], 1)

    def test_full_negative_needs_safe_reached_and_no_violation(self):
        registration = {
            "domain": {"initial_status": ["WAIT_AUTH"],
                       "auth_type": ["00 00 00 02"], "length_bytes": [16, 20],
                       "combinations": 2}
        }
        rows = [row(16, 0, version="fixed"), row(20, 4, version="fixed")]
        self.assertEqual(assess_domain(registration, rows)["fixed"]["decision"], "negative")
        rows[1]["target_reached"] = False
        rows[1]["ptr"] = rows[1]["offset"] = rows[1]["width"] = None
        rows[0]["target_reached"] = False
        rows[0]["ptr"] = rows[0]["offset"] = rows[0]["width"] = None
        self.assertEqual(assess_domain(registration, rows)["fixed"]["decision"], "pending")

    def test_rejects_wrong_span_and_unattributed_asan(self):
        bad = row(16, 4, asan=False)
        with self.assertRaisesRegex(ValueError, "physical_evidence"):
            classify_target(bad)
        bad = row(20, 4)
        bad["end"] = hex(0x10000 + 21)
        with self.assertRaisesRegex(ValueError, "span_binding"):
            classify_target(bad)


if __name__ == "__main__":
    unittest.main()
