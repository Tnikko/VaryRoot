"""Declarative OOB contract compilation and backend admission checks."""

import unittest
from pathlib import Path

from tools.oob_feasibility.ql_contract import (
    classify_rows, render_contract, render_lane, validate_contract,
)


def unrelated_contract():
    return {
        "function": "scan_parent", "copy_api": "memcpy", "target_line": 16,
        "destination": "out", "destination_argument": 0,
        "source_argument": 1, "width_argument": 2,
        "width_bytes": 8, "payload_path": ["body"],
        "logical_length_path": ["body_bytes"],
        "total_length_path": ["wire_bytes"],
    }


class OobCodeqlContractTest(unittest.TestCase):
    def test_second_api_contract_and_two_lanes_use_same_shared_module(self):
        contract = unrelated_contract()
        self.assertEqual(validate_contract(contract), contract)
        module = render_contract(contract)
        self.assertIn('hasName("body")', module)
        self.assertIn('hasName("wire_bytes")', module)
        self.assertIn('result = 8', module)
        self.assertIn('result = 16', module)
        self.assertIn('getTarget() = root', module)
        self.assertIn('import oob_interval', render_lane("Q0"))
        self.assertIn('import oob_interval', render_lane("Qstar"))
        self.assertNotEqual(render_lane("Q0"), render_lane("Qstar"))

    def test_rejects_unproven_or_malformed_contract_parameters(self):
        contract = unrelated_contract()
        for key, value in (
            ("width_bytes", 0), ("target_line", 0),
            ("source_argument", -1), ("payload_path", ["body", "bad-name"]),
            ("logical_length_path", []),
        ):
            with self.subTest(key=key):
                bad = dict(contract, **{key: value})
                with self.assertRaises(ValueError):
                    validate_contract(bad)

    def test_shared_ql_has_no_seed_field_or_width_literals(self):
        shared = (Path(__file__).parents[1] / "varyroot/ql07/oob_interval.qll").read_text()
        for forbidden in ("disp_data", "disp_len", "Ettercap", "VNCAUTH", ">= 16"):
            self.assertNotIn(forbidden, shared)

    def test_exact_target_and_coverage_gate(self):
        target = [{"kind": "site", "line": 16}, {"kind": "covered", "line": 16}]
        self.assertEqual(classify_rows(target, 16), "quiet")
        self.assertEqual(classify_rows(target + [{"kind": "alert", "line": 16}], 16), "report")
        self.assertEqual(classify_rows([{"kind": "site", "line": 16}], 16), "backend_gap")
        self.assertEqual(classify_rows([], 16), "backend_gap")
        self.assertEqual(classify_rows(target + [{"kind": "alert", "line": 37}], 16), "quiet")


if __name__ == "__main__":
    unittest.main()
