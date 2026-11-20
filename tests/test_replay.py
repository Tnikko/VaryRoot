import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fixtures_m1 import write
from test_inference import get, npd, oob


class Replay(unittest.TestCase):
    def cli(self, *args):
        result = subprocess.run([sys.executable, "-B", "-m", "varyroot", *map(str, args)],
                                capture_output=True, check=False)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def test_reorder_and_version(self):
        with tempfile.TemporaryDirectory() as d:
            rows = oob(3, "full")
            p = write(d, rows)
            a = self.cli("explain", p, "t@1")
            self.assertEqual((a[0], a[1]["outcome"]), (0, "report"))
            reordered = [dict(reversed(r.items())) for r in reversed(rows)]
            write(d, reordered)
            self.assertEqual(self.cli("explain", p, "t@1"), a)
            get(rows, "f.width")["version"] = 2
            write(d, rows)
            b = self.cli("explain", p, "t@1")
            self.assertIn("f.width@2", b[1]["derivation"]["paths"][0]["facts"])
            self.assertNotIn("f.width@1", b[1]["derivation"]["paths"][0]["facts"])

    def test_all_acceptance_files(self):
        vectors = [(mode + ("_old" if weak else "_new"), npd(mode, weak),
                    "report" if mode == "log" and not weak else "quiet")
                   for mode in ("log", "exit", "goto", "repair") for weak in (True, False)]
        for width in (2, 3):
            for style, expected in (("start", "quiet"), ("single", "uncovered"),
                                    ("full", "report" if width == 3 else "quiet")):
                vectors.append((f"width_{width}_{style}", oob(width, style), expected))
            rows = oob(width, "full")
            get(rows, "f.capacity")["typed_operands"] = {"type": "bytes", "missing": "capacity_unit"}
            vectors.append((f"width_{width}_missing_unit", rows, "uncovered"))
        with tempfile.TemporaryDirectory() as d:
            for name, rows, expected in vectors:
                with self.subTest(name=name):
                    rc, result = self.cli("explain", write(d, rows), "t@1")
                    self.assertEqual((rc, result["outcome"]), (0, expected))
                    steps = result["derivation"]["paths"][0]["clauses"]
                    guard = next(s for s in steps if s["clause"] == "c.guard@1")
                    self.assertTrue(guard["evaluations"])
                    if name.endswith("missing_unit"):
                        self.assertEqual(result["missing_facts"][0]["fact_id"], "f.capacity@1")

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            rows = npd("exit")
            p = write(d, rows)
            self.assertEqual(self.cli("validate", p)[0], 0)
            self.assertEqual(self.cli("explain", p, "t@2")[0], 2)
            get(rows, "c.guard")["antecedent"] = {"var": "typo"}
            write(d, rows)
            self.assertEqual(self.cli("validate", p)[0], 3)
            rows = npd("log")
            other = dict(get(rows, "c.guard"), id="c.other", clause_id="other", antecedent=True)
            rows.append(other)
            get(rows, "s")["clause_refs"].append("c.other@1")
            write(d, rows)
            rc, result = self.cli("explain", p, "t@1")
            self.assertEqual((rc, result["code"]), (4, "spec_conflict"))
            self.assertTrue(all(result["derivation"][k] for k in ("quiet", "report")))
            self.assertEqual(self.cli("validate", Path(d) / "missing.json")[0], 5)

    def test_legal_uncovered(self):
        with tempfile.TemporaryDirectory() as d:
            rows = npd("repair")
            get(rows, "f.ptr")["approval_status"] = "pending"
            rc, result = self.cli("explain", write(d, rows), "t@1")
            self.assertEqual((rc, result["code"]), (0, "uncovered"))
            self.assertIn("f.ptr@1", [f["fact_id"] for f in result["missing_facts"]])
