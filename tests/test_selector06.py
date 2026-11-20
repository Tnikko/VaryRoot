import os
import tempfile
import unittest
from pathlib import Path

from varyroot.selector import payloads, select
from varyroot.selector_container import choose


class SelectorTests(unittest.TestCase):
    def test_random_view_and_selection_ignore_matrix_and_order(self):
        args = ("random", ["b", "a"], {"private": 1}, ["a"], 1, 42)
        self.assertEqual(payloads(*args), payloads("random", ["a", "b"], None, None, 1, 42))
        self.assertEqual(set(payloads(*args)), {"pool", "budget", "policy"})
        self.assertEqual(choose("random", ["a", "b"], 1, 42), choose("random", ["b", "a"], 1, 42))

    def test_incremental_gain_tie_domain_and_fallback(self):
        rows = dict(a=["quiet","report","report"], b=["quiet","report","report"],
                    c=["quiet","quiet","report"], d=["uncovered","quiet","quiet"],
                    e=["quiet","quiet","quiet"])
        matrix = {i:dict(zip("xyz", vals)) for i,vals in rows.items()}
        result = choose("divergence", list(reversed(rows)), 8, matrix=matrix, equivalent=["e"])
        self.assertEqual(result["selected"], ["a", "c", "d", "e"])
        self.assertEqual(result["trace"][0]["tied"], ["a","b","c"])
        self.assertEqual([r["reason"] for r in result["trace"]], ["hard","hard","domain","equivalent"])
        self.assertEqual(len(result["trace"][1]["new_hard"]), 1)
        self.assertEqual(result["stop_reason"], "no_new_pairs_or_equivalent")

    def test_domain_gain_breaks_hard_tie(self):
        matrix = {i:dict(zip("wxyz", row)) for i,row in {
            "a":["report","quiet","report","quiet"],
            "b":["uncovered","report","report","quiet"],
            "c":["report","uncovered","quiet","uncovered"]}.items()}
        result = choose("divergence", list(matrix), 2, matrix=matrix)
        self.assertEqual(result["selected"], ["a","c"])

    def test_zero_large_and_fallback_only(self):
        for group in ("random", "divergence"):
            options = dict(seed=13, matrix={"a":{"x":"quiet"}}, equivalent=["a"])
            self.assertEqual(choose(group, ["a"], 0, **options)["selected"], [])
            large = choose(group, ["a"], 7, **options)
            self.assertEqual(large["selected"], ["a"])
            self.assertEqual(large["stop_reason"], "pool_exhausted")

    def test_reject_mismatched_registration(self):
        with self.assertRaises(ValueError):
            choose("divergence", ["a","b"], 2, matrix={"a":{"x":"quiet"},"b":{"z":"quiet"}})
        with self.assertRaises(ValueError):
            choose("divergence", [], 2, matrix={}, equivalent=["other"])


    @unittest.skipUnless(os.environ.get("VARYROOT_STEP06_DOCKER") == "1", "requires selector image")
    def test_container_views_and_random_byte_replay(self):
        ids = ["b", "a"]
        matrix = {"a":{"x":"report","y":"quiet"}, "b":{"x":"quiet","y":"quiet"}}
        with tempfile.TemporaryDirectory() as directory:
            # materialized input directories are intentionally read-only
            random1 = select(directory, "random", ids, matrix, ["b"], 2, 123)
            alternate = {"a":{"x":"uncovered","y":"quiet"}, "b":{"x":"quiet","y":"report"}}
            random2 = select(directory, "random", ids[::-1], alternate, ["a"], 2, 123)
            div = select(directory, "divergence", ids, matrix, ["b"], 2, 123)
            for key in ("manifest_sha256", "selection_sha256", "input_sha256"):
                self.assertEqual(random1["audit"][key], random2["audit"][key])
            self.assertNotIn("predictions.json", random1["audit"]["input_files"])
            self.assertIn("predictions.json", div["audit"]["input_files"])
            self.assertEqual(div["selected"], ["a", "b"])
            self.assertEqual(div["budget"], random1["budget"])
            dest = os.environ.get("VARYROOT_B_TRACE")
            if dest:
                import json
                out = Path(dest)
                out.mkdir(parents=True,exist_ok=True)
                (out/"selector-audit.json").write_text(json.dumps(dict(first=random1,reordered=random2,divergence=div,original_matrix=matrix,substituted_matrix=alternate),indent=2))
            for result in (random1, random2, div):
                view = Path(result["audit"]["attempt_dir"]) / "input"
                view.chmod(0o755)

if __name__ == "__main__":
    unittest.main()


