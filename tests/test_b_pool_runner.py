import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from varyroot.b_pool_runner import select_pool, run_pool
from varyroot.b_interval_ir import make_interval_pair
from varyroot.b_prompt import build_request, hypothesis_pair


class PoolRunnerTest(unittest.TestCase):
    def test_selection_is_deterministic_and_budgeted(self):
        rows = [
            {"status": "admitted", "source_sha256": f"{n:064x}",
             "predictions": pair, "hard_divergent": hard}
            for n, pair, hard in ((1, ["report", "quiet"], True),
                                  (2, ["report", "quiet"], True),
                                  (3, ["quiet", "report"], True),
                                  (4, ["quiet", "quiet"], False),
                                  (5, ["report", "report"], False))]
        selected = select_pool(rows, 2, [17, 29, 43, 71, 101])
        self.assertEqual(selected["divergence"], [rows[0]["source_sha256"],
                                                  rows[2]["source_sha256"]])
        self.assertEqual(len(selected["random"]), 5)
        self.assertTrue(all(len(items) == 2 and len(set(items)) == 2
                            for items in selected["random"].values()))
        self.assertEqual(selected, select_pool(rows, 2, [17, 29, 43, 71, 101]))

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_locked_offline_run_never_calls_network_before_hash_check(self):
        project = Path(__file__).resolve().parents[1]
        revision = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"],
                                           text=True).strip()
        before = ("#include <string.h>\nint parse(char *dst,char *base,int len) {\n"
                  " char *cursor=base,*end=base+len; cursor+=2;\n"
                  " if(len>=8) {\n  memcpy(dst,cursor,8);\n }\n return 0;\n}\n")
        after = before.replace("len>=8", "end-cursor>=8")
        pair = make_interval_pair("fixture_run", "logical_span")
        first, second = pair["specs"]["H_total"], pair["specs"]["H_remaining"]
        policy = {"model": "deepseek-flash", "temperature": 0.7, "top_p": 1.0,
                  "max_tokens": 128, "max_retries": 0, "max_proposals_per_round": 1,
                  "min_admitted": 5, "min_divergent": 2, "require_mixed_scores": True}
        contract = {"object": "logical span", "operation": "source read"}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def save(name, value):
                path = root / name
                path.write_text(json.dumps(value, sort_keys=True) + "\n")
                return path
            (root / "before.c").write_text(before)
            (root / "after.c").write_text(after)
            projection = hypothesis_pair(first, second)
            save("pair.json", projection)
            save("request.json", build_request(policy, before, after, contract, first, second))
            exclusions = save("exclusions.json", {"entries": []})
            digest = lambda value: hashlib.sha256(value).hexdigest()
            save("seed-lock.json", {"policy": {"fixture": policy},
                "source_sha256": {"before": digest(before.encode()), "after": digest(after.encode())},
                "hypotheses": {"fixture": {"projection_sha256": digest(
                    json.dumps(projection, sort_keys=True).encode())}},
                "exclusions_sha256": digest(exclusions.read_bytes())})
            config = {"project_root": str(project), "lock_manifest": str(root / "manifest.json"),
                      "seed_lock": str(root / "seed-lock.json"), "seed": "fixture",
                      "historical_exclusions": str(exclusions),
                      "sources": {"before": str(root / "before.c"), "after": str(root / "after.c")},
                      "source_lock_keys": {"before": "before", "after": "after"},
                      "family": "interval", "ir_run_id": "fixture_run", "subject": "logical_span",
                      "pair_projection": str(root / "pair.json"),
                      "request_sample": str(root / "request.json"), "output_dir": str(root / "out"),
                      "contract": contract, "key_path": str(root / "never-used.key"),
                      "static_config": {"target_expression": "memcpy(dst,cursor,8)",
                                        "target_call": "memcpy", "total_expr": "len",
                                        "remaining_expr": "end-cursor", "pointer_expr": "cursor",
                                        "width": 8},
                      "function": "parse", "target_lines": {"before": 5, "after": 5},
                      "clang_argv": ["clang-18", "-c", "{source}", "-o", "{object}"]}
            config_path = save("config.json", config)
            files = {str(path): digest(path.read_bytes()) for path in root.iterdir() if path.is_file()}
            manifest = save("manifest.json", {"code_revision": revision, "files": files})
            with patch("varyroot.b_pool_runner.post_once", return_value={"proposals": []}) as call:
                result = run_pool(config_path)
                self.assertTrue(result["unresolved"])
                self.assertEqual(call.call_count, 1)
            config_path.write_text(config_path.read_text() + " ")
            with patch("varyroot.b_pool_runner.post_once") as call:
                with self.assertRaisesRegex(ValueError, "prereg_file_lock_mismatch"):
                    run_pool(config_path)
                call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
