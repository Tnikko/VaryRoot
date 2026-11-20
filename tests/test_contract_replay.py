import json
import os
import tempfile
import unittest
from pathlib import Path

from varyroot.contract_replay import replay
from varyroot.cli_runner import CliFailure, run_cli
from varyroot.sandbox import Scope, materialize, run_role


@unittest.skipUnless(os.environ.get("VARYROOT_R05_DOCKER") == "1", "requires isolated role image")
class ContractReplay(unittest.TestCase):
    def test_contract_rejection_does_not_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            view = Path(tmp) / "view"
            materialize(view, tmp, Scope("test", "s", "g", 0, "A", "seed", "req", 1), [])
            with self.assertRaises(CliFailure) as raised:
                run_cli(lambda n: run_role(view, ["python", "-m", "varyroot.contract_role", "unknown"]))
            self.assertEqual((raised.exception.code, raised.exception.attempts), (2, 1))
            self.assertEqual(raised.exception.diagnostic["code"], "invalid_bundle")

    def test_four_file_chains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(os.environ.get("VARYROOT_TRACE_DEST", str(Path(tmp) / "fixture")))
            chains = replay(root)
            for chain, action in zip(chains, ("revise", "keep", "unresolved", "revise"), strict=True):
                with self.subTest(run=chain["run"]):
                    self.assertEqual(chain["decision"]["action"], action)
                    kinds = [event["kind"] for event in chain["events"]]
                    self.assertLess(kinds.index("prediction"), kinds.index("selected"))
                    self.assertLess(kinds.index("selected"), kinds.index("reveal"))
                    self.assertLess(kinds.index("reveal"), kinds.index("adjudicating"))
                    self.assertEqual(kinds.count("charged"), 1)
                    self.assertEqual(kinds[-1], chain["terminal"]["state"])
                    self.assertEqual(chain["decision"]["revision_ref"] is None, action != "revise")
                    base = root / chain["scenario"]
                    grant = json.loads((base / "verifier-1/input/input_manifest.json").read_bytes())
                    self.assertEqual([f["kind"] for f in grant["files"]], ["case"])
                    b_input = json.loads((base / "B-1/input/input_manifest.json").read_bytes())
                    self.assertGreater(b_input["scope"]["watermark"], 0)
                    if action == "unresolved":
                        self.assertFalse((base / "C-1").exists())
                    elif chain["scenario"] == "gap":
                        self.assertIsNone(chain["terminal"]["freeze_id"])
                        self.assertEqual(chain["terminal"]["rows"][1]["classification"], "FN")
                    else:
                        self.assertTrue(chain["terminal"]["freeze_id"].startswith("test:"))
