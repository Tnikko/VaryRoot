import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from varyroot.ledger import Ledger, LedgerError
from varyroot.publication import digest, encode
from varyroot.source_seed import grants

CATALOG = Path(__file__).parent / "fixtures/agent_a/catalog.json"


class SourceRequestTests(unittest.TestCase):
    def test_only_source_material_admitted(self):
        proposal = {"ref":"proposal@1", "path":"proposal.json", "kind":"seed", "sha256":"a"*64,"size":12}
        base = {"schema_version":1,"seed":"s","files":[proposal]}
        self.assertEqual(grants(base)[0].kind, "seed")
        with self.assertRaises(ValueError):
            grants({**base,"files":[proposal,dict(proposal,kind="evidence",path="label.json")]})
        with self.assertRaises(ValueError):
            grants({**base,"files":[]})


@unittest.skipUnless(os.environ.get("VARYROOT_R06_DOCKER") == "1", "requires locked source worker image")
class IsolatedSourceSeed(unittest.TestCase):
    def test_real_A_to_seed_pending(self):
        # The old Step 03 dispatcher now accepts a real source input catalog.
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(os.environ.get("VARYROOT_SEED_TRACE_DEST", str(Path(tmp)/"store")))
            catalog = json.loads(CATALOG.read_bytes())
            run = "development:offline-source"
            command = [sys.executable, "-B", "-m", "varyroot.contract_replay", str(store),
                       "--seed-inputs", str(CATALOG), "--run-id", run]
            def dispatch():
                p = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
                return json.loads(p.stdout)
            receipt = dispatch()
            self.assertEqual(receipt["state"], "seed_pending")
            db = Ledger(store)
            package = db.seed_package(run)
            self.assertEqual(package["packet_sha"], receipt["package_sha"])
            raw = (store/"seed-objects"/receipt["seed_sha"]).read_bytes()
            self.assertEqual(digest(raw), receipt["seed_sha"])
            seed = json.loads(raw)
            self.assertEqual(raw, encode(seed))
            self.assertEqual(seed["seed_id"], catalog["seed"])
            self.assertEqual(seed["state"], "seed_pending")
            self.assertIsNone(seed["candidate_check_ref"])
            self.assertTrue(db.seed_gate(run)["blockers"])
            with self.assertRaises(LedgerError):
                db.accept_seed(run, db.run(run)["version"], package["version"])
            before = db.events(run)
            self.assertEqual(dispatch(), receipt)
            self.assertEqual(db.events(run), before)
            self.assertEqual(db.balances(run)["B.verify"], 2)
            self.assertFalse(any(e["kind"] == "seed_accepted" for e in before))


    def test_contract_diagnostics_survive_real_handoff(self):
        cases = {"pending": {"capacity": {"approval": "pending"}},
                 "unknown-unit": {"capacity": {"unit": None}},
                 "wrong-owner": {"subject": "other"}}
        for label, changes in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                store = Path(os.environ.get("VARYROOT_SEED_TRACE_DEST", str(parent / "store")))
                local = parent / "sources"
                local.mkdir()
                catalog = json.loads(CATALOG.read_bytes())
                for entry in catalog["files"]:
                    name = entry["path"]
                    shutil.copyfile(CATALOG.parent / name, local / name)
                    if name == "proposal.json":
                        proposal = json.loads((local / name).read_bytes())
                        for key, value in changes.items():
                            if isinstance(value, dict):
                                proposal[key].update(value)
                            else:
                                proposal[key] = value
                        raw = encode(proposal)
                        (local / name).write_bytes(raw)
                        entry.update(size=len(raw), sha256=digest(raw))
                (local / "catalog.json").write_bytes(encode(catalog))
                run = "development:" + label
                proc = subprocess.run([sys.executable, "-m", "varyroot.contract_replay", str(store),
                                       "--seed-inputs", str(local / "catalog.json"), "--run-id", run],
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
                db = Ledger(store)
                packet = db.seed_package(run)["packet"]
                self.assertTrue(any(a["status"] in ("pending", "rejected") for a in packet["assumptions"]))
                self.assertFalse(any(c["eligible_for_review"] for c in packet["candidates"]))
                bundle = packet["bundles"]["before"]
                manifest = parent / "manifest.json"
                manifest.write_bytes(encode(bundle["manifest"]))
                (parent / "records.json").write_bytes(encode(bundle["records"]))
                target, = bundle["manifest"]["target_refs"]
                for args, expected in ((["validate", str(manifest)], "ok"),
                                       (["explain", str(manifest), target], "uncovered")):
                    result = subprocess.run([sys.executable, "-m", "varyroot", *args],
                                            check=True, capture_output=True)
                    diagnostic = json.loads(result.stdout)
                    self.assertEqual(diagnostic["code"], expected)
                    if args[0] == "explain":
                        self.assertEqual(diagnostic, packet["candidates"][0]["predictions"]["before"])
                self.assertEqual(db.run(run)["state"], "seed_pending")
                with self.assertRaises(LedgerError):
                    db.accept_seed(run, db.run(run)["version"], 1)
