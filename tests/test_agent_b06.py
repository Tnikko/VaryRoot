import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from varyroot.agent_b import append_erratum, branch_seed, freeze, paired, select_batch, verify_selected
from varyroot.b_batch import read_object, registration
from varyroot.calibration_decision import finalize, write_bundle
from varyroot.case_pool import build_pool
from varyroot.ledger import Ledger, LedgerError
from varyroot.publication import digest, encode
from varyroot.qualification import artifact, qualify
from varyroot.seed_fixture import bind_fixture
from varyroot.source_seed import prepare_seed
from varyroot.verify_request import image_id


@unittest.skipUnless(os.environ.get("VARYROOT_STEP06_DOCKER") == "1", "needs Step 06 images")
class BIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(os.environ.get("VARYROOT_B_TRACE", self.temp.name)) / self._testMethodName
        self.db = Ledger(root)
        self.image = image_id()

    def npd(self):
        bind_fixture(self.db, "seed", "exit", initial="check_seen", competitors=("nonnull_or_exit",))
        self.assertEqual(qualify(self.db, "seed")["state"], "seed_accepted")

    def check_bundle(self, result):
        manifest = write_bundle(result, self.db.root / "handoffs" / result["run"])
        p = subprocess.run([sys.executable, "-m", "varyroot", "validate", str(manifest)], capture_output=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        positions = {(p["target_ref"],p["contract_ref"],p["domain_ref"]) for p in result["positions"]}
        if result["action"] != "unresolved":
            partitions = result["changed_judgments"] + result["preserved_judgments"]
            self.assertEqual(len(positions), len(partitions))
        self.assertIs(result["revision_ref"] is None, result["action"] != "revise")

    def test_pair_revise_and_no_budget(self):
        self.npd()
        db = self.db
        results = paired(db, "seed", "pair", k=6, rng_seed=71)
        self.assertEqual({r["action"] for r in results.values()}, {"revise"})
        for result in results.values():
            self.check_bundle(result)
        random, divergence = (db.snapshot("pair." + g) for g in ("random","divergence"))
        left = {r["intent"]["case"]:r for r in random["members"]}
        right = {r["intent"]["case"]:r for r in divergence["members"]}
        overlap = left.keys() & right.keys()
        self.assertTrue(overlap)
        for case in overlap:
            self.assertNotEqual(left[case]["request_id"], right[case]["request_id"])
        first_select = next(e for e in db.events("pair.divergence") if e["kind"]=="selected")
        self.assertGreater(first_select["commit_seq"], random["watermark"])
        for group in ("random","divergence"):
            run = "pair." + group
            reg, _ = registration(db, run, "b1")
            self.assertEqual(json.loads(reg["snapshot"])["watermark"], 0)
            self.assertEqual(6-db.balances(run)["B.verify"],len(db.snapshot(run)["members"]))
        for result in paired(db, "seed","stopped",k=0,rng_seed=1).values():
            self.assertEqual(result["action"], "unresolved")
            self.check_bundle(result)
            with self.assertRaises(LedgerError):
                finalize(db,result["run"],claims=dict(action="keep",changed_judgments=[],preserved_judgments=[]))

    def test_oob_keep(self):
        parent = Path(__file__).parent / "fixtures/agent_a"
        fixture = Path(self.temp.name) / "source"
        fixture.mkdir()
        catalog = json.loads((parent/"catalog.json").read_bytes())
        for item in catalog["files"]:
            name = item["path"]
            raw = (parent/(name.replace("after","after_rebound") if name.startswith("after") else name)).read_bytes()
            (fixture/name).write_bytes(raw)
            item.update(size=len(raw), sha256=digest(raw))
        (fixture/"catalog.json").write_bytes(encode(catalog))
        prepare_seed(self.db.root, fixture/"catalog.json", "seed")
        self.assertEqual(qualify(self.db, "seed")["state"], "seed_accepted")
        result = paired(self.db, "seed", "oob", k=12, rng_seed=73)
        for r in result.values():
            self.assertEqual(r["action"], "keep")
            self.check_bundle(r)

    def test_append_erratum_and_rework(self):
        self.npd()
        db = self.db
        for branch in ("A2", "A5"):
            run = "work." + branch
            branch_seed(db, "seed", run, "random", 10)
            original = build_pool(db, run, self.image)
            bad = copy.deepcopy(original)
            case = bad["cases"][0]
            mid = bad["baseline"]
            case["predictions"][mid] = "uncovered"
            with patch("varyroot.case_pool.build_pool",return_value=bad):
                files = freeze(db,run,"b1",self.image,8,91)
            old_reg, _ = registration(db,run,"b1")
            select_batch(db,run,"b1")
            verify_selected(db,run,"b1",files,self.image)
            self.assertEqual(finalize(db,run)["action"], "correct_reading")
            seq = append_erratum(db,run,"b1",case["case_id"],mid)
            self.assertGreater(seq, db.snapshot(run)["watermark"])
            self.assertEqual(append_erratum(db,run,"b1",case["case_id"],mid),seq)
            self.assertEqual(old_reg,registration(db,run,"b1")[0])
            snapshot, balances = db.snapshot(run), db.balances(run)
            pkg = db.seed_package(run)
            if branch == "A2":
                changes = {"before_sources":dict(artifact(pkg,"before_sources"),review_version=2)}
            else:
                active = copy.deepcopy(artifact(pkg,"active_model"))
                active["spec"]["version"] = 2
                hyps = copy.deepcopy(artifact(pkg,"hypothesis_set"))
                hyps["specs"] = [active,*[m for m in hyps["specs"] if m["spec"]["id"] != active["spec"]["id"]]]
                changes = {"active_model":active,"hypothesis_set":hyps}
            db.rework_seed(run, db.run(run)["version"], pkg["version"],branch=branch,
                           reason="reviewed dependency correction",changes=changes)
            self.assertEqual(qualify(db,run)["state"],"seed_accepted")
            freeze(db,run,"b2",self.image,1,91)
            reg, _ = registration(db,run,"b2")
            self.assertEqual(reg["source_kind"],"post_remodel")
            self.assertEqual(json.loads(reg["snapshot"]),snapshot)
            self.assertEqual(db.balances(run), balances)
