import copy
import json
import unittest
from pathlib import Path

from varyroot.ledger import Ledger, LedgerError

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "runs/interface3d-production"
STATIC = ROOT / "runs/interface3-static"
OBS = ROOT / "runs/interface3c-complete/out"
RUN = "curl-openldap-2018-seed-v4"


def load(name):
    return json.loads(name.read_bytes())


class ProductionQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from varyroot import openldap_qualification as target
        cls.target = target
        cls.package = Ledger(STATIC / "production-ledger").seed_package(RUN)
        cls.review = load(STATIC / "review-data.json")
        cls.lock = load(OBS / "build-lock.json")

    def test_scoped_mapping_and_mutation_rejection(self):
        scope = self.target.mapping_scope(self.package, self.review, self.lock)
        self.assertEqual(scope["approval"], "accepted_for_scope")
        self.assertEqual(set(scope["sides"]), {"before", "after"})
        bad = copy.deepcopy(self.package)
        record = bad["artifacts"][bad["roles"]["after_mapping"]]["value"]
        record["status"] = "ambiguous"
        with self.assertRaises(ValueError):
            self.target.mapping_scope(bad, self.review, self.lock)

    def test_receipt_binding_and_domain_rejection(self):
        for side in ("before", "after"):
            receipt = load(OBS / f"{side}-raw.json")
            expected = dict(request_id=receipt["request_id"], attempt_id=receipt["attempt_id"],
                            manifest_sha256=receipt["manifest_sha256"],
                            domain_sha256=receipt["domain_sha256"],
                            binding=receipt["binding"], mapping_status="exact_1to1")
            self.assertTrue(self.target.validate_observation(receipt, expected))
            bad = dict(expected, domain_sha256="0"*64)
            with self.assertRaises(ValueError):
                self.target.validate_observation(receipt, bad)

    def test_production_projection_binds_seed_and_tool(self):
        files, binding = self.target.observation_inputs(self.package, "before", self.review, self.lock)
        self.assertEqual(binding["seed_package_sha256"], self.package["packet_sha"])
        self.assertEqual(binding["contract_sha256"],
                         self.target.digest(files["contract.json"]))
        self.assertEqual(binding["so_sha256"], self.target.digest(files["observer.so"]))
        self.assertEqual(set(files), {"contract.json", "domain.json", "binding.json",
                                      "observer.so", "measure.py", "case_runner.py"})

    def test_old_seed_and_digest_cannot_reserve(self):
        import sqlite3
        import tempfile
        from contextlib import closing
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as tmp:
            copydb = Path(tmp) / "ledger.sqlite3"
            with closing(sqlite3.connect(BASE / "out/production-before.sqlite3")) as source:
                with closing(sqlite3.connect(copydb)) as target:
                    source.backup(target)
            db = Ledger(tmp)
            files, _ = self.target.observation_inputs(self.package, "before", self.review, self.lock)
            with self.assertRaises(LedgerError):
                self.target.reserve_observation(db, RUN, dict(self.package, version=0),
                                                "before", files, "sha256:"+"0"*64)
            files["domain.json"] = b'{}'
            with self.assertRaises(ValueError):
                self.target.reserve_observation(db, RUN, self.package,
                                                "before", files, "sha256:"+"0"*64)

    def test_finish_cannot_accept_without_two_production_receipts(self):
        import sqlite3
        import tempfile
        from contextlib import closing
        with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as tmp:
            copydb = Path(tmp) / "ledger.sqlite3"
            with closing(sqlite3.connect(BASE / "out/production-before.sqlite3")) as source:
                with closing(sqlite3.connect(copydb)) as target:
                    source.backup(target)
            db = Ledger(tmp)
            files = {side:self.target.observation_inputs(self.package, side, self.review, self.lock)[0]
                     for side in ("before","after")}
            scope = self.target.mapping_scope(self.package, self.review, self.lock)
            result = self.target.finish_qualification(db, RUN, self.package, files,
                                                       "sha256:"+"0"*64, scope)
            self.assertEqual(result["state"], "seed_pending")
            self.assertEqual(db.run(RUN)["state"], "seed_pending")
            with self.assertRaises(LedgerError):
                self.target.finish_qualification(db, RUN, dict(self.package, version=0),
                                                 files, "sha256:"+"0"*64, scope)

    def test_interpreter_replay_and_incompatible_candidate(self):
        decision = self.target.replay_models(self.package)
        self.assertEqual(decision["baseline"]["outcomes"], {"before": "report", "after": "quiet"})
        self.assertEqual(len(decision["survivors"]), 3)
        bad = copy.deepcopy(self.package)
        model = bad["artifacts"][bad["roles"]["hypothesis_set"]]["value"]["specs"]
        for candidate in model[1:]:
            guard = next(c for c in candidate["clauses"] if c["field"] == "Guard")
            guard["antecedent"] = True
            entry = next(c for c in bad["packet"]["candidates"]
                         if c["spec_ref"] == candidate["spec"]["id"] + "@1")
            entry["predictions"]["before"]["outcome"] = "quiet"
        decision = self.target.replay_models(bad)
        self.assertEqual(decision["route"], "A5")
        self.assertEqual(decision["survivors"], ["spec.openldap.H_check@1"])
