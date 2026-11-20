import copy
import json
import tempfile
import unittest
from pathlib import Path
from varyroot.ledger import Ledger, LedgerError
from varyroot.seed_fixture import bind_fixture
from varyroot.qualification import prepared,predictions
from varyroot.verdict import classify
from varyroot.publication import digest

class Review(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db=Ledger(tmp.name)
        bind_fixture(self.db,"audit","exit")
        self.p=self.db.seed_package("audit")

    def test_fault_only_use_is_not_normal_witness(self):
        rows=[dict(input_id=0,event="blocked",accesses=0),
              dict(input_id=1,event="used",value=4,reference_value=4,accesses=1)]
        self.assertEqual(classify([0,1],rows,normal_inputs=[0])["label"],"pending")

    def test_authored_contract_and_domain(self):
        for change in ("authority","domain","mapping"):
            p=copy.deepcopy(self.p)
            if change=="authority":
                p["artifacts"]["contracts"]["value"]["support"]["authority@1"]["description"]["contract"]["extent"]["value"]=3
            elif change=="domain":
                p["artifacts"]["domain"]["value"]["pointer_modes@1"]["paths"]=["fixed_input"]
            else:
                src=p["artifacts"]["before_sources"]["value"]
                snap=src["snapshots"][1]
                text=snap["files"]["sample.c"].replace("return read_required","if (!p) return 0; return read_required")
                snap["files"]["sample.c"]=text
                src["views"][1]["target"]["file_digest"]=digest(text.encode())
            with self.subTest(change=change),self.assertRaises(ValueError):
                prepared(p,"before")

    def test_compare_baseline_and_working_model(self):
        p=copy.deepcopy(self.p)
        p["artifacts"]["active_model"]["value"]=p["artifacts"]["hypothesis_set"]["value"]["specs"][-1]
        original,working,candidates=predictions(p)
        self.assertEqual(original["status"],"matched")
        self.assertEqual(working["status"],"contradicted")

    def test_pending_A2_rework(self):
        old=self.p["artifacts"]["before_sources"]["value"]
        self.db.rework_seed("audit",1,1,branch="A2",reason="fix reviewed source",
                            changes={"before_sources":dict(old,revision=2)})
        self.assertEqual(self.db.seed_package("audit")["version"],2)
