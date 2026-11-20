import json
import os
import tempfile
import unittest
from pathlib import Path

from varyroot.__main__ import run as cli
from varyroot.b_batch import register_batch, verify_selected
from varyroot.calibration_decision import check_claims, choose, finalize, write_bundle
from varyroot.case_pool import build_pool
from varyroot.ledger import Ledger, LedgerError, pool_hash
from varyroot.publication import encode
from varyroot.qualification import qualify
from varyroot.seed_fixture import bind_fixture
from varyroot.verify_request import image_id, input_hash


class DecisionGate(unittest.TestCase):
    def test_choose_refuses_tied_keep(self):
        models = ["base", "path", "loop"]
        outcomes = dict(zip(models, ({"outcome": value} for value in ("quiet", "quiet", "uncovered"))))
        positions = [dict(case_id="local-exit", stage="B", label="negative", results=outcomes)]
        pool = {"local-exit": ({}, outcomes)}

        action, final, reasons = choose(models, "base", pool, positions, [], 0)

        self.assertEqual((action, final), ("unresolved", None))
        self.assertIn({"reason": "non_unique_alignment", "aligned_explanations": ["base", "path"]}, reasons)

    def test_choose_refuses_tied_revise(self):
        models = ["base", "path", "loop"]
        outcomes = dict(zip(models, ({"outcome": value} for value in ("quiet", "report", "report"))))
        positions = [dict(case_id="hard", stage="B", label="positive", results=outcomes)]
        pool = {"hard": ({}, outcomes)}

        action, final, reasons = choose(models, "base", pool, positions, [], 0)

        self.assertEqual((action, final), ("unresolved", None))
        self.assertIn({"reason": "non_unique_alignment", "aligned_explanations": ["loop", "path"]}, reasons)

    def test_unique_keep_and_revise_require_evidence(self):
        models = ["base", "path"]
        outcomes = {"base": {"outcome": "quiet"}, "path": {"outcome": "report"}}
        pool = {"hard": ({}, outcomes)}
        for label, expected in (("positive", ("revise", "path")), ("negative", ("keep", "base"))):
            with self.subTest(label=label):
                positions = [dict(case_id="hard", stage="B", label=label, results=outcomes)]
                self.assertEqual(choose(models, "base", pool, positions, [], 0)[:2], expected)
        self.assertEqual(choose(models, "base", pool, [], [], 0)[:2], ("unresolved", None))

    def test_exhaustion_and_uncovered_keep_the_disagreement_open(self):
        models = ["base","peer"]
        known = {"base":{"outcome":"quiet"}, "peer":{"outcome":"quiet"}}
        gap = {"base":{"outcome":"uncovered"}, "peer":{"outcome":"report"}}
        positions = [dict(case_id="control", stage="B", label="negative", results=known)]
        pool = {"control":({},known), "material":({},gap)}
        self.assertEqual(choose(models,"base",pool,positions,[],0)[0], "unresolved")
        self.assertEqual(choose(models,"base",pool,positions,[],1)[0], "seek_evidence")
        positions.append(dict(case_id="material", stage="B", label="positive", results=gap))
        self.assertEqual(choose(models,"base",pool,positions,[],0)[:2], ("revise","peer"))
        gap["base"]["outcome"] = "spec_conflict"
        self.assertEqual(choose(models,"base",pool,positions,[],0)[0],"B4")
        gap["base"]["outcome"] = gap["peer"]["outcome"] = "quiet"
        self.assertEqual(choose(models,"base",pool,positions,[],0)[0],"A5")

    def test_independent_partition_and_action(self):
        yes = ["a@1","quiet","report","v@1"]
        same = ["b@1","quiet","quiet","w@1"]
        result = dict(action="revise",changed_judgments=[yes],preserved_judgments=[same])
        check_claims(result,result)
        for changes in (dict(action="keep"), dict(preserved_judgments=[]), dict(changed_judgments=[yes,yes]),
                        dict(changed_judgments=[yes,same]), dict(changed_judgments=[[*yes[:3],"v@2"]])):
            with self.subTest(changes=changes), self.assertRaises(LedgerError):
                check_claims(result,result | changes)


@unittest.skipUnless(os.environ.get("VARYROOT_R08_DOCKER") == "1","requires registered Step 06 verifier image")
class PublishedHandoff(unittest.TestCase):
    def test_revise_keep_unresolved_pass_step01(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Ledger(Path(os.environ.get("VARYROOT_B_TRACE", tmp)) / "b6-gates")
            image = image_id()
            for action, baseline, other in (("revise","check_seen","nonnull_or_exit"),
                                           ("keep","nonnull_or_exit","check_seen"),
                                           ("unresolved","nonnull_or_exit","check_seen"),
                                           ("partial","nonnull_or_exit","check_seen")):
                run = "fixture-"+action
                bind_fixture(db,run,"rebind",initial=baseline,competitors=(other,))
                self.assertEqual(qualify(db,run)["state"],"seed_accepted")
                pool = build_pool(db,run,image)
                replay = dict(pool, cases=[{k:v for k,v in c.items() if k!="files"} for c in pool["cases"]])
                matrix = {c["case_id"]:c["predictions"] for c in pool["cases"]}
                files = {c["case_id"]:dict(c["files"]) for c in pool["cases"]}
                pool_cases = {c["case_id"]:c for c in pool["cases"]}
                rows = []
                for case_id, f in files.items():
                    target, authority, domain = (json.loads(f[n+".json"]) for n in ("target","contract","domain"))
                    if action=="partial" and pool_cases[case_id]["operator"]=="npd_act_observe":
                        f["domain.json"] = encode(dict(domain,inputs=[0]))
                    if action=="partial" and pool_cases[case_id]["operator"]=="npd_note_before":
                        f["target.json"] = encode(dict(target,object_name="wrong"))
                    rows.append(dict(case=case_id,target=target["target_ref"],domain=domain["id"],
                                contract=authority["id"]+"@"+str(authority["version"]),verifier=image,input_sha=input_hash(f,image)))
                rows.sort(key=lambda r:r["case"])
                register_batch(db,run,"round",rows,matrix,[],dict(k=2,group="test"),replay)
                if action=="unresolved":
                    selected = [r for r in rows if pool_cases[r["case"]]["equivalent"]][:1]
                elif action=="partial":
                    selected = [r for r in rows if pool_cases[r["case"]]["operator"] in ("npd_act_observe","npd_note_before")]
                else:
                    selected = [r for r in rows if pool_cases[r["case"]]["operator"]=="npd_act_observe"]
                db.select(run,"pick",db.run(run)["version"],"round",pool_hash(rows),selected)
                verify_selected(db,run,"round",files,image)
                with self.assertRaises(LedgerError):
                    finalize(db,run,claims=dict(action="keep",changed_judgments=[],preserved_judgments=[]))
                self.assertEqual(db.run(run)["state"],"adjudicating")
                result = finalize(db,run)
                self.assertEqual(result["action"],"unresolved" if action=="partial" else action,result["remaining_disagreements"])
                if action=="partial":
                    self.assertEqual({p["reason"] for p in result["excluded"]},{"pending","case_exec_failure"})
                    self.assertEqual(set(p["stage"] for p in result["positions"]),{"A4"})
                else:
                    self.assertEqual(set(p["stage"] for p in result["positions"]),{"A4","B"})
                self.assertEqual(finalize(db,run),result)
                path = write_bundle(result,Path(tmp)/action)
                self.assertEqual(cli(["validate",str(path)])["code"],"ok")
                if action=="revise":
                    self.assertEqual(len(result["changed_judgments"]),1)
                    self.assertEqual(len(result["preserved_judgments"]),2)
                if action in ("unresolved","partial"):
                    self.assertIsNone(result["final_spec_ref"])
                else:
                    for target in json.loads(path.read_bytes())["target_refs"]:
                        self.assertIn(cli(["explain",str(path),target])["outcome"],("report","quiet"))
