"""Archive integrity, full C1/C4/C5 gates and crash recovery in a real SQLite store."""
import json
import os
import signal
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

from varyroot.b_batch import save_object
from tools.codeql07.replay import replay_files
from varyroot.agent_c import compile_manifest, emit_queries, regression, verify_outputs
from varyroot.c_ledger import budget_snapshot, finish_regression, frozen_receipt, reserve_shared_repair, start_regression
from varyroot.freeze_archive import MANIFEST, build_archive, restore_archive, verify_archive
from varyroot.ledger import Ledger, LedgerError
from varyroot.publication import digest, encode


class Archive(unittest.TestCase):
    def test_restore_checks_contents_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "query"
            source.write_bytes(b"content\n")
            archive = root / "archive"
            files = {"queries/Q0.ql":source, "queries/Qstar.ql":source}
            sha = build_archive(archive, files)
            self.assertEqual(build_archive(archive, files), sha)
            restored = restore_archive(archive, sha, root / "empty")
            self.assertEqual(verify_archive(restored, sha), verify_archive(archive, sha))
            with self.assertRaises(LedgerError):
                restore_archive(archive, sha, restored)
            for name in ("../external","/absolute","a//b",r"a\b","x:stream","a/NUL","freeze-manifest.json"):
                with self.subTest(name=name), self.assertRaises(LedgerError):
                    build_archive(root / "bad", {name:source})
            for name in ("extra", "Queries/q0.ql"):
                path = restored / name
                path.parent.mkdir(exist_ok=True)
                path.write_text("extra")
                with self.assertRaises(LedgerError):
                    verify_archive(restored, sha)
                path.unlink()
            (archive / "queries/Q0.ql").unlink()
            with self.assertRaises(LedgerError):
                verify_archive(archive, sha)
            (archive / "queries/Q0.ql").symlink_to(source)
            with self.assertRaises(LedgerError):
                verify_archive(archive, sha)

    def test_stale_manifest_and_mutated_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "data"
            source.write_bytes(b"first")
            sha = build_archive(root / "sealed", {"data":source})
            (root / "sealed/data").write_bytes(b"second")
            with self.assertRaisesRegex(LedgerError, "digest mismatch"):
                restore_archive(root / "sealed", sha, root / "restore")
            self.assertFalse((root / "restore").exists())
            source.write_bytes(b"second")
            with self.assertRaisesRegex(LedgerError, "manifest digest mismatch"):
                build_archive(root / "sealed", {"data":source})


class PairTransaction(unittest.TestCase):
    """Feed synthetic engine receipts through the full gates on accepted Step 06 data."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.work = self.root / "inputs"
        self.work.mkdir()
        self.db = Ledger(self.root / "store")
        self.run = "fixture-revise"
        self.db.create_run(self.run, "fixture", repair=1)
        data = Path(__file__).resolve().parents[1] / "docs/step-06"
        b6 = json.loads((data / "raw" / self.run / "b6.json").read_bytes())
        for key in ("manifest","records"):
            b6[key] = json.loads((data / "handoffs" / self.run / (key+".json")).read_bytes())
        if self._testMethodName in ("test_b4_restores_batch_and_evidence","test_conflict_notified_on_unmeasured_lane"):
            # Fault injection: B approves keeping the old spec despite a qualified positive.
            b6.update(action="keep",final_spec_ref=b6["initial_spec_ref"], revision_ref=None)
            b6["manifest"]["spec_ref"] = b6["initial_spec_ref"]
            b6["records"] = [r for r in b6["records"] if r["kind"]!="Revision"]
            for r in b6["records"]:
                if r["kind"]=="Decision":
                    r.update(action="keep")
                if r["kind"]=="Handoff":
                    r.update(final_spec_ref=b6["initial_spec_ref"],revision_ref=None)
        snap = self.db.snapshot(self.run)
        b6.update(snapshot=snap["digest"],watermark=snap["watermark"],group=snap["group"])
        for key in ("manifest","records"):
            self.write("handoff/"+key+".json", encode(b6[key]))
        self.write("handoff/b6.json",encode(b6))
        sha = save_object(self.db,b6)
        with self.db.tx() as c:
            self.db._advance(c,self.db._run(c,self.run),"adjudicating",{"fixture":"Step 06"},batch="b1")
            ready = self.db._advance(c,self.db._run(c,self.run),"spec_ready",dict(handoff_sha=sha,
                       action=b6["action"],baseline=b6["initial_spec_ref"], final=b6["final_spec_ref"],
                       revision_ref=b6["revision_ref"],snapshot=snap["digest"]))
        with ZipFile(self.work/"database.zip","w") as z:
            z.writestr("test-snapshot","transaction unit test")
        self.lock = dict(database_sha256=digest((self.work/"database.zip").read_bytes()),
                         tool_tree_sha256=digest(b"test tool"),runtime_image="sha256:"+digest(b"test image"),
                         cli_version="test",cpp_all="test",threads=1,ram=512)
        self.write("toolchain.json",encode(self.lock))
        self.c1 = compile_manifest(self.work / "handoff")
        self.version = start_regression(self.db,self.run,ready["version"],self.c1,toolchain=self.lock)["version"]
        self.write("c1.json",encode(self.c1))
        for name, path in replay_files(Path(__file__).resolve().parents[1]).items():
            self.write(name,path.read_bytes())
        self.pack_sha = digest(encode({k:digest(v) for k,v in emit_queries(self.c1).items()}))
        for name, raw in emit_queries(self.c1).items():
            self.write("queries/"+name,raw)
        self.records = {r["id"]+"@"+str(r["version"]):r for r in b6["records"]}

    def write(self, name, raw):
        path = self.work / name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)

    def stage(self, route="freeze"):
        self.write("budget.json",encode(budget_snapshot(self.db,self.run)))
        log = []
        for lane in ("Q0","Qstar"):
            log.extend([dict(argv=["codeql","query","run",lane+".ql","--output="+lane+".bqrs",
                                   "--database=/fixture/db"],exit_code=0,output="ok"),
                        dict(argv=["codeql","bqrs","decode","--format=csv","--output="+lane+".csv",
                                   lane+".bqrs"],exit_code=0,output="ok")])
            csv = ["filename,sl,sc,el,ec,kind,multiplicity"]
            for i, t in enumerate(self.c1["targets"]):
                src = self.records[t["snapshot_ref"]]["files"][t["file"]].encode()
                coords = []
                for pos in (t["expr_span"][0],t["expr_span"][1]-1):
                    coords += [str(src[:pos].count(b"\n")+1),str(pos-src[:pos].rfind(b"\n"))]
                prefix = ",".join([t["file_digest"]+".c",*coords])+","
                csv.append(prefix+"site,1")
                wanted = t["predictions"][lane]=="report"
                if route=="repair" and lane=="Qstar" and i==0:
                    wanted = not wanted
                if wanted:
                    csv.append(prefix+"alert,1")
            raw = ("\n".join(csv)+"\n").encode()
            self.write("results/"+lane+".csv",raw)
            self.write("results/"+lane+".bqrs",b"unit-test-engine-result")
            self.write("results/"+lane+".status.json",encode(dict(completed=True,exit_code=0,query_exit_code=0,decode_exit_code=0,
                 query_sha256=digest((self.work/"queries"/(lane+".ql")).read_bytes()),
                 toolchain_sha256=digest(encode(self.lock)),query_pack_sha256=self.pack_sha,
                 bqrs_sha256=digest(b"unit-test-engine-result"), database_sha256=self.lock["database_sha256"],csv_sha256=digest(raw))))
        self.write("build-log.json",encode(log))
        c4 = verify_outputs(self.work,self.c1)
        self.write("c4.json",encode(c4))
        self.write("c5.json",encode(regression(self.c1,c4)))
        archive = self.root / ("sealed-"+str(self.head())+"-"+route)
        self.seal(archive)
        return archive

    def seal(self, archive):
        return build_archive(archive,{p.relative_to(self.work).as_posix():p for p in self.work.rglob("*") if p.is_file()})

    def head(self):
        return self.db.events(self.run)[-1]["commit_seq"]

    def finish(self, head, archive, route, checkpoint=None):
        return finish_regression(self.db,self.run,self.version,head,archive,checkpoint=checkpoint)

    def test_paid_repair_requires_committed_parent_despite_resealing(self):
        from varyroot.repair_parent import validate_parent
        prior = self.stage("repair")
        self.finish(self.head(),prior,"repair")

        def decode(*argv):
            output = Path(next(a[9:] for a in argv if str(a).startswith("--output=")))
            output.write_bytes((prior/"results"/(Path(argv[-1]).stem+".csv")).read_bytes())

        engine = SimpleNamespace(work=self.root,command=decode)
        parent,diagnostic = validate_parent(self.db,self.run,self.db.run(self.run),prior,self.c1,
                                           self.lock,engine,self.work)
        ids = reserve_shared_repair(self.db,self.run,self.version,parent,diagnostic,1)
        from varyroot.c_pipeline import finish_repairs
        finish_repairs(self.db,ids,dict(shared_sha=digest((self.work/"queries/shared.qll").read_bytes()),
                                       parent_sha=parent,diagnostic=diagnostic))
        valid = self.stage()
        head = self.head()
        files = {n: valid/n for n in verify_archive(valid)}
        repaired = {n:p for n,p in files.items() if not n.startswith("repair/")}
        missing = self.root/"missing-paid-parent"
        build_archive(missing,repaired)
        with self.assertRaisesRegex(LedgerError,"paid repair parent manifest"):
            self.finish(head,missing,"freeze")
        nested = {k.removeprefix("repair/"):p for k,p in files.items()
                  if k.startswith("repair/") and k != "repair/"+MANIFEST}
        alternate = self.root/"altered-paid-parent"
        fake = self.root/"other-report"
        fake.write_bytes(encode({"route":"repair"}))
        build_archive(alternate,dict(nested,**{"parent-c5.json":fake}))
        substituted = dict(repaired,**{"repair/"+n:alternate/n for n in (*nested,MANIFEST)})
        resealed = self.root/"reissued"
        build_archive(resealed,substituted)
        with self.assertRaisesRegex(LedgerError,"paid repair parent manifest"):
            self.finish(head,resealed,"freeze")
        # Keeping the original nested manifest name and bytes cannot hide a removed raw file.
        missing_raw = self.root/"parent-raw-missing"
        build_archive(missing_raw,{n:p for n,p in files.items() if n != "repair/results/Q0.bqrs"})
        with self.assertRaisesRegex(LedgerError,"paid repair inventory"):
            self.finish(head,missing_raw,"freeze")
        receipt = self.finish(head,valid,"freeze")
        self.assertEqual(frozen_receipt(self.db,self.run)["freeze_id"],receipt["freeze_id"])

    def test_shared_repair_reserves_both_lanes_once(self):
        args = (self.db,self.run,self.version,digest(b"shared"),digest(b"diagnostic"),1)
        ids = reserve_shared_repair(*args)
        self.assertEqual(ids,reserve_shared_repair(*args))
        self.assertEqual(len(set(ids)),2)
        budget = budget_snapshot(self.db,self.run)
        self.assertEqual([budget[k]["remaining"] for k in ("Q0","Qstar")],[0,0])
        self.assertEqual([budget[k]["charges"][0]["request_id"] for k in ("Q0","Qstar")],ids)

    def test_shared_repair_rolls_back_on_second_lane_exhaustion(self):
        self.db.repair(self.run,"first",self.version,"Qstar","parent","diagnostic",1,digest(b"input"))
        prior,head = budget_snapshot(self.db,self.run), self.head()
        with self.assertRaisesRegex(LedgerError,"insufficient balance"):
            reserve_shared_repair(self.db,self.run,self.version,digest(b"shared"),digest(b"diagnostic"),1)
        self.assertEqual(prior,budget_snapshot(self.db,self.run))
        self.assertEqual(head,self.head())

    def test_independent_charges_exhaustion_and_stale_watermark(self):
        stale, archive = self.head(), self.stage("repair")
        args = (self.run, "repair-key", self.version, "Qstar", "parent-query", "diagnostic",1,digest(b"input"))
        first = self.db.repair(*args)
        self.assertEqual(self.db.repair(*args), first)
        self.assertEqual(budget_snapshot(self.db,self.run)["Qstar"]["remaining"],0)
        self.assertEqual(budget_snapshot(self.db,self.run)["Q0"]["remaining"],1)
        with self.assertRaisesRegex(LedgerError,"stale C event watermark"):
            self.finish(stale,archive,"repair")
        with self.assertRaisesRegex(LedgerError,"stale C repair budget"):
            self.finish(self.head(),archive,"repair")
        with self.assertRaisesRegex(LedgerError,"pending C repair"):
            self.finish(self.head(),self.stage(),"freeze")
        receipt = self.finish(self.head(),self.stage("repair"),"repair")
        self.assertEqual((receipt["state"],receipt["failed_lanes"],receipt["budget_exhausted"]),
                         ("partial",["Qstar"],["Qstar"]))
        self.assertNotIn("freeze_id",receipt)

    def test_b4_restores_batch_and_evidence(self):
        snap = self.db.snapshot(self.run)
        receipt = self.finish(self.head(),self.stage(),"B4")
        self.assertEqual((receipt["state"],receipt["route"],receipt["batch"]),("adjudicating","B4","b1"))
        self.assertEqual(snap,self.db.snapshot(self.run))
        self.assertEqual(budget_snapshot(self.db,self.run)["Qstar"]["charges"],[])
        self.assertNotIn("freeze_id",receipt)

    def test_false_score_and_false_completion_claim(self):
        self.stage()
        report = json.loads((self.work/"c5.json").read_bytes())
        report["lanes"]["Q0"]["rows"][0]["score"] = "invented"
        self.write("c5.json",encode(report))
        altered = self.root/"forged"
        self.seal(altered)
        with self.assertRaisesRegex(LedgerError,"C5 differs"):
            self.finish(self.head(),altered,"freeze")
        status = json.loads((self.work/"results/Q0.status.json").read_bytes())
        status["completed"] = "false"
        self.write("results/Q0.status.json",encode(status))
        self.seal(self.root/"bad-status")
        with self.assertRaisesRegex(LedgerError,"engine completion"):
            self.finish(self.head(),self.root/"bad-status","freeze")
        self.assertEqual(self.db.run(self.run)["state"],"regressing")

    def test_missing_or_inconsistent_build_log_blocks_publication(self):
        self.stage()
        log = json.loads((self.work/"build-log.json").read_bytes())
        (self.work/"build-log.json").unlink()
        self.seal(self.root/"missing-command-log")
        with self.assertRaisesRegex(LedgerError,"missing C gate dependencies"):
            self.finish(self.head(),self.root/"missing-command-log","freeze")
        log[-1]["exit_code"] = 2
        self.write("build-log.json",encode(log))
        self.seal(self.root/"failed-decode")
        with self.assertRaisesRegex(LedgerError,"contradicts build command log"):
            self.finish(self.head(),self.root/"failed-decode","freeze")
        self.assertEqual(self.db.run(self.run)["state"],"regressing")

    def incomplete_lane(self):
        self.stage()
        status = json.loads((self.work/"results/Qstar.status.json").read_bytes())
        status.update(completed=False,exit_code=137,query_exit_code=137,decode_exit_code=None,
                      bqrs_sha256=None,csv_sha256=None)
        self.write("results/Qstar.status.json",encode(status))
        log = json.loads((self.work/"build-log.json").read_bytes())[:-1]
        log[-1].update(exit_code=137,output="terminated")
        self.write("build-log.json",encode(log))
        (self.work/"results/Qstar.csv").unlink()
        (self.work/"results/Qstar.bqrs").unlink()
        c4 = verify_outputs(self.work,self.c1)
        self.write("c4.json",encode(c4))
        report = regression(self.c1,c4)
        self.write("c5.json",encode(report))
        altered = self.root/"interrupted"
        self.seal(altered)
        return self.finish(self.head(),altered,"partial"),report

    def test_conflict_notified_on_unmeasured_lane(self):
        result, report = self.incomplete_lane()
        self.assertEqual(result["state"],"partial")
        event, = [e for e in self.db.events(self.run) if e["kind"]=="C5.B4_evidence_conflict"]
        self.assertEqual(result["b4_notification_seq"],event["commit_seq"])
        rows = event["detail"]["rows"]
        self.assertEqual(rows,[r for r in report["lanes"]["Qstar"]["rows"] if r["evidence_conflict"]])
        self.assertTrue(rows and all(not r["fidelity"] and r["actual_output"]=="unavailable" for r in rows))

    def test_decode_failure_keeps_bqrs_and_excludes_lane_from_scoring(self):
        self.stage()
        status = json.loads((self.work/"results/Qstar.status.json").read_bytes())
        status.update(completed=False, exit_code=2, decode_exit_code=2, csv_sha256=None)
        self.write("results/Qstar.status.json",encode(status))
        log = json.loads((self.work/"build-log.json").read_bytes())
        log[-1].update(exit_code=2,output="decode failed")
        self.write("build-log.json",encode(log))
        (self.work/"results/Qstar.csv").unlink()
        c4 = verify_outputs(self.work,self.c1)
        report = regression(self.c1,c4)
        self.write("c4.json",encode(c4))
        self.write("c5.json",encode(report))
        archive = self.root/"decode-failure"
        self.seal(archive)
        (self.work/"results/Qstar.bqrs").unlink()
        self.seal(self.root/"lost-bqrs")
        with self.assertRaisesRegex(LedgerError,"raw BQRS digest mismatch"):
            self.finish(self.head(),self.root/"lost-bqrs","partial")
        receipt = self.finish(self.head(),archive,"partial")
        self.assertEqual(receipt["failed_lanes"],["Qstar"])
        self.assertTrue(all(r["score"] is None for r in report["lanes"]["Qstar"]["rows"]))

    def test_single_incomplete_lane_preserved_as_partial(self):
        result, report = self.incomplete_lane()
        self.assertEqual(result["state"],"partial")
        self.assertEqual(result["failed_lanes"],["Qstar"])
        self.assertTrue(all(row["score"] is None for row in report["lanes"]["Qstar"]["rows"]))
        self.assertNotIn("freeze_id",result)
        with self.assertRaisesRegex(LedgerError,"no committed"):
            frozen_receipt(self.db,self.run)

    def test_missing_artifact_after_freeze_invalidates_retrieval(self):
        head, archive = self.head(), self.stage()
        self.finish(head,archive,"freeze")
        (archive / "c5.json").unlink()
        with self.assertRaisesRegex(LedgerError,"missing or unlisted"):
            self.finish(head,archive,"freeze")

    @unittest.skipUnless(hasattr(os,"fork"),"requires POSIX SIGKILL")
    def test_sigkill_before_and_after_commit_exactly_one_freeze(self):
        head, archive = self.head(), self.stage()
        for phase, expected in (("before_commit","regressing"),("after_commit","frozen")):
            pid = os.fork()
            if pid == 0:
                def kill(at):
                    if at == phase:
                        os.kill(os.getpid(),signal.SIGKILL)
                try:
                    self.finish(head,archive,"freeze",kill)
                finally:
                    os._exit(17)
            _, status = os.waitpid(pid,0)
            self.assertEqual(os.waitstatus_to_exitcode(status),-signal.SIGKILL)
            self.assertEqual(self.db.run(self.run)["state"],expected)
        receipt = self.finish(head,archive,"freeze")
        self.assertEqual(receipt,self.finish(head,archive,"freeze"))
        self.assertEqual(frozen_receipt(self.db,self.run)["freeze_id"],receipt["freeze_id"])
        events = [r for r in self.db.events(self.run) if r["kind"]=="frozen"]
        self.assertEqual([r["detail"]["detail"]["freeze_id"] for r in events],[receipt["freeze_id"]])
        self.assertEqual(receipt["archive_sha"],digest((archive / MANIFEST).read_bytes()))


if __name__ == "__main__":
    unittest.main()
