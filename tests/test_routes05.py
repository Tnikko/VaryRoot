import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from varyroot.ledger import Ledger,LedgerError,pool_hash
from varyroot.publication import Publication,digest,encode
from varyroot.source_seed import prepare_seed
from varyroot.qualification import qualify,prepared,attach
from varyroot.seed_fixture import bind_fixture
from varyroot.verify_request import image_id,input_hash,execute_request
from varyroot.sandbox import run_role

CAT=Path(__file__).parent/"fixtures/agent_a/catalog.json"

@unittest.skipUnless(os.environ.get("VARYROOT_R07_DOCKER")=="1","requires A and verifier role images")
class Routes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        dest=os.environ.get("VARYROOT_05_TRACE")
        self.root=(Path(dest)/self._testMethodName) if dest else Path(self.tmp.name)/"store"
        self.db=Ledger(self.root)

    def test_arrays(self):
        for key,expected,reason in (("rebind","seed_accepted",None),("exit","seed_pending","missing_qualified_side"),
                                    ("unit","seed_pending","missing_logical_capacity_or_unit"),
                                    ("owner","seed_pending","wrong_capacity_object"),
                                    ("pending","seed_pending","pending_capacity_review")):
            folder=Path(self.tmp.name)/key
            folder.mkdir()
            catalog=json.loads(CAT.read_bytes())
            for f in catalog["files"]:
                name=f["path"]
                src=name.replace("after","after_rebound") if key=="rebind" and name.startswith("after") else name
                raw=(CAT.parent/src).read_bytes()
                if name=="proposal.json":
                    prop=json.loads(raw)
                    if key=="unit": prop["capacity"]["unit"]=None
                    if key=="owner": prop["subject"]="another"
                    if key=="pending": prop["capacity"]["approval"]="pending"
                    raw=encode(prop)
                (folder/name).write_bytes(raw)
                f.update(size=len(raw),sha256=digest(raw))
            path=folder/"catalog.json"
            path.write_bytes(encode(catalog))
            prepare_seed(self.root,path,key)
            res=qualify(self.db,key)
            self.assertEqual((res["state"],res.get("reason")),(expected,reason))
            if key in ("unit","owner","pending"):
                self.assertEqual({f["reason"] for f in res["missing_facts"]},{reason})
                self.assertEqual({f["fact_ref"] for f in res["missing_facts"]},
                                 {"fact.before.capacity@1","fact.after.capacity@1"})
            if reason:
                self.assertFalse(any(e["kind"]=="A6.replayed" for e in self.db.events(key)))

    def test_remodel_and_filter(self):
        for key,baseline,others,dest in (("filtered","nonnull_or_exit",("live_or_exit","seen"),"seed_accepted"),
                ("bad-base","seen",("nonnull_or_exit","live_or_exit"),"remodel"),
                ("bad-peers","nonnull_or_exit",("seen",),"remodel")):
            bind_fixture(self.db,key,"rebind",initial=baseline,competitors=others)
            result=qualify(self.db,key)
            self.assertEqual(result["state"],dest)
            self.assertNotIn("seen@1",result["survivors"])
            if dest=="remodel":
                cases=[dict(case="c",target="t",contract="k",domain="d",verifier="v",input_sha=digest(b"c"))]
                with self.assertRaises(LedgerError):
                    self.db.register(key,self.db.run(key)["version"],"b",pool_hash(cases),digest(b"p"),
                                     self.db.snapshot(key)["digest"],pool_cases=cases,source_kind="post_remodel")

    def test_budget_failure_retry_and_stale(self):
        run="version-bound"
        db=self.db
        bind_fixture(db,run,"exit")
        qualify(db,run)
        original=db.seed_package(run)
        image=image_id()
        files=prepared(original,"after")[0]
        partial=dict(files)
        partial["domain.json"]=encode({"id":"pointer_modes@1","inputs":[0]})
        wrong=dict(files)
        wrong["target.json"]=encode(dict(json.loads(files["target.json"]),object_name="other"))
        sets=[partial,wrong]
        rows=[dict(case=n,target=json.loads(f["target.json"])["target_ref"],contract="static-live-read@1",
                   domain="pointer_modes@1",verifier=image,input_sha=input_hash(f,image))
              for n,f in zip(("partial","invalid"),sets)]
        pool=pool_hash(rows)
        db.register(run,db.run(run)["version"],"b1",pool,digest(b"predictions"),db.snapshot(run)["digest"],pool_cases=rows)
        ids=db.select(run,"picked",db.run(run)["version"],"b1",pool,rows)
        evidence={}
        for index,(rid,items) in enumerate(zip(ids,sets,strict=True)):
            calls=[]
            def interrupted(view,argv,**kwargs):
                calls.append(1)
                if len(calls)==1 and index==0:
                    return run_role(view,["python","-c",
                       "import subprocess,sys; p=subprocess.run([sys.executable,'-c','import os;os.kill(os.getpid(),9)']);sys.exit(128-p.returncode)"],**kwargs)
                return run_role(view,argv,**kwargs)
            with patch("varyroot.verify_request.run_role",side_effect=interrupted):
                state,result=execute_request(db,run,rid,items,image)
            self.assertEqual(state["action"],"ready")
            if index==0:
                self.assertEqual(result["verdict"]["label"],"pending")
                self.assertEqual(result["attempt_id"],2)
            else:
                self.assertEqual(result["completion"],"case_exec_failure")
                self.assertNotIn("verdict",result)
                self.assertEqual(result["attempt_id"],1)
            self.assertEqual(db.balances(run)["B.verify"],0)
            evidence[rid]=state["digest"]
        db.deliver(run,"b1",evidence)
        side_requests={e["detail"]["side"]:e["detail"]["request_id"] for e in db.events(run)
                       if e["kind"]=="A4.request"}
        old=original["artifacts"]["before_sources"]["value"]
        db.rework_seed(run,db.run(run)["version"],1,branch="A2",reason="refresh source review",
                       changes={"before_sources":dict(old,review_version=2)})
        with self.assertRaisesRegex(LedgerError,"stale"):
            attach(db,run,1,"before",side_requests["before"])
        with self.assertRaisesRegex(LedgerError,"mismatch"):
            attach(db,run,2,"before",side_requests["before"])
        gate=db.seed_gate(run)
        self.assertIn("after_ok",gate["evidence"])
        self.assertIn("before_ok",gate["blockers"])
        self.assertEqual(qualify(db,run)["state"],"seed_accepted")
        self.assertEqual(len([e for e in db.events(run) if e["kind"]=="A4.request"]),3)


    def test_receipt_survives_lost_stdout_and_late_failure(self):
        import subprocess
        db=self.db
        run="lost-stdout"
        bind_fixture(db,run,"exit")
        calls=[]
        def disconnect(view,argv,**kwargs):
            proc=run_role(view,argv,**kwargs)
            self.assertEqual(proc.returncode,0,proc.stderr)
            calls.append(view.name)
            return subprocess.CompletedProcess(argv,137,"","lost transport after worker sealed receipt")
        with patch("varyroot.verify_request.run_role",side_effect=disconnect):
            result=qualify(db,run)
        self.assertEqual(result["state"],"seed_accepted")
        self.assertEqual(len(calls),2)


    def test_real_verifier_view(self):
        from varyroot.sandbox import Scope,materialize
        from varyroot.verifier_view import grants
        run="view"
        bind_fixture(self.db,run,"exit")
        files=prepared(self.db.seed_package(run),"after")[0]
        temp=Path(self.tmp.name)/"view-catalog"
        temp.mkdir()
        for k,v in files.items():
            (temp/k).write_bytes(v)
        (temp/"prediction.json").write_text("forbidden")
        dest=temp/"attempt"
        image=image_id()
        scope=Scope(run,"npd-fixture-v1","development",0,"verifier","verify","view",1)
        stamp=materialize(dest,temp,scope,grants(files,"development"))
        script="""import json,os
from pathlib import Path
view=Path('/input')
out=dict(files=sorted(p.name for p in view.iterdir()),modules=sorted(p.name for p in Path('/opt/role/varyroot').glob('*.py')),
         network=sorted(os.listdir('/sys/class/net')),docker_socket=Path('/var/run/docker.sock').exists())
try: (view/'write').write_text('test')
except OSError as e: out['write_errno']=e.errno
print(json.dumps(out))"""
        proc=run_role(dest,["python","-c",script],image=image)
        self.assertEqual(proc.returncode,0,proc.stderr)
        obs=json.loads(proc.stdout)
        self.assertEqual(obs["files"],sorted([*files,"input_manifest.json"]))
        self.assertEqual(obs["network"],["lo"])
        self.assertFalse(obs["docker_socket"])
        self.assertEqual(obs["write_errno"],30)
        self.assertNotIn("inference.py",obs["modules"])
        (self.root/"view.json").write_text(json.dumps(dict(obs,image=image,manifest_sha=stamp),indent=2))


    def test_selected_zero_and_partial_modes_each_charged_once(self):
        from varyroot.verifier_view import project
        run="budget-diagnostics"
        db=self.db
        bind_fixture(db,run,"exit")
        qualify(db,run)
        image=image_id()
        cases=[]
        views=[]
        for directory,file,expr,policy,domain,inputs in (
            ("extent05","zero.c",b"read_slice(buffer, 8, 0)","byte-buffer","singleton@1",[0]),
            ("npd05","modes.c",b"read_required(p)","static-live-read","three_modes@1",[0,1])):
            base=CAT.parent.parent/directory
            src=(base/file).read_bytes()
            contract=json.loads((base/"contract.json").read_bytes())
            start=src.index(expr)
            t=dict(target_ref="access."+digest(src),snapshot_ref="src."+digest(src)+"@1",file_digest=digest(src),
                   byte_span=[start,start+len(expr)],operation="read",object_name=contract["subject"])
            files=project(src,t,contract,dict(id=domain,inputs=inputs))
            views.append(files)
            cases.append(dict(case=file,target=t["target_ref"],contract=policy+"@1",domain=domain,
                              verifier=image,input_sha=input_hash(files,image)))
        pool=pool_hash(cases)
        db.register(run,2,"b",pool,digest(b"selection-fixture"),db.snapshot(run)["digest"],pool_cases=cases)
        ids=db.select(run,"selection",3,"b",pool,cases)
        for rid,files,missing in zip(ids,views,([],[2]),strict=True):
            status,row=execute_request(db,run,rid,files,image)
            self.assertEqual(row["verdict"]["label"],"pending")
            self.assertEqual(row["verdict"]["missing"],missing)
            self.assertEqual(row["attempt_id"],1)
            self.assertEqual(execute_request(db,run,rid,files,image),(status,row))
        self.assertEqual(db.balances(run)["B.verify"],0)

    def test_retired_domain_cannot_attach(self):
        from varyroot.verify_request import reserve
        db=self.db
        run="retired-domain"
        bind_fixture(db,run,"exit")
        p=db.seed_package(run)
        files=prepared(p,"after")[0]
        # The old request and receipt are internally consistent, but name a retired observer domain.
        old=dict(files)
        old["domain.json"]=encode(dict(id="pointer_modes@0",inputs=[0,1]))
        image=image_id()
        rid=reserve(db,run,p,"after",old,image)
        state,result=execute_request(db,run,rid,old,image)
        self.assertEqual(state["action"],"ready")
        self.assertEqual(result["completion"],"case_exec_failure")
        with self.assertRaisesRegex(LedgerError,"mismatch"):
            attach(db,run,1,"after",rid)
        self.assertEqual(db.run(run)["state"],"seed_pending")
        self.assertFalse(any(e["kind"]=="A6.replayed" for e in db.events(run)))
        self.assertEqual(qualify(db,run)["state"],"seed_accepted")
