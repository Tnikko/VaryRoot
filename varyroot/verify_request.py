"""Reserve and dispatch a version-bound verifier role through the publication fence."""
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

from .ledger import LedgerError
from .publication import Publication,digest,encode
from .sandbox import Scope,materialize,resolve_image,run_role
from .verifier_view import grants

IMAGE="varyroot-verifier:step05"


def image_id():
    return resolve_image(IMAGE)


def input_hash(files,image):
    return digest(encode({"image":image,"files":{k:digest(v) for k,v in files.items()}}))


def reserve(db,run,package,side,files,image):
    sha=input_hash(files,image)
    identity={"stage":"A4","side":side,"version":package["version"],
              "basis":package["role_refs"][side+"_basis"],"image":image,
              "observation_domain":digest(files["domain.json"])}
    key=digest(encode(identity))
    with db.tx() as c:
        if db._run(c,run)["state"]!="seed_pending" or db._seed_package(c,run)["version"]!=package["version"]:
            raise LedgerError("stale seed before dispatch")
        row=c.execute("SELECT request_id,input_sha FROM requests WHERE run_id=? AND account='A.bootstrap' AND business_key=?",
                      (run,key)).fetchone()
        if row:
            if row["input_sha"]!=sha:
                raise LedgerError("changed request for this identity")
            return row["request_id"]
        rid=uuid.uuid4().hex
        c.execute("INSERT INTO requests(request_id,run_id,account,business_key,input_sha,intent) VALUES(?,?,'A.bootstrap',?,?,?)",
                  (rid,run,key,sha,encode(identity).decode()))
        c.execute("INSERT INTO dispatch VALUES(?)",(rid,))
        db.event(c,run,"A4.request",dict(identity,request_id=rid,input_sha=sha))
        return rid


def execute_request(db,run,rid,files,image):
    pub=Publication(db,lease_seconds=120)
    current=db.run(run)
    entries=grants(files,current["group_name"])
    sha=input_hash(files,image)
    with db.tx() as c:
        row=c.execute("SELECT input_sha,account,intent FROM requests WHERE request_id=? AND run_id=?",(rid,run)).fetchone()
        if not row or row["input_sha"]!=sha or row["account"] not in ("A.bootstrap","B.verify"):
            raise LedgerError("request projection or owner mismatch")
        if row["account"]=="B.verify":
            intent=json.loads(row["intent"])
            policy=json.loads(files["contract.json"])
            expected=dict(verifier=image,target=json.loads(files["target.json"])["target_ref"],
                          domain=json.loads(files["domain.json"])["id"],contract=f'{policy["id"]}@{policy["version"]}')
            if any(intent[k]!=v for k,v in expected.items()):
                raise LedgerError("selected target, contract, domain or tool differs")
    def invoke(attempt):
        with tempfile.TemporaryDirectory(dir=db.root) as temp:
            root=Path(temp)
            for name,raw in files.items():
                (root/name).write_bytes(raw)
            scope=Scope(run,current["seed"],current["group_name"],current["repeat"],"verifier","verify",
                        rid,str(attempt["attempt_id"]),db.snapshot(run)["watermark"])
            view=root/"role"
            stamp=materialize(view,root,scope,entries)
            with db.tx() as c:
                c.execute("INSERT INTO verifier_attempt_views VALUES(?,?,?)",(rid,attempt["attempt_id"],stamp))
                db.event(c,run,"manifest",dict(role="verifier",request_id=rid,attempt_id=attempt["attempt_id"],
                                               digest=stamp,files=sorted(files),image=image))
            try:
                return run_role(view,["python","-m","varyroot.verifier_worker",encode(attempt).decode()],
                                image=image,output_dir=pub.staging/attempt["token"])
            finally:
                audit_path=view/"execution.json"
                if audit_path.exists():
                    with db.tx() as c:
                        db.event(c,run,"role.execution",json.loads(audit_path.read_bytes()))
    result=pub.recover(rid)
    while result["action"]=="dispatch":
        attempt=result
        if not pub.claim(attempt):
            return {"action":"stale"},None
        try:
            proc=invoke(attempt)
            diagnostic={"completion":"infra_failure","exit_status":proc.returncode,"reason":"missing_valid_receipt"}
        except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
            diagnostic={"completion":"infra_failure","reason":str(exc)}
        result=pub.recover(rid,finished=(attempt,diagnostic))
    return (result,pub.read(rid)) if result["action"]=="ready" else (result,None)
