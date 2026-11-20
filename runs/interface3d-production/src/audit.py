import json
import sqlite3
from contextlib import closing
import tempfile
from pathlib import Path
from varyroot.ledger import Ledger
from varyroot.publication import Publication, digest, encode
from varyroot.openldap_qualification import (
    RUN, STATIC, OBS, load, validate_observation, observation_inputs, _grants,
)
from varyroot.sandbox import Scope, materialize

ROOT=Path("runs/interface3d-production")
OUT=ROOT/"out"
db=Ledger(STATIC/"production-ledger")
run=db.run(RUN)
package=db.seed_package(RUN)
gate=db.seed_gate(RUN)
events=db.events(RUN)
assert run["state"]=="seed_accepted" and gate["blockers"]==[]
names=[e["kind"] for e in events]
assert names.count("seed_accepted")==1
accepted=next(e for e in events if e["kind"]=="seed_accepted")
a6=next(e for e in events if e["kind"]=="A6.replayed")
mapping=next(e for e in events if e["kind"]=="A4.mapping_approved")
assert a6["commit_seq"] < mapping["commit_seq"] < accepted["commit_seq"]
details=accepted["detail"]["detail"]
assert details["baseline_spec"]=="spec.openldap.H_check@1"
assert len(details["surviving_explanations"])==3
assert details["scope"]["approval"]=="accepted_for_scope"
assert details["functional_note"]=={
    "fixed_mode4_attribute_traversal_truncated":True,
    "parent_post_violation_behavior":"undetermined"}
assert details["contract"]["reference_commit"]=="40421915e08ed1a10b5703973116705a94190ab0"
assert details["contract"]["historical_deployment_version_verified"] is False
assert len(details["contract"]["basis"])==3
assert all(c["status"]=="matched" for c in a6["detail"]["candidates"])
assert a6["detail"]["route"]=="accept"
assert set(gate["evidence"])=={"before_ok","after_ok","mapping_ok","contracts_ok","candidates_ok","versions_ok"}
pub=Publication(db)
summary={"run_id":RUN,"state":run["state"],"run_version":run["version"],
         "seed_package_version":package["version"],"gate":gate,
         "accept_commit_seq":accepted["commit_seq"],"a6_commit_seq":a6["commit_seq"],
         "mapping_commit_seq":mapping["commit_seq"],"baseline_spec":details["baseline_spec"],
         "survivors":details["surviving_explanations"],
         "scope":details["scope"]["scope"],
         "reference_commit":details["contract"]["reference_commit"],
         "functional_note":details["functional_note"],
         "denominator":{"attempted_unique_seed":1,"production_accepted":1,"pending":0},
         "sides":{}}
for side,label in (("before","positive"),("after","negative")):
    request=next(e["detail"] for e in events if e["kind"]=="A4.request" and e["detail"]["side"]==side)
    rid=request["request_id"]
    receipt=pub.read(rid)
    with db.tx() as c:
        q=c.execute("SELECT * FROM requests WHERE request_id=?",(rid,)).fetchone()
        attempts=c.execute("SELECT * FROM execution_attempts WHERE request_id=?",(rid,)).fetchall()
        view=c.execute("SELECT * FROM verifier_attempt_views WHERE request_id=?",(rid,)).fetchone()
        intent=c.execute("SELECT * FROM publication_intents WHERE request_id=?",(rid,)).fetchone()
    assert q["state"]=="ready" and q["account"]=="A.bootstrap"
    assert len(attempts)==1 and attempts[0]["attempt_id"]==1 and attempts[0]["state"]=="accepted"
    assert intent["state"]=="ready" and intent["digest"]==digest(encode(receipt))
    assert receipt["label"]==label and receipt["coverage_basis"]=="exhaustive_finite_domain"
    binding=receipt["binding"]
    assert binding["seed_package_sha256"]==package["packet_sha"]
    assert binding["contract_sha256"]==request["contract_sha256"]
    assert receipt["domain_sha256"]==request["domain_sha256"]
    validate_observation(receipt,{"request_id":rid,"attempt_id":"1",
                         "manifest_sha256":view["manifest_sha"],
                         "domain_sha256":request["domain_sha256"],
                         "binding":binding,"mapping_status":"exact_1to1"})
    manifest=next(e["detail"] for e in events if e["kind"]=="manifest" and e["detail"].get("request_id")==rid)
    execution=next(e["detail"] for e in events if e["kind"]=="role.execution" and e["detail"].get("request_id")==rid)
    assert manifest["digest"]==view["manifest_sha"]
    assert manifest["files"]==["binding.json","case_runner.py","contract.json",
                              "domain.json","measure.py","observer.so"]
    assert execution["backend"]=="namespace" and execution["effective_uid"]!=0
    assert execution["network"]=="isolated_loopback_only"
    assert execution["mounts"]["input"]=="read_only" and execution["mounts"]["rootfs"]=="read_only"
    assert execution["rootfs_digest"] and execution["image_id"]
    assert not set(manifest["files"]) & {"prediction.json","spec.json","guard.json","query.ql"}
    assert receipt["rows"][1]["actual_reads"]==2
    assert receipt["verdict"]["normal_witnesses"]==[2]
    projected,_=observation_inputs(package,side,load(STATIC/"review-data.json"),
                                   load(OBS/"build-lock.json"))
    with tempfile.TemporaryDirectory(dir=OUT) as temp:
        source=Path(temp)/"source"
        source.mkdir()
        for name,raw in projected.items():
            (source/name).write_bytes(raw)
        attempt_view=Path(temp)/"role"
        scope=Scope(RUN,run["seed"],run["group_name"],str(run["repeat"]),
                    "verifier","verify",rid,str(attempts[0]["attempt_id"]),
                    db.snapshot(RUN)["watermark"])
        rebuilt=materialize(attempt_view,source,scope,_grants(projected,run["group_name"]))
        assert rebuilt==view["manifest_sha"]
        (OUT/f"production-{side}-input_manifest.json").write_bytes(
            (attempt_view/"input/input_manifest.json").read_bytes())
    obj=(db.root/"published-objects"/intent["digest"]).read_bytes()
    assert digest(obj)==intent["digest"] and obj==encode(receipt)
    dest=OUT/"production-published-objects"
    dest.mkdir(exist_ok=True)
    (dest/intent["digest"]).write_bytes(obj)
    (OUT/f"production-{side}-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    (OUT/f"production-{side}-execution.json").write_text(json.dumps(execution,indent=2,sort_keys=True)+"\n")
    summary["sides"][side]={
        "request_id":rid,"attempt_id":1,"receipt_sha256":digest(encode(receipt)),
        "manifest_sha256":view["manifest_sha"],"image_id":execution["image_id"],
        "rootfs_digest":execution["rootfs_digest"],"label":label,
        "normal_actual_reads":receipt["rows"][1]["actual_reads"],
        "violations":receipt["verdict"]["violations"],
        "mode4_traversal_truncated":receipt["rows"][3]["attribute_traversal_truncated"]}
assert summary["sides"]["before"]["violations"]==[1,4]
assert summary["sides"]["after"]["violations"]==[]
assert summary["sides"]["after"]["mode4_traversal_truncated"] is True
assert summary["sides"]["before"]["mode4_traversal_truncated"] is None
(OUT/"audit.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
(OUT/"event-chain.json").write_text(json.dumps([e for e in events if e["commit_seq"]>=42],
                                                 indent=2,sort_keys=True)+"\n")
with closing(sqlite3.connect(db.path)) as source:
    with closing(sqlite3.connect(OUT/"production-after.sqlite3")) as target:
        source.backup(target)
print(json.dumps({k:summary[k] for k in ("run_id","state","denominator","sides")},sort_keys=True))
