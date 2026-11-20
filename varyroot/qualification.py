"""A4 and A6 for the registered finite-domain adapters."""
import argparse
import json
from pathlib import Path
from .agent_a import PREFIX,ENUM
from .inference import evaluate
from .ledger import Ledger,LedgerError
from .publication import Publication,encode,digest
from .verifier_view import project
from .verify_request import execute_request,image_id,input_hash,reserve

SIDES=("before","after")
LABEL={"before":"positive","after":"negative"}


def artifact(p,name):
    return p["artifacts"][p["roles"][name]]["value"]


def prepared(p,side):
    sources=artifact(p,side+"_sources")
    link=artifact(p,side+"_mapping")
    target, skeleton=[v["target"] for v in sources["views"]]
    if (link["status"]!="exact_1to1" or link["approval"]!="accepted_for_scope"
            or link["original"]!=target["target_ref"] or link["skeleton"]!=skeleton["target_ref"]
            or link["original_span"]!=target["byte_span"] or link["skeleton_span"]!=skeleton["byte_span"]):
        raise ValueError("mapping_unqualified")
    source_text=[]
    for t,snap,snap_ref in zip((target,skeleton),sources["snapshots"],link["snapshots"],strict=True):
        raw=snap["files"][t["file"]].encode()
        if (t["file_digest"]!=digest(raw) or snap_ref!=t["snapshot_ref"]
                or snap_ref!=f'{snap["id"]}@{snap["version"]}'):
            raise ValueError("snapshot_mismatch")
        source_text.append(raw)
    original,reduced=source_text
    transform=link.get("transform","identity")
    expected=original
    if transform=="drop_unused_enum":
        if original.count(ENUM)!=1 or original.count(b"sample_revision")!=1 or original.index(ENUM)>=target["byte_span"][0]:
            raise ValueError("unapproved deletion")
        expected=expected.replace(ENUM,b"",1)
    if transform in ("drop_unused_enum","comment_prefix"):
        expected=PREFIX+expected
    elif transform!="identity":
        raise ValueError("unregistered transform")
    shift=len(expected)-len(original)
    if (reduced!=expected or skeleton["object_name"]!=target["object_name"]
            or skeleton["operation"]!=target["operation"] or skeleton["byte_span"]!=[n+shift for n in target["byte_span"]]):
        raise ValueError("skeleton_transform_mismatch")
    contracts=artifact(p,"contracts")
    for a in contracts["assumptions"]:
        if a["status"]!="approved":
            raise ValueError(a["reason"])
    contract,=contracts["contracts"].values()
    authority,=contract["basis_refs"]
    policy=contracts["support"][authority]["description"]["contract"]
    if (contract["approval_status"]!="approved" or policy["approval"]!="approved" or
            policy["subject"]!=target["object_name"] or contract["subject"]!=policy["subject"]):
        raise ValueError("contract_unqualified")
    policies={"p":("npd05/contract.json","pointer_modes@1",["present","absent"]),
              "data":("agent_a/capacity-contract.json","singleton@1",["fixed_input"])}
    file,domain_id,expected_paths=policies[target["object_name"]]
    authority_bytes=(Path(__file__).resolve().parents[1]/"tests/fixtures"/file).read_bytes()
    if (contracts["support"][authority]["description"]["grant_sha256"]!=digest(authority_bytes)
            or json.loads(authority_bytes)!=policy):
        raise ValueError("authority_unregistered")
    (domref,dom),=artifact(p,"domain").items()
    paths=dom["paths"]
    if (dom["coverage"]!="exhaustive" or paths!=expected_paths or domref!=domain_id
            or domref!=f'{dom["id"]}@{dom["version"]}'):
        raise ValueError("domain_unqualified")
    ids=list(range(len(paths)))
    files=project(source_text[0],target,policy,dict(id=domref,inputs=ids))
    return files,target,contract,dom


def _attach(db,run,version,side,rid):
    pub=Publication(db)
    receipt=pub.read(rid)
    sha=digest(encode(receipt))
    with db.tx() as c:
        p=db._seed_package(c,run)
        if p["version"]!=version or db._run(c,run)["state"]!="seed_pending":
            raise LedgerError("stale seed receipt")
        files,*_=prepared(p,side)
        req=c.execute("""SELECT q.*,p.digest,v.manifest_sha,p.attempt_id FROM requests q JOIN publication_intents p USING(request_id)
                        JOIN verifier_attempt_views v ON v.request_id=q.request_id AND v.attempt_id=p.attempt_id
                        WHERE q.request_id=? AND q.run_id=? AND q.state='ready' AND p.state='ready'""",
                      (rid,run)).fetchone()
        if (not req or req["account"]!="A.bootstrap" or req["digest"]!=sha or req["manifest_sha"]!=receipt["manifest_sha"]
                or receipt["request_id"]!=rid or receipt["attempt_id"]!=req["attempt_id"]):
            raise LedgerError("unqualified publication")
        intent=json.loads(req["intent"])
        if (intent["side"]!=side or intent["version"]!=version or intent["basis"]!=p["role_refs"][side+"_basis"]
                or req["input_sha"]!=input_hash(files,intent["image"])
                or receipt["inputs"]!={k:digest(v) for k,v in files.items()}):
            raise LedgerError("receipt binding mismatch")
        if receipt["completion"]!="completed" or receipt["verdict"]["label"]!=LABEL[side]:
            return False
        name=side+"_ok"
        c.execute("INSERT OR REPLACE INTO seed_verified VALUES(?,?,?,?,?)",
                  (run,name,db._seed_checks(p)[name],rid,sha))
        return True


def attach(db,run,version,side,rid):
    try:
        return _attach(db,run,version,side,rid)
    except LedgerError as error:
        with db.tx() as c:
            db.event(c,run,"A4.receipt_rejected",dict(version=version,current=db._seed_package(c,run)["version"],
                                                     side=side,request_id=rid,reason=str(error)))
        raise


def compatible_proof(db,c,run,p,side,image,files):
    name=side+"_ok"
    row=c.execute("""SELECT q.input_sha,q.state FROM seed_verified v JOIN requests q USING(request_id)
                    WHERE v.run_id=? AND v.name=? AND v.bindings_sha=?""",
                  (run,name,db._seed_checks(p)[name])).fetchone()
    return row is not None and row["state"] in ("ready","delivered") and row["input_sha"]==input_hash(files,image)


def predictions(p):
    def replay(model):
        spec=dict(model["spec"],clauses=model["clauses"])
        results={}
        for side in SIDES:
            _,target,contract,domain=prepared(p,side)
            t=dict(id=target["target_ref"],version=1,subject=target["object_name"])
            results[side]=evaluate(spec,t,contract,domain,artifact(p,side+"_facts"))
        outcomes=[results[s]["outcome"] for s in SIDES]
        status=("matched" if outcomes==["report","quiet"] else
                "contradicted" if outcomes[0]=="quiet" or outcomes[1]=="report" else "insufficient")
        return dict(spec=spec["id"]+"@"+str(spec["version"]),status=status,outcomes=outcomes,derivation=results)
    return replay(artifact(p,"baseline_spec")),replay(artifact(p,"active_model")),[replay(m) for m in artifact(p,"hypothesis_set")["specs"]]


def finish(db,run,version,image):
    with db.tx() as c:
        current=db._run(c,run)
        p=db._seed_package(c,run)
        if p["version"]!=version or current["state"]!="seed_pending":
            raise LedgerError("stale A4/A6 decision")
        gate=db._seed_gate(c,current,p)
        if not all(compatible_proof(db,c,run,p,s,image,prepared(p,s)[0]) for s in SIDES):
            reason="missing_qualified_side"
            db.event(c,run,"A4.blocked",dict(version=version,reason=reason,gate=gate))
            return dict(state="seed_pending",reason=reason,gate=gate)
        baseline,working,candidates=predictions(p)
        survivors=[r["spec"] for r in candidates if r["status"]=="matched"]
        decision=dict(version=version,baseline=baseline,working=working,candidates=candidates,survivors=survivors,
                      side_receipts=gate["evidence"])
        seq=db.event(c,run,"A6.replayed",decision)
        if baseline["status"]!="matched" or working["status"]!="matched" or not any(r!=working["spec"] for r in survivors):
            db._advance(c,current,"remodel",dict(responsible="A5",decision=seq))
            return dict(state="remodel",route="A5",decision=seq,survivors=survivors)
        for name in ("mapping_ok","contracts_ok","candidates_ok","versions_ok"):
            c.execute("INSERT OR REPLACE INTO seed_verified VALUES(?,?,?,NULL,?)",
                      (run,name,db._seed_checks(p)[name],"decision:"+str(seq)))
        gate=db._seed_gate(c,current,p)
        if gate["blockers"]:
            raise LedgerError("unclosed seed gate")
        db._advance(c,current,"seed_accepted",dict(gate=gate,decision=seq,survivors=survivors))
        return dict(state="seed_accepted",decision=seq,survivors=survivors,gate=gate)


def qualify(db,run):
    p=db.seed_package(run)
    version=p["version"]
    if db.run(run)["state"]!="seed_pending":
        return {"state":db.run(run)["state"],"version":version}
    try:
        files={side:prepared(p,side)[0] for side in SIDES}
    except (ValueError,KeyError,TypeError) as e:
        with db.tx() as c:
            if db._seed_package(c,run)["version"]!=version or db._run(c,run)["state"]!="seed_pending":
                raise LedgerError("stale A4 projection")
            missing=[]
            for side in SIDES:
                for fact in artifact(p,side+"_facts"):
                    if fact["approval_status"]!="approved":
                        missing.append(dict(fact_ref=f'{fact["id"]}@{fact["version"]}',target_ref=fact["target_ref"],
                                            reason=fact["typed_operands"].get("missing",str(e))))
            detail=dict(version=version,reason=str(e),missing_facts=missing)
            db.event(c,run,"A4.blocked",detail)
        return dict(state="seed_pending",**detail)
    image=image_id()
    for side in SIDES:
        with db.tx() as c:
            if compatible_proof(db,c,run,p,side,image,files[side]):
                continue
        rid=reserve(db,run,p,side,files[side],image)
        status,output=execute_request(db,run,rid,files[side],image)
        if output is None:
            return dict(state="seed_pending",request_id=rid,execution=status)
        attach(db,run,version,side,rid)
    return finish(db,run,version,image)

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace")
    parser.add_argument("run")
    args=parser.parse_args()
    print(json.dumps(qualify(Ledger(args.workspace),args.run),sort_keys=True))
