"""Consume a production B6 run and commit the paired CodeQL regression."""
import argparse
import fcntl
from io import BytesIO
import json
import tempfile
import zipfile
from pathlib import Path
import shutil

from .agent_c import LANES, compile_manifest, emit_queries, regression, require, verify_outputs
from .b_batch import read_object
from .c_ledger import budget_snapshot, finish_regression, frozen_receipt, start_regression, reserve_shared_repair
from .calibration_decision import write_bundle
from .freeze_archive import build_archive, verify_archive
from .ledger import Ledger
from .publication import Publication, digest, encode
from tools.codeql07.replay import replay_files, unpack_database
from tools.codeql07.runner import Engine, file_sha, save, tree_sha


def load(path):
    return json.loads(path.read_bytes())


def finish_repairs(db, requests, receipt):
    publisher=Publication(db)
    for request in requests:
        attempt=publisher.recover(request)
        if attempt["action"] in ("ready","delivered"):
            continue
        require(attempt["action"] in ("dispatch","rerun") and publisher.claim(attempt),"repair publication busy")
        publisher.submit(attempt,receipt)
        require(publisher.recover(request)["action"]=="ready","repair receipt publication failed")


def verify_database(root,c1,lock):
    path=root/"database.zip"
    require(file_sha(path)==lock["database_sha256"],"stale database")
    with zipfile.ZipFile(path) as archive:
        nested,=[i for i in archive.namelist() if i.endswith("/src.zip")]
        with zipfile.ZipFile(BytesIO(archive.read(nested))) as sources:
            members=[m for m in sources.namelist() if m.endswith(".c")]
            require(len(members)==len({Path(m).name for m in members}),"duplicate database source identity")
            actual={Path(m).name:digest(sources.read(m)) for m in members}
    expected={t["file_digest"]+".c":t["file_digest"] for t in c1["targets"]}
    require(actual==expected,"database source archive does not match snapshots")
    return actual


def submit(db,run,work,tools,image,*,profile="registered",reuse=None,repair_from=None):
    work=Path(work).resolve()
    work.mkdir(parents=True,exist_ok=True)
    with (work/".submit.lock").open("a+b") as mutex:
        fcntl.flock(mutex,fcntl.LOCK_EX)
        identity=dict(run=run,ledger=str(db.root.resolve()),profile=profile,image=image)
        from .publication import put
        put(work/"request.json",encode(identity))
        return _submit(db,run,work,tools,image,profile=profile,reuse=reuse,repair_from=repair_from)


def _submit(db,run,work,tools,image,*,profile,reuse,repair_from):
    work=Path(work).resolve()
    work.mkdir(exist_ok=True,parents=True)
    state=db.run(run)
    if state["state"]=="unresolved":
        saved=dict(state="unresolved",reason="B6 stopped before C",budget=budget_snapshot(db,run))
        save(work/"receipt.json",saved)
        return saved
    if state["state"] in ("frozen","partial"):
        decision=next(e["detail"]["detail"] for e in reversed(db.events(run)) if e["kind"]==state["state"])
        verify_archive(decision["archive_dir"],decision["archive_sha"])
        if state["state"]=="frozen":
            decision=frozen_receipt(db,run)
        saved=dict(decision,state=state["state"])
        save(work/"receipt.json",saved)
        save(work/"events.json",db.events(run))
        return saved
    require(state["state"] in ("spec_ready","regressing"),"run is not eligible for C")
    ready=next(e for e in reversed(db.events(run)) if e["kind"]=="spec_ready")
    b6=read_object(db,ready["detail"]["detail"]["handoff_sha"])
    root=work/"artifacts"
    root.mkdir(exist_ok=True)
    write_bundle(b6,root/"handoff")
    save(root/"handoff/b6.json",b6)
    c1=compile_manifest(root/"handoff",profile)
    save(root/"c1.json",c1)
    intent=work/"finish-intent.json"
    if intent.exists():
        previous=load(intent)
        result=finish_regression(db,run,previous["version"],previous["head"],work/"candidate")
        save(work/"receipt.json",result)
        save(work/"events.json",db.events(run))
        return result
    engine=Engine(tools,(work/"engine") if not (work/"engine").exists() else tempfile.mkdtemp(prefix="resume-",dir=work))
    if state["state"]=="regressing":
        lock=load(root/"toolchain.json")
        start=next(e for e in reversed(db.events(run)) if e["kind"]=="regressing")["detail"]["detail"]
        require(start["toolchain_sha"]==digest(encode(lock)) and lock["tool_tree_sha256"]==tree_sha(engine.tools),
                "cannot resume a different toolchain")
        verify_database(root,c1,lock)
        dbdir=unpack_database(root/"database.zip",engine.work/"restored")
    elif reuse:
        prior=Path(reuse).resolve()
        lock=load(prior/"toolchain.json")
        require(lock["runtime_image"]==image and tree_sha(engine.tools)==lock["tool_tree_sha256"],"stale tool lock")
        require(file_sha(prior/"database.zip")==lock["database_sha256"],"database digest differs")
        required={t["file_digest"]+".c" for t in c1["targets"]}
        require(required=={s for s in lock["sources"] if s.endswith(".c")},"database source set differs")
        shutil.copyfile(prior/"database.zip",root/"database.zip")
        dbdir=unpack_database(root/"database.zip",engine.work/"restored")
    else:
        lock=engine.extract(root/"handoff",root,c1,image)
        dbdir=engine.work/"db"
    save(root/"database-sources.json",verify_database(root,c1,lock))
    if not (root/"database-build-log.json").exists():
        if reuse:
            base=Path(reuse)
            provenance=next((f for f in [base/"database-build-log.json",base.parent/"build/commands.json",base.parent/"engine/commands.json"]
                             if f.is_file()),None)
            require(provenance is not None,"missing source database build log")
            commands=load(provenance)
        else:
            commands=engine.commands
        save(root/"database-build-log.json",[c for c in commands if c["argv"][1:3] in
                    (["database","create"],["database","bundle"],["version","--format=json"],["resolve","qlpacks"])])
    save(root/"toolchain.json",lock)
    if state["state"]=="spec_ready":
        state=start_regression(db,run,state["version"],c1,toolchain=lock)
    requests=[]
    if repair_from:
        prior=Path(repair_from)
        require(load(prior/"c1.json")==c1 and load(prior/"toolchain.json")==lock,"repair parent differs")
        from .repair_parent import validate_parent
        parent,diag=validate_parent(db,run,state,prior,c1,lock,engine,root)
        requests=reserve_shared_repair(db,run,state["version"],parent,diag,1)
    querydir=root/"queries"
    querydir.mkdir(exist_ok=True)
    queries=emit_queries(c1)
    for name,raw in queries.items():
        (querydir/name).write_bytes(raw)
    if requests:
        finish_repairs(db,requests,dict(shared_sha=digest(queries["shared.qll"]),parent_sha=parent,diagnostic=diag))
    engine.execute(root,dbdir,lock)
    c4=verify_outputs(root,c1)
    save(root/"c4.json",c4)
    save(root/"c5.json",regression(c1,c4))
    save(root/"budget.json",budget_snapshot(db,run))
    inputs={p.relative_to(root).as_posix():p for p in root.rglob("*") if p.is_file()}
    inputs["build-log.json"]=engine.work/"commands.json"
    inputs.update(replay_files(Path(__file__).resolve().parents[1]))
    dest=work/"candidate"
    build_archive(dest,inputs)
    head=db.events(run)[-1]["commit_seq"]
    save(intent,dict(version=state["version"],head=head))
    result=finish_regression(db,run,state["version"],head,dest)
    save(work/"receipt.json",result)
    save(work/"events.json",db.events(run))
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ("ledger","run","work","toolchain","image"):
        parser.add_argument(arg)
    parser.add_argument("--profile",choices=("registered","library-body"),default="registered")
    parser.add_argument("--reuse")
    parser.add_argument("--repair-from")
    args=parser.parse_args()
    result=submit(Ledger(args.ledger),args.run,args.work,args.toolchain,args.image,
                  profile=args.profile,reuse=args.reuse,repair_from=args.repair_from)
    print(json.dumps(result,ensure_ascii=False))
