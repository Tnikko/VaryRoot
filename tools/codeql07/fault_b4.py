"""Registered NPD regression for C5 → B4 with an intentionally incorrect upstream keep.

Run in the same offline image and tool tree as the original pair.divergence build.
Clone the source SQLite snapshot and leave the original B6 ledger untouched.
"""
import argparse
import json
import shutil
import sqlite3
from pathlib import Path

from tools.codeql07.replay import unpack_database
from tools.codeql07.runner import Engine, file_sha, save
from varyroot.agent_c import compile_manifest, emit_queries, regression, verify_outputs
from varyroot.b_batch import read_object, save_object
from varyroot.c_ledger import budget_snapshot, finish_regression, start_regression
from varyroot.freeze_archive import build_archive
from varyroot.ledger import Ledger
from varyroot.publication import digest, encode


def exercise(source_store, original, tools, out):
    out = out.resolve()
    run = "pair.divergence"
    out.mkdir(parents=True)
    store = out / "ledger"
    store.mkdir()
    original_db = sqlite3.connect((source_store / "ledger.sqlite3").resolve().as_uri()+"?mode=ro",uri=True)
    clone = sqlite3.connect(store/"ledger.sqlite3")
    try:
        original_db.backup(clone)
    finally:
        original_db.close()
        clone.close()
    db = Ledger(store)
    ready = db.run(run)
    if ready["state"] != "spec_ready":
        raise ValueError("expected original B6 spec_ready snapshot")
    handoff_sha = next(e["detail"]["detail"]["handoff_sha"] for e in reversed(db.events(run))
                       if e["kind"]=="spec_ready")
    (store/"b-objects").mkdir()
    shutil.copyfile(source_store/"b-objects"/handoff_sha,store/"b-objects"/handoff_sha)
    b6 = read_object(db,handoff_sha)
    for key in ("manifest","records"):
        if b6[key] != json.loads((original/"handoff"/(key+".json")).read_bytes()):
            raise ValueError("registered database scenario and B6 source differ")
    if (b6["action"],b6["initial_spec_ref"],b6["final_spec_ref"]) != ("revise","check_seen@1","nonnull_or_exit@1"):
        raise ValueError("requires registered NPD revision")
    b6.update(action="keep", final_spec_ref=b6["initial_spec_ref"],revision_ref=None,
              reason="fault_injection_for_step07_B4")
    b6["manifest"]["spec_ref"] = b6["initial_spec_ref"]
    b6["records"] = [r for r in b6["records"] if r["kind"] != "Revision"]
    for r in b6["records"]:
        if r["kind"] == "Decision":
            r.update(action="keep",reason=b6["reason"])
        if r["kind"] == "Handoff":
            r.update(final_spec_ref=b6["initial_spec_ref"],revision_ref=None)
    introduced = save_object(db,b6)
    with db.tx() as c:
        ready = db._advance(c,ready,"spec_ready",dict(handoff_sha=introduced, fault_injection=True,
              original_b6_sha=handoff_sha,action="keep",baseline=b6["initial_spec_ref"],
              final=b6["final_spec_ref"],revision_ref=None,snapshot=b6["snapshot"]))
    staged = out/"inputs"
    for key in ("manifest","records"):
        save(staged/"handoff"/(key+".json"),b6[key])
    save(staged/"handoff/b6.json",b6)
    c1 = compile_manifest(staged/"handoff")
    lock = json.loads((original/"toolchain.json").read_bytes())
    if file_sha(original/"database.zip") != lock["database_sha256"]:
        raise ValueError("database archive mismatch")
    save(staged/"c1.json",c1)
    save(staged/"toolchain.json",lock)
    shutil.copyfile(original/"database.zip",staged/"database.zip")
    build = start_regression(db,run,ready["version"],c1,toolchain=lock)
    (staged/"queries").mkdir()
    for name,raw in emit_queries(c1).items():
        (staged/"queries"/name).write_bytes(raw)
    database = unpack_database(staged/"database.zip",out/"restored-db")
    engine = Engine(tools,out/"engine")
    engine.execute(staged,database,lock)
    c4 = verify_outputs(staged,c1)
    report = regression(c1,c4)
    if not all(r["fidelity"] and r["score"] is not None for lane in report["lanes"].values()
               for r in lane["rows"]):
        raise ValueError("incomplete, ambiguous or unfaithful real query observation")
    if not any(r["route"]=="B4" and r["spec_prediction"]=="quiet" and r["score"]=="FN"
               for r in report["lanes"]["Qstar"]["rows"]):
        raise ValueError("expected measured positive without an alert at the erroneous keep")
    save(staged/"c4.json",c4)
    save(staged/"c5.json",report)
    save(staged/"budget.json",budget_snapshot(db,run))
    shutil.copyfile(out/"engine/commands.json",staged/"build-log.json")
    archive = out/"archive"
    build_archive(archive,{p.relative_to(staged).as_posix():p for p in staged.rglob("*") if p.is_file()})
    receipt = finish_regression(db,run,build["version"],db.events(run)[-1]["commit_seq"],archive)
    if receipt["state"] != "adjudicating" or receipt["route"] != "B4" or "freeze_id" in receipt:
        raise ValueError("faulty upstream keep did not return to B4")
    save(out/"proof.json",dict(fault="unjustified_keep",original_b6_sha=handoff_sha,injected_b6_sha=introduced,
                              source_run=run,database_sha256=lock["database_sha256"],original_decision="revise",
                              observed_targets={p["target_ref"]:p["receipt_sha"] for p in b6["positions"]},
                              c4_sha256=digest(encode(c4)),receipt=receipt))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source_store","original","toolchain","output"):
        p.add_argument(name,type=Path)
    a = p.parse_args()
    exercise(a.source_store,a.original,a.toolchain,a.output)
