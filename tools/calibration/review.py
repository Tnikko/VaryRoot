"""Export the committed Step 06 regression evidence for independent review."""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from varyroot.agent_b import projection
from varyroot.b_batch import read_object, registration
from varyroot.calibration_decision import write_bundle
from varyroot.case_pool import build_pool
from varyroot.ledger import Ledger, pool_hash
from varyroot.publication import Publication, digest, encode


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(value))


def report(source, out):
    summary = {}
    for ledger in sorted(source.glob("*/ledger.sqlite3")):
        db = Ledger(ledger.parent)
        pub = Publication(db)
        with db.tx() as c:
            groups = [r[0] for r in c.execute("select distinct run_id from registrations order by run_id")]
        for run in groups:
            folder = out / "raw" / run
            events = db.events(run)
            dump(folder / "events.json", events)
            row = db.run(run)
            stats = summary[run] = dict(state=row["state"], balance=db.balances(run)["B.verify"])
            registrations = [e["detail"]["batch"] for e in events if e["kind"] == "prediction"]
            for batch in registrations:
                reg, data = registration(db, run, batch)
                dump(folder / batch / "pre-registration.json", dict(row=reg, payload=data))
                if batch == "b1" and row["state"] in ("spec_ready", "unresolved") and run.startswith(("pair.", "oob.", "stopped.")):
                    regenerated = build_pool(db,run,data["policy"]["verifier"])
                    rows = [projection(c,data["policy"]["verifier"]) for c in regenerated["cases"]]
                    predictions = {c["case_id"]:c["predictions"] for c in regenerated["cases"]}
                    if rows != data["rows"] or predictions != data["matrix"]:
                        raise ValueError("regenerated pool or predictions differ: " + run)
                    stats.update(pool=len(rows),regenerated_digest=pool_hash(rows), frozen_digest=reg["pool_digest"])
            for event in events:
                detail = event["detail"]
                if event["kind"] == "selected" and detail["detail"].get("selector_audit"):
                    sel = read_object(db,detail["detail"]["selector_audit"])
                    dump(folder / detail["batch"] / "selection.json",sel)
                    stats["selected"] = len(sel["selected"])
                    # Preserve the isolated selector's exact visible bytes for offline inspection.
                    attempt = Path(sel["audit"]["attempt_dir"])
                    dest = folder / detail["batch"] / "selector-view"
                    dest.mkdir(parents=True, exist_ok=True)
                    for name in sel["audit"]["input_files"]:
                        raw = (attempt / "input" / name).read_bytes()
                        expected = (sel["audit"]["manifest_sha256"] if name == "input_manifest.json"
                                    else sel["audit"]["input_sha256"][name])
                        if digest(raw) != expected:
                            raise ValueError("selector input digest mismatch: " + name)
                        (dest / name).write_bytes(raw)
                    output = (attempt / "output" / "selection.json").read_bytes()
                    if digest(output) != sel["audit"]["selection_sha256"]:
                        raise ValueError("selector output digest mismatch")
                    (dest/"observed-selection.json").write_bytes(output)
                if event["kind"] == "B6.routed":
                    result = read_object(db,detail["report_sha"])
                    dump(folder / ("route-%s.json" % event["commit_seq"]),result)
                if event["kind"] in ("spec_ready","unresolved"):
                    result = read_object(db,detail["detail"]["handoff_sha"])
                    dump(folder / "b6.json",{k:v for k,v in result.items() if k not in ("records","manifest")})
                    manifest = write_bundle(result,out/"handoffs"/run)
                    validation = subprocess.run([sys.executable, "-m", "varyroot", "validate", str(manifest)],
                                                check=True, capture_output=True, text=True)
                    dump(folder / "step01-validation.json", json.loads(validation.stdout))
                    stats.update(action=result["action"], anchors=sum(p["stage"]=="A4" for p in result["positions"]),
                                 determinate=sum(p["stage"]=="B" for p in result["positions"]),
                                 excluded=[p["reason"] for p in result["excluded"]],
                                 changed=len(result["changed_judgments"]), preserved=len(result["preserved_judgments"]))
            snapshot = db.snapshot(run)
            receipts = [{**m, "publication":pub.read(m["request_id"])} for m in snapshot["members"]]
            with db.tx() as c:
                charges = [dict(r) for r in c.execute("select * from charges where run_id=? order by request_id",(run,))]
            dump(folder / "reveals.json",dict(snapshot=snapshot,receipts=receipts,charges=charges))
        for prefix in ("pair","oob"):
            arms = [prefix+"."+group for group in ("random","divergence")]
            if not set(arms) <= set(groups):
                continue
            selections = [next(e["commit_seq"] for e in db.events(r) if e["kind"]=="selected") for r in arms]
            snaps = [db.snapshot(r) for r in arms]
            maps = [{m["intent"]["case"]:m for m in s["members"]} for s in snaps]
            shared = sorted(set(maps[0]) & set(maps[1]))
            if not shared or max(m["seq"] for m in maps[0].values()) >= selections[1]:
                raise ValueError("missing staged independent reveal")
            common = [{r:members[case] for r,members in zip(arms,maps)} for case in shared]
            if any(p[arms[0]]["request_id"]==p[arms[1]]["request_id"] for p in common):
                raise ValueError("shared logical request across arms")
            dump(out/"raw"/(prefix+"-overlap.json"),dict(arms=arms,selection_seq=selections,common=common))
    shutil.copyfile(source/"selector-audit.json",out/"role-isolation.json")
    dump(out/"summary.json",summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--prior-trace", type=Path)
    args=parser.parse_args()
    print(json.dumps(report(args.trace,args.output),indent=2))
    if args.prior_trace:
        differences = {}
        for path in sorted(args.trace.glob("*/ledger.sqlite3")):
            prior = args.prior_trace / path.parent.name / path.name
            if not prior.exists():
                continue
            left, right = Ledger(prior.parent), Ledger(path.parent)
            with right.tx() as c:
                arms = [r[0] for r in c.execute("select distinct run_id from selections")]
            for arm in arms:
                paired = []
                for db in (left,right):
                    event = next(e for e in db.events(arm) if e["kind"] == "selected")
                    selector = read_object(db,event["detail"]["detail"]["selector_audit"])
                    reg, data = registration(db,arm,event["detail"]["batch"])
                    paired.append(dict(pool=reg["pool_digest"], matrix=digest(encode(data["matrix"])),
                        regenerated_seed=data["policy"]["rng_seed"], inputs=selector["audit"]["input_sha256"],
                        selection_sha=selector["audit"]["selection_sha256"]))
                if paired[0] != paired[1]:
                    raise ValueError("paired replays differ: " + arm)
                differences[arm]=dict(first=paired[0],repeat=paired[1])
        if not differences:
            raise ValueError("no shared runs in independent replays")
        dump(args.output/"repeated-runs.json",differences)
