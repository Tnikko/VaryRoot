"""Authenticate the failed build used to authorize a paid shared-query repair."""
import json
from pathlib import Path
import tempfile

from tools.codeql07.replay import csv_rows
from tools.codeql07.runner import file_sha, save
from .agent_c import LANES, regression, require, verify_outputs
from .freeze_archive import MANIFEST, build_archive, verify_archive
from .publication import digest, encode


# SHA-256 of the canonical file/digest map for the original c07-oob1 run.
# Includes the exact two queries, shared source, per-lane BQRS and status,
# CSVs, eight-command engine log, handoff, database bundle, C1 and tool lock.
# Only this historical run predates the multiplicity column.
BOOTSTRAP_INVENTORY = "a5b80a07b2afb436ba40bf21d1ed7551ddd374157735f2360fa394f8b3cd8dc8"


def _inputs(prior):
    names = ["c1.json", "toolchain.json", "database.zip", "handoff/manifest.json",
             "handoff/records.json", "queries/shared.qll", "queries/qlpack.yml"]
    for lane in LANES:
        names.append(f"queries/{lane}.ql")
        names.extend(f"results/{lane}.{suffix}" for suffix in ("bqrs", "csv", "status.json"))
    paths = {name: prior / name for name in names}
    log = prior / "build-log.json"
    paths["build-log.json"] = log if log.is_file() else prior.parent / "build" / "commands.json"
    return paths


def _authorized(db, run, prior, files):
    inventory = digest(encode(files))
    if inventory == BOOTSTRAP_INVENTORY:
        return True
    require((prior / MANIFEST).is_file(), "unregistered repair parent")
    archive_sha = file_sha(prior / MANIFEST)
    require(any(e["kind"] == "C5.repair_required" and e["detail"]["archive_sha"] == archive_sha
                for e in db.events(run)), "repair parent was not committed for this run")
    committed = verify_archive(prior, archive_sha)
    require(all(committed.get(name) == sha for name, sha in files.items()),
            "repair evidence differs from committed parent")
    return False


def _record(db, run, version, evidence):
    with db.tx() as conn:
        db._current(conn, run, version, ["regressing"])
        start = conn.execute("SELECT detail FROM events WHERE kind='regressing' AND run_id=? "
                             "ORDER BY commit_seq DESC LIMIT 1", (run,)).fetchone()
        require(start is not None, "missing C1 registration")
        registered = json.loads(start[0])["detail"]
        require(all(registered[k] == evidence[k] for k in ("c1_sha", "toolchain_sha")),
                "repair differs from registered C1 or toolchain")
        key = f"C.repair_parent/{version}/{evidence['archive_sha']}"
        args_sha, prior = db._retry(conn, run, key, evidence)
        if prior is None:
            seq = db.event(conn, run, "C5.repair_parent", evidence)
            conn.execute("INSERT INTO commands VALUES(?,?,?,?)", (run, key, args_sha, str(seq)))


def validate_parent(db, run, state, prior, c1, lock, engine, destination):
    """Record a verified failed parent. Its diagnosis can authorize repairs only."""
    require(not db.fixture_gates, "repair parent requires a production ledger")
    prior, destination = Path(prior), Path(destination)
    inputs = _inputs(prior)
    with tempfile.TemporaryDirectory(dir=engine.work, prefix="repair-parent-") as tmp:
        tmp = Path(tmp)
        stage = tmp / "parent"
        sources_sha = build_archive(stage, inputs)
        files = verify_archive(stage, sources_sha)
        historical = _authorized(db, run, prior, files)
        require(json.loads((stage / "c1.json").read_bytes()) == c1
                and json.loads((stage / "toolchain.json").read_bytes()) == lock,
                "repair parent C1 or toolchain differs")
        require(files["database.zip"] == lock["database_sha256"] == file_sha(destination / "database.zip"),
                "repair parent database differs from current build")
        for lane in LANES:
            output = tmp / f"{lane}.csv"
            engine.command("bqrs", "decode", "--format=csv", "--output=" + str(output),
                           stage / "results" / f"{lane}.bqrs")
            require(csv_rows(output) == csv_rows(stage / "results" / f"{lane}.csv"),
                    f"{lane} repair parent BQRS differs from recorded CSV")
        c4 = verify_outputs(stage, c1, historical_counts=historical)
        failed = regression(c1, c4)
        require(failed["route"] == "repair", "repair requires a measured implementation mismatch")
        save(tmp / "parent-c4.json", c4)
        save(tmp / "parent-c5.json", failed)
        artifacts = {name: stage / name for name in files}
        for name in ("parent-c4.json", "parent-c5.json"):
            artifacts[name] = tmp / name
        repair = destination / "repair"
        archive_sha = build_archive(repair, artifacts)
        # Persist a content-addressed copy before committing its immutable event.
        sealed = db.root / "c-repair-parents" / archive_sha
        require(build_archive(sealed, artifacts) == archive_sha, "parent changed while sealing")
        parent, diagnostic = files["queries/shared.qll"], digest(encode(failed))
        evidence = dict(parent_sha=parent, diagnostic_sha=diagnostic, archive_sha=archive_sha,
                        c1_sha=digest(encode(c1)), toolchain_sha=digest(encode(lock)),
                        database_sha=files["database.zip"], historical_counts=historical,
                        failed_lanes=[lane for lane in LANES if not failed["lanes"][lane]["passed"]])
        _record(db, run, state["version"], evidence)
        return parent, diagnostic
