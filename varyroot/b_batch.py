"""Immutable prediction batches and isolated verification for one experiment group."""
import json
from pathlib import Path

from .ledger import LedgerError, pool_hash
from .publication import Publication, digest, encode, put, read_file
from .qualification import qualify
from .verify_request import execute_request


def branch_seed(db, parent_run, run, group, budget):
    """Start a private group from the common accepted development seed."""
    origin = db.run(parent_run)
    if origin["state"] != "seed_accepted" or origin["group_name"] != "development":
        raise LedgerError("paired groups require an accepted common development seed")
    if group not in ("random", "divergence"):
        raise LedgerError("unknown selection policy")
    source = db.seed_package(parent_run)
    row = db.create_run(run, group, seed=origin["seed"], verify=budget)
    if row["state"] == "draft":
        packet = dict(source["packet"], run_ref=run, parent_seed_digest=source["packet_sha"])
        db.bind_seed(run, row["version"], packet, artifacts=source["artifacts"], roles=source["roles"])
    if db.seed_package(run, 1)["packet"].get("parent_seed_digest") != source["packet_sha"]:
        raise LedgerError("different development seed for this branch")
    if db.run(run)["state"] == "seed_pending":
        return qualify(db, run)
    return db.run(run)


def save_object(db, value):
    raw = encode(value)
    sha = digest(raw)
    folder = db.root / "b-objects"
    folder.mkdir(mode=0o700, exist_ok=True)
    put(folder / sha, raw)
    return sha


def read_object(db, sha):
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        raise LedgerError("invalid B artifact reference")
    raw = read_file(db.root / "b-objects" / sha)
    if digest(raw) != sha:
        raise LedgerError("B artifact digest mismatch")
    return json.loads(raw)


def register_batch(db, run, batch, rows, matrix, equivalent, policy, replay):
    pkg = db.seed_package(run)
    snapshot = db.snapshot(run)
    rows = sorted(rows, key=lambda row: (row["case"], row["target"]))
    if set(matrix) != {r["case"] for r in rows} or len(matrix) != len(rows):
        raise LedgerError("prediction coverage differs from pool")
    value = dict(batch=batch, package_version=pkg["version"], rows=rows, matrix=matrix,
                 equivalent=sorted(equivalent), policy=policy, replay=replay)
    sha = save_object(db, value)
    with db.tx() as conn:
        prior = conn.execute("SELECT payload_sha FROM registrations WHERE run_id=? AND batch=?",
                             (run, batch)).fetchone()
    if prior:
        if prior[0] != sha:
            raise LedgerError("frozen prediction or policy differs")
        return sha
    state = db.run(run)
    if state["state"] != "seed_accepted":
        raise LedgerError("new B batch requires a qualified seed version")
    source = "post_remodel" if pkg["branch"] in ("A2", "A5") else "initial_registration"
    db.register(run, state["version"], batch, pool_hash(rows), sha, snapshot["digest"],
                pool_cases=rows, source_kind=source)
    return sha


def registration(db, run, batch):
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM registrations WHERE run_id=? AND batch=?", (run, batch)).fetchone()
        if row is None:
            raise LedgerError("unknown prediction batch")
        return dict(row), read_object(db, row["payload_sha"])


def verify_selected(db, run, batch, files_by_case, image):
    pub = Publication(db)
    with db.tx() as conn:
        ids = conn.execute("SELECT request_ids FROM selections WHERE run_id=? AND batch=?",
                           (run, batch)).fetchone()
        if ids is None:
            raise LedgerError("selection must commit before verification")
        requests = [(rid, json.loads(conn.execute("SELECT intent FROM requests WHERE request_id=? AND run_id=?",
                                                  (rid, run)).fetchone()[0])) for rid in json.loads(ids[0])]
        delivered = conn.execute("SELECT result FROM deliveries WHERE run_id=? AND batch=?", (run, batch)).fetchone()
        if delivered:
            return json.loads(delivered[0])
    evidence = {}
    for rid, intent in requests:
        state, output = execute_request(db, run, rid, files_by_case[intent["case"]], image)
        if state["action"] in ("ready", "delivered"):
            evidence[rid] = digest(encode(output if output is not None else pub.read(rid)))
        elif state["action"] != "failed":
            return {"state": "waiting", "request_id": rid, "execution": state}
    return db.deliver(run, batch, evidence)
