"""Fenced local JSON-result publication on Linux. Only coordinators access the ledger."""
import hashlib
import json
import math
import os
import re
import secrets
import stat
import tempfile
import time
from pathlib import Path


LIMIT = 16 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}")


def encode(value):
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    sync_dir(path.parent)
    return path


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError("expected bounded regular file")
        data = f.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("oversize file")
        return data


def put(path, data):
    """Create a complete immutable name, never replacing existing bytes."""
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                if read_file(path) != data:
                    raise ValueError("immutable object mismatch")
            sync_dir(path.parent)
        finally:
            tmp.unlink(missing_ok=True)


def process_start(pid):
    try:
        # comm can contain spaces and parentheses.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] in {"Z", "X"} else fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def validate_json(raw):
    obj = json.loads(raw)
    if not isinstance(obj, dict) or encode(obj) != raw:
        raise ValueError("expected canonical JSON object")
    return obj


class Publication:
    def __init__(self, ledger, *, lease_seconds=30, max_attempts=3, checkpoint=None):
        if not math.isfinite(lease_seconds) or lease_seconds <= 0 or type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("invalid infrastructure policy")
        self.ledger = ledger
        self.lease_seconds = lease_seconds
        self.max_attempts = max_attempts
        self.checkpoint = checkpoint or (lambda phase: None)
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.staging = directory(ledger.root / "attempt-staging")
        self.sealed = directory(ledger.root / "coordinator-staging")
        self.objects = directory(ledger.root / "published-objects")
        with ledger.tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS execution_attempts (
                request_id TEXT NOT NULL REFERENCES requests, attempt_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL, state TEXT NOT NULL, owner TEXT, pid INTEGER, start TEXT,
                boot TEXT NOT NULL, deadline REAL NOT NULL, lease REAL NOT NULL, max_attempts INTEGER NOT NULL,
                PRIMARY KEY(request_id,attempt_id))""")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS current_attempt
                ON execution_attempts(request_id) WHERE state IN ('reserved','claimed','publishing')""")
            db.execute("""CREATE TABLE IF NOT EXISTS invalid_late_receipts (
                token TEXT NOT NULL REFERENCES execution_attempts(token), filename TEXT NOT NULL,
                PRIMARY KEY(token,filename))""")
            db.execute("""CREATE TABLE IF NOT EXISTS publication_intents (
                request_id TEXT PRIMARY KEY REFERENCES requests, attempt_id INTEGER NOT NULL,
                digest TEXT NOT NULL, size INTEGER NOT NULL, receipt_digest TEXT NOT NULL,
                schema TEXT NOT NULL, state TEXT NOT NULL)""")

    def _reserve(self, db, r, previous):
        number = previous["attempt_id"] + 1 if previous else 1
        limit = previous["max_attempts"] if previous else self.max_attempts
        lease = previous["lease"] if previous else self.lease_seconds
        if number > limit:
            return self._state(db, r, "failed")
        token = secrets.token_hex(32)
        directory(self.staging / token)
        db.execute("""INSERT INTO execution_attempts
            (request_id,attempt_id,token,state,boot,deadline,lease,max_attempts)
            VALUES (?,?,?,'reserved',?,?,?,?)""",
                   (r["request_id"], number, token, self.boot, time.monotonic()+lease, lease, limit))
        self._state(db, r, "running")
        return dict(action="dispatch", run_id=r["run_id"], request_id=r["request_id"], attempt_id=number,
                    token=token, input_sha=r["input_sha"])

    def _state(self, db, r, state):
        db.execute("UPDATE requests SET state=? WHERE request_id=?", (state, r["request_id"]))
        self.ledger.event(db, r["run_id"], "request."+state, {"request_id": r["request_id"]})
        return {"action": state}

    def claim(self, attempt, owner="worker"):
        pid = os.getpid()
        with self.ledger.tx() as db:
            now = time.monotonic()
            changed = db.execute("""UPDATE execution_attempts SET state='claimed',owner=?,pid=?,start=?,deadline=?+lease
                WHERE request_id=? AND attempt_id=? AND token=? AND state='reserved' AND boot=? AND deadline>?""",
                (owner,pid,process_start(pid),now,attempt["request_id"],attempt["attempt_id"],attempt["token"],self.boot,now))
            return changed.rowcount == 1

    def heartbeat(self, attempt):
        pid = os.getpid()
        with self.ledger.tx() as db:
            now = time.monotonic()
            changed = db.execute("""UPDATE execution_attempts SET deadline=?+lease WHERE request_id=?
                AND attempt_id=? AND token=? AND pid=? AND start=? AND boot=? AND state='claimed' AND deadline>?""",
                (now, attempt["request_id"],attempt["attempt_id"],attempt["token"],pid,process_start(pid),self.boot,now))
            return changed.rowcount == 1

    def fail_attempt(self, attempt, diagnostic, *, retryable):
        """Fence a worker failure; infrastructure retries retain the original charge."""
        with self.ledger.tx() as db:
            a = db.execute("""SELECT * FROM execution_attempts WHERE request_id=? AND attempt_id=?
                AND token=? AND state='claimed' AND boot=? AND pid=? AND start=?""",
                (attempt["request_id"], attempt["attempt_id"], attempt["token"], self.boot,
                 os.getpid(), process_start(os.getpid()))).fetchone()
            if a is None:
                return {"action": "stale"}
            r = db.execute("SELECT * FROM requests WHERE request_id=?", (a["request_id"],)).fetchone()
            self.ledger.event(db, r["run_id"], "cli.failure",
                              {"request_id": r["request_id"], "attempt_id": a["attempt_id"],
                               "retryable": retryable, "diagnostic": diagnostic})
            if retryable:
                return self._retry(db, r, a, "infrastructure_failure")
            db.execute("UPDATE execution_attempts SET state='rejected' WHERE token=?", (a["token"],))
            return self._state(db, r, "failed")

    def submit(self, attempt, payload, *, exit_status=0):
        if not isinstance(payload, dict) or not HEX.fullmatch(attempt["token"]):
            raise ValueError("invalid result or token")
        folder = self.staging / attempt["token"]
        raw = encode(payload)
        if len(raw) > LIMIT:
            raise ValueError("oversize output")
        sha = digest(raw)
        put(folder / sha, raw)
        receipt = {k: attempt[k] for k in ("run_id","request_id","attempt_id","token","input_sha")}
        receipt.update(schema="varyroot.result.v1", size=len(raw), digest=sha, exit_status=exit_status)
        data = encode(receipt)
        path = folder / ("receipt-" + digest(data) + ".json")
        put(path, data)
        return path

    def _verify(self, path, r, a):
        data = read_file(path)
        receipt = validate_json(data)
        identity = {k: r[k] for k in ("run_id","request_id","input_sha")}
        identity.update(attempt_id=a["attempt_id"], token=a["token"], schema="varyroot.result.v1", exit_status=0)
        sha = receipt.get("digest")
        if (path.name != "receipt-"+digest(data)+".json" or not isinstance(sha, str)
                or not HEX.fullmatch(sha) or type(receipt.get("size")) is not int):
            raise ValueError("invalid receipt metadata")
        identity.update(digest=sha,size=receipt["size"])
        if encode(identity) != data:
            raise ValueError("mismatched receipt identity, schema or exit status")
        raw = read_file(path.parent / sha)
        if digest(raw) != sha or len(raw) != receipt["size"]:
            raise ValueError("output bytes mismatch")
        validate_json(raw)
        return sha, raw, digest(data)

    def recover(self, request_id, *, finished=None):
        with self.ledger.tx() as db:
            r = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
            if r is None:
                raise KeyError(request_id)
            a = db.execute("SELECT * FROM execution_attempts WHERE request_id=? ORDER BY attempt_id DESC LIMIT 1",
                           (request_id,)).fetchone()
            if r["state"] == "queued":
                return self._reserve(db,r,a)
            if r["state"] not in {"publishing","ready","running","delivered"}:
                return {"action": r["state"]}
            intent = db.execute("SELECT * FROM publication_intents WHERE request_id=?", (request_id,)).fetchone()
            if r["state"] != "publishing":
                paths = sorted((self.staging / a["token"]).glob("receipt-*.json"))
                if r["state"] in {"ready","delivered"}:
                    if self._new_conflict(db, r, a, intent, paths):
                        return self._conflict(db, r, a)
                    return {"action": "ready", "digest": intent["digest"]}
                if not paths:
                    # A completed role may have lost its return channel after sealing a receipt.
                    # Only the current claim owner may terminate a receiptless attempt.
                    if finished is not None:
                        attempt, diagnostic = finished
                        if (a["token"] == attempt["token"] and a["attempt_id"] == attempt["attempt_id"]
                                and a["state"] == "claimed" and a["pid"] == os.getpid()
                                and a["start"] == process_start(os.getpid())):
                            self.ledger.event(db,r["run_id"],"cli.failure",dict(request_id=request_id,
                                attempt_id=a["attempt_id"],retryable=True,diagnostic=diagnostic))
                            return self._retry(db,r,a,"infrastructure_failure")
                    live = a["state"] == "reserved" or process_start(a["pid"]) == a["start"]
                    if a["boot"] == self.boot and a["deadline"] > time.monotonic() and live:
                        return {"action": "wait"}
                    return self._retry(db,r,a,"revoked")
                try:
                    if a["state"] != "claimed":
                        raise ValueError("receipt before claim")
                    sha, raw, receipt_digest = self._verify(paths[0],r,a)
                    for path in paths[1:]:
                        if self._verify(path,r,a)[0] != sha:
                            return self._conflict(db,r,a)
                except (ValueError,OSError,RecursionError):
                    return self._retry(db,r,a,"invalid_receipt")
                try:
                    put(self.sealed / sha, raw)
                except (OSError, ValueError):
                    return self._retry(db, r, a, "staging_failed")
                self.checkpoint("before_t1")
                db.execute("INSERT INTO publication_intents VALUES (?,?,?,?,?,'varyroot.result.v1','publishing')",
                           (request_id,a["attempt_id"],sha,len(raw),receipt_digest))
                db.execute("UPDATE execution_attempts SET state='publishing' WHERE token=?", (a["token"],))
                self._state(db,r,"publishing")
        self.checkpoint("after_t1")
        result = self._promote(request_id)
        if result["action"] == "ready":
            self.checkpoint("after_t2")
        return result

    def _retry(self, db, r, a, reason):
        db.execute("UPDATE execution_attempts SET state=? WHERE token=?", (reason,a["token"]))
        self.ledger.event(db,r["run_id"],"attempt."+reason,{"request_id":r["request_id"],"attempt_id":a["attempt_id"]})
        return self._reserve(db,r,a)

    def _conflict(self, db, r, a):
        db.execute("UPDATE execution_attempts SET state='conflict' WHERE token=?", (a["token"],))
        db.execute("UPDATE publication_intents SET state='conflict' WHERE request_id=?", (r["request_id"],))
        return self._state(db,r,"conflict")

    def _new_conflict(self, db, r, a, intent, paths):
        for path in paths:
            if path.name == "receipt-" + intent["receipt_digest"] + ".json":
                continue
            try:
                sha, _, _ = self._verify(path, r, a)
            except (ValueError, OSError, RecursionError) as error:
                new = db.execute("INSERT OR IGNORE INTO invalid_late_receipts VALUES (?,?)",
                                 (a["token"], path.name))
                if new.rowcount:
                    self.ledger.event(db, r["run_id"], "attempt.invalid_late_receipt",
                                      {"request_id": r["request_id"], "attempt_id": a["attempt_id"],
                                       "filename": path.name, "reason": str(error)})
                continue
            if sha != intent["digest"]:
                return True
        return False

    def _promote(self, request_id):
        with self.ledger.tx() as db:
            r = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
            p = db.execute("SELECT * FROM publication_intents WHERE request_id=?", (request_id,)).fetchone()
            sha = p["digest"]
            if r["state"] in {"ready","delivered"}:
                return {"action":"ready","digest":sha}
            if r["state"] != "publishing":
                return {"action":r["state"]}
            a = db.execute("SELECT * FROM execution_attempts WHERE request_id=? AND attempt_id=?",
                           (request_id,p["attempt_id"])).fetchone()
            paths = sorted((self.staging / a["token"]).glob("receipt-*.json"))
            if self._new_conflict(db, r, a, p, paths):
                return self._conflict(db, r, a)
            try:
                dest = self.objects / sha
                if not dest.exists():
                    stage = self.sealed / sha
                    if not stage.exists():
                        path = self.staging / a["token"] / ("receipt-"+p["receipt_digest"]+".json")
                        _, raw, _ = self._verify(path,r,a)
                        put(stage,raw)
                    raw = read_file(stage)
                    if len(raw) != p["size"] or digest(raw) != sha:
                        raise ValueError("corrupt publication staging file")
                    put(dest,raw)
                raw = read_file(dest)
                if len(raw) != p["size"] or digest(raw) != sha:
                    raise ValueError("corrupt published object")
                sync_dir(self.objects)
            except (OSError,ValueError,RecursionError) as error:
                db.execute("UPDATE publication_intents SET state='failed' WHERE request_id=?", (request_id,))
                db.execute("UPDATE execution_attempts SET state='failed' WHERE token=?", (a["token"],))
                self.ledger.event(db,r["run_id"],"publication.failed",{"request_id":request_id,"reason":str(error)})
                return self._state(db,r,"failed")
            self.checkpoint("after_promotion")
            db.execute("UPDATE publication_intents SET state='ready' WHERE request_id=?", (request_id,))
            db.execute("UPDATE execution_attempts SET state='accepted' WHERE token=?", (a["token"],))
            self._state(db,r,"ready")
            return {"action":"ready","digest":sha}

    def read(self, request_id):
        with self.ledger.tx() as db:
            p = db.execute("""SELECT p.* FROM publication_intents p JOIN requests r USING(request_id)
                WHERE request_id=? AND p.state='ready' AND r.state IN ('ready','delivered')""",(request_id,)).fetchone()
            if p is None:
                raise ValueError("request has no accepted publication")
            raw = read_file(self.objects / p["digest"])
            if len(raw) != p["size"] or digest(raw) != p["digest"]:
                raise ValueError("corrupt published object")
            return validate_json(raw)
