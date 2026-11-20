import hashlib
import json
import multiprocessing
import os
import signal
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from varyroot.ledger import ContractFixtureLedger as Ledger
from varyroot.publication import Publication


def claim_then_wait(root, attempt, claimed):
    assert Publication(Ledger(root)).claim(attempt)
    claimed.set()
    signal.pause()


def die_mid_object_write(root):
    from unittest.mock import patch

    opened = tempfile.NamedTemporaryFile
    def injected(*args, **kwargs):
        stream = opened(*args, **kwargs)
        if Path(kwargs["dir"]).name == "published-objects":
            write = stream.write
            def partial_write(data):
                write(data[:len(data) // 2])
                stream.flush()
                os.kill(os.getpid(), signal.SIGKILL)
            stream.write = partial_write
        return stream

    with patch("varyroot.publication.tempfile.NamedTemporaryFile", side_effect=injected):
        Publication(Ledger(root)).recover("r")


def crash_publication(root, stop):
    def kill(phase):
        if phase == stop:
            os.kill(os.getpid(), signal.SIGKILL)
    Publication(Ledger(root), checkpoint=kill).recover("r")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ledger = Ledger(self.root)
        self.ledger.create_run("run", "random")
        with self.ledger.tx() as db:
            db.execute("INSERT INTO requests(request_id,run_id,state,input_sha) VALUES ('r','run','queued',?)",
                       (hashlib.sha256(b'input').hexdigest(),))
        self.pub = Publication(self.ledger)

    def prepare(self):
        attempt = self.pub.recover("r")
        self.assertEqual(attempt["action"], "dispatch")
        self.assertTrue(self.pub.claim(attempt))
        self.assertFalse(self.pub.claim(attempt))
        self.pub.submit(attempt, {"value": 1})
        return attempt

    def test_retrieve_and_conflicting_duplicate(self):
        attempt = self.prepare()
        self.pub.submit(attempt, {"value": 1})
        ready = self.pub.recover("r")
        self.assertEqual(ready["action"], "ready")
        self.assertEqual(self.pub.read("r"), {"value": 1})
        self.assertEqual(self.pub.recover("r"), ready)
        self.pub.submit(attempt, {"value": 2})
        self.assertEqual(self.pub.recover("r")["action"], "conflict")
        with self.assertRaises(ValueError):
            self.pub.read("r")

    def test_dead_worker_stale_receipt_and_concurrent_retry(self):
        first = self.pub.recover("r")
        self.assertEqual(self.pub.recover("r")["action"], "wait")
        ctx = multiprocessing.get_context("fork")
        claimed = ctx.Event()
        child = ctx.Process(target=claim_then_wait, args=(self.root, first, claimed))
        child.start()
        try:
            self.assertTrue(claimed.wait(5))
            self.assertEqual(self.pub.recover("r")["action"], "wait")
        finally:
            child.kill()
            child.join(5)
        self.assertEqual(child.exitcode, -signal.SIGKILL)
        with ThreadPoolExecutor(4) as pool:
            recovered = list(pool.map(lambda _: self.pub.recover("r"), range(4)))
        self.assertCountEqual([r["action"] for r in recovered], ["dispatch","wait","wait","wait"])
        second = next(r for r in recovered if r["action"] == "dispatch")
        self.pub.submit(first, {"late": True})
        self.assertFalse(self.pub.heartbeat(first))
        self.assertTrue(self.pub.claim(second))
        self.assertTrue(self.pub.heartbeat(second))
        self.pub.submit(second, {"current": True})
        self.assertEqual(self.pub.recover("r")["action"], "ready")
        self.assertEqual(self.pub.read("r"), {"current": True})

    def test_invalid_receipts_exhaust_registered_attempt_limit(self):
        self.pub = Publication(self.ledger, max_attempts=2)
        current = self.pub.recover("r")
        for i in range(2):
            self.assertTrue(self.pub.claim(current))
            path = self.pub.submit(current, {"v": i})
            receipt = json.loads(path.read_bytes())
            receipt["token"] = "invalid"
            path.unlink()
            path.write_text(json.dumps(receipt))
            current = Publication(self.ledger, max_attempts=99).recover("r")
        self.assertEqual(current["action"], "failed")
        self.assertEqual(self.pub.recover("r"), current)

    def check_crash(self, phase):
        self.prepare()
        proc = multiprocessing.get_context("fork").Process(target=crash_publication, args=(self.root, phase))
        proc.start()
        proc.join(5)
        self.assertEqual(proc.exitcode, -signal.SIGKILL)
        with self.assertRaises(ValueError):
            self.pub.read("r")
        self.assertEqual(self.pub.recover("r")["action"], "ready")
        self.assertEqual(self.pub.read("r"), {"value": 1})

    def test_kill_halfway_through_promotion(self):
        self.prepare()
        child = multiprocessing.get_context("fork").Process(target=die_mid_object_write, args=(self.root,))
        child.start()
        child.join(10)
        self.assertEqual(child.exitcode, -signal.SIGKILL)
        with self.ledger.tx() as db:
            state = db.execute("SELECT state FROM requests WHERE request_id='r'").fetchone()[0]
        self.assertEqual(state, "publishing")
        with self.assertRaises(ValueError):
            self.pub.read("r")
        fragments = list(self.pub.objects.iterdir())
        self.assertEqual(len(fragments), 1)
        self.assertEqual(fragments[0].stat().st_size, len(b'{"value":1}') // 2)
        self.assertEqual(self.pub.recover("r")["action"], "ready")
        self.assertEqual(self.pub.read("r"), {"value": 1})

    def test_kill_after_t1(self):
        self.check_crash("after_t1")

    def test_kill_before_t2(self):
        self.check_crash("after_promotion")

    def test_kill_before_t1_and_orphan_is_invisible(self):
        self.check_crash("before_t1")

    def test_kill_after_t2_replays_ready(self):
        self.prepare()
        proc = multiprocessing.get_context("fork").Process(target=crash_publication, args=(self.root, "after_t2"))
        proc.start()
        proc.join(5)
        self.assertEqual(proc.exitcode, -signal.SIGKILL)
        self.assertEqual(self.pub.read("r"), {"value": 1})
        self.assertEqual(self.pub.recover("r")["action"], "ready")

    def test_expired_attempt_with_valid_receipt_is_retrieved(self):
        attempt = self.prepare()
        with self.ledger.tx() as db:
            db.execute("UPDATE execution_attempts SET deadline=0, boot='previous'")
        self.assertFalse(self.pub.heartbeat(attempt))
        self.assertEqual(self.pub.recover("r")["action"], "ready")

    def test_missing_coordinator_stage_rebuilds_from_receipt(self):
        self.prepare()
        def remove_stage(phase):
            if phase == "after_t1":
                for path in self.pub.sealed.iterdir():
                    path.unlink()
        self.pub.checkpoint = remove_stage
        self.assertEqual(self.pub.recover("r")["action"], "ready")

    def test_corrupt_existing_object_preserved_and_not_committed(self):
        self.prepare()
        def create_bad_object(phase):
            if phase == "after_t1":
                (stage,) = list(self.pub.sealed.iterdir())
                (self.pub.objects / stage.name).write_bytes(b"unrelated")
        self.pub.checkpoint = create_bad_object
        self.assertEqual(self.pub.recover("r")["action"], "failed")
        (obj,) = list(self.pub.objects.iterdir())
        self.assertEqual(obj.read_bytes(), b"unrelated")
        with self.assertRaises(ValueError):
            self.pub.read("r")

    def test_conflicting_receipt_between_t1_and_t2(self):
        attempt = self.prepare()
        def second_receipt(phase):
            if phase == "after_t1":
                self.pub.submit(attempt, {"value": 2})
        self.pub.checkpoint = second_receipt
        self.assertEqual(self.pub.recover("r")["action"], "conflict")
        with self.assertRaises(ValueError):
            self.pub.read("r")

    def test_invalid_late_receipt_is_audited_once(self):
        attempt = self.prepare()
        ready = self.pub.recover("r")
        self.pub.submit(attempt, {"value": 2}, exit_status=7)
        self.assertEqual(self.pub.recover("r"), ready)
        self.assertEqual(self.pub.recover("r"), ready)
        events = self.ledger.events("run")
        self.assertEqual(sum(e["kind"] == "attempt.invalid_late_receipt" for e in events), 1)
