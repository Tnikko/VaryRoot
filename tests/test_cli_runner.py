import json
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fixtures_m1 import write
from test_inference import get, npd, oob
from varyroot.cli_runner import CliFailure, run_cli, run_request
from varyroot.ledger import ContractFixtureLedger as Ledger
from varyroot.publication import Publication


def cli(*args):
    return subprocess.run([sys.executable, "-B", "-m", "varyroot", *map(str, args)],
                          capture_output=True)


class CliTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_real_cli_semantic_failures_stop_and_preserve_diagnostics(self):
        rows = npd("exit")
        manifest = write(self.root, rows)
        for expected in (2, 3, 4):
            target = "t@2" if expected == 2 else "t@1"
            if expected == 3:
                get(rows, "c.guard")["antecedent"] = {"var": "typo"}
            if expected == 4:
                rows = npd("log")
                rows.append(dict(get(rows, "c.guard"), id="c.other", clause_id="other", antecedent=True))
                get(rows, "s")["clause_refs"].append("c.other@1")
            write(self.root, rows)
            with self.assertRaises(CliFailure) as error:
                run_cli(lambda attempt: cli("explain", manifest, target))
            self.assertEqual((error.exception.code, error.exception.attempts), (expected, 1))
            if expected == 4:
                self.assertTrue(all(error.exception.diagnostic["derivation"][k] for k in ("report", "quiet")))

    def test_real_cli_uncovered_and_retry_after_io_error(self):
        manifest = write(self.root, oob(3, "single"))
        seen = []
        def invoke(number):
            seen.append(number)
            return cli("explain", self.root / "missing" if number == 1 else manifest, "t@1")
        result = run_cli(invoke, max_attempts=2)
        self.assertEqual(json.loads(result.stdout)["code"], "uncovered")
        self.assertEqual(seen, [1, 2])

    def test_crash_and_engine_failure_are_bounded(self):
        for code in (-signal.SIGKILL, 125, 126, 127):
            with self.subTest(code=code), self.assertRaises(CliFailure) as error:
                command = ("import os, signal; os.kill(os.getpid(), signal.SIGKILL)" if code < 0
                           else f"raise SystemExit({code})")
                run_cli(lambda n: subprocess.run([sys.executable, "-c", command], capture_output=True),
                        max_attempts=2)
            self.assertEqual((error.exception.code, error.exception.attempts), (code, 2))

    def publication(self):
        ledger = Ledger(self.root / "store")
        ledger.create_run("run", "random")
        with ledger.tx() as db:
            db.execute("INSERT INTO requests(request_id,run_id,state,account) VALUES ('r','run','queued','B.verify')")
            db.execute("INSERT INTO charges VALUES ('r','run','B.verify')")
        return Publication(ledger, max_attempts=2)

    def test_request_io_retry_reuses_charge_and_accepted_receipt(self):
        pub = self.publication()
        manifest = write(self.root, npd("exit"))
        def invoke(attempt):
            return cli("validate", self.root / "missing" if attempt["attempt_id"] == 1 else manifest)
        status = run_request(pub, "r", invoke)
        self.assertEqual(status["action"], "ready")
        self.assertEqual(pub.read("r")["code"], "ok")
        self.assertEqual(run_request(pub, "r", lambda _: self.fail("repeat launch")), status)
        with pub.ledger.tx() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM charges").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM execution_attempts").fetchone()[0], 2)

    def test_request_semantic_error_never_retried(self):
        pub = self.publication()
        manifest = write(self.root, npd("exit"))
        result = run_request(pub, "r", lambda a: cli("explain", manifest, "t@2"))
        self.assertEqual(result["action"], "failed")
        with pub.ledger.tx() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM execution_attempts").fetchone()[0], 1)
        self.assertEqual(pub.recover("r"), {"action": "failed"})


    def test_request_exhaustion_survives_restart(self):
        pub = self.publication()
        result = run_request(pub, "r", lambda a: cli("validate", self.root / "missing"))
        self.assertEqual(result["action"], "failed")
        reopened = Publication(Ledger(pub.ledger.root), max_attempts=20)
        self.assertEqual(run_request(reopened, "r", lambda a: self.fail("reopened terminal request")), result)
        failures = [e for e in reopened.ledger.events("run") if e["kind"] == "cli.failure"]
        self.assertEqual([e["detail"]["diagnostic"]["exit_status"] for e in failures], [5, 5])
