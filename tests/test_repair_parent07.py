"""Repair authorization is anchored in a committed failed build and live BQRS decode."""
from pathlib import Path
import shutil
import tempfile
import unittest

import test_freeze07 as fixtures
from varyroot.c_ledger import finish_regression
from varyroot.freeze_archive import verify_archive
from varyroot.repair_parent import validate_parent


class DecodeEngine:
    """Read-only test decoder that emits the preselected BQRS table."""

    def __init__(self, work, raw):
        self.work = work
        self.raw = raw

    def command(self, *args):
        assert args[:3] == ("bqrs", "decode", "--format=csv")
        lane = args[-1].stem
        Path(args[-2].removeprefix("--output=")).write_bytes(self.raw[lane])


class RepairParentTests(unittest.TestCase):
    def setUp(self):
        f = fixtures.PairTransaction()
        self.addCleanup(f.doCleanups)
        f.setUp()
        self.f = f
        self.parent = f.stage("repair")
        self.decoded = {lane: (self.parent / "results" / f"{lane}.csv").read_bytes()
                        for lane in ("Q0", "Qstar")}
        self.engine = DecodeEngine(f.root, self.decoded)
        self.destination = f.root / "new-artifacts"
        self.destination.mkdir()
        shutil.copyfile(self.parent / "database.zip", self.destination / "database.zip")

    def commit_parent(self):
        f = self.f
        result = finish_regression(f.db, f.run, f.version, f.head(), self.parent)
        self.assertEqual(result["route"], "repair")

    def validate(self):
        f = self.f
        return validate_parent(f.db, f.run, f.db.run(f.run), self.parent, f.c1,
                               f.lock, self.engine, self.destination)

    def test_committed_parent_persists_once(self):
        self.commit_parent()
        parent, diagnostic = self.validate()
        self.assertEqual(self.validate(), (parent, diagnostic))
        events = [e["detail"] for e in self.f.db.events(self.f.run) if e["kind"] == "C5.repair_parent"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["diagnostic_sha"], diagnostic)
        files = verify_archive(self.destination / "repair", events[0]["archive_sha"])
        sealed = self.f.db.root / "c-repair-parents" / events[0]["archive_sha"]
        self.assertEqual(files, verify_archive(sealed, events[0]["archive_sha"]))
        self.assertEqual(files["queries/shared.qll"], parent)
        self.assertEqual(files["parent-c5.json"], diagnostic)
        self.assertIn("parent-c4.json", files)
        self.assertIn("build-log.json", files)
        self.assertFalse(events[0]["historical_counts"])

    def test_uncommitted_and_changed_live_database(self):
        with self.assertRaisesRegex(ValueError, "not committed"):
            self.validate()
        self.commit_parent()
        (self.destination / "database.zip").write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "database differs"):
            self.validate()
        self.assertFalse((self.destination / "repair").exists())

    def test_decode_mismatch_has_no_authority(self):
        self.commit_parent()
        self.decoded["Qstar"] += b"additional,row\n"
        with self.assertRaisesRegex(ValueError, "Qstar repair parent BQRS"):
            self.validate()
        self.assertFalse(any(e["kind"] == "C5.repair_parent" for e in self.f.db.events(self.f.run)))
