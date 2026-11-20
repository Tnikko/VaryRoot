"""Isolated filesystem and launcher regressions for the offline, paired replay."""
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.codeql07 import replay


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.root = self.work / "bundle"
        self.root.mkdir()
        names = list(replay.replay_files(".")) + [
            "database.zip", "toolchain.json", "c1.json", "c4.json", "c5.json", "budget.json",
            "handoff/b6.json", "handoff/manifest.json", "handoff/records.json", "queries/qlpack.yml",
            "queries/shared.qll",
        ]
        for lane in replay.LANES:
            names.extend((f"queries/{lane}.ql", f"results/{lane}.csv", f"results/{lane}.bqrs",
                          f"results/{lane}.status.json"))
        for name in names:
            path = self.root / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(name)
        (self.root / "replay/tools/codeql07/replay.py").write_bytes(Path(replay.__file__).read_bytes())
        self.image = "sha256:" + "a" * 64
        (self.root / "toolchain.json").write_text(json.dumps(dict(runtime_image=self.image)))
        self.expected = self.sign()
        self.tools = self.work / "tools"
        self.tools.mkdir()

    def sign(self):
        inventory = {p.relative_to(self.root).as_posix(): replay.sha(p) for p in self.root.rglob("*")
                     if p.is_file() and p.name != replay.MANIFEST}
        manifest = self.root / replay.MANIFEST
        manifest.write_text(json.dumps(dict(schema_version=1, algorithm="sha256", files=inventory)))
        return replay.sha(manifest)

    def test_tampering_stops_before_engine(self):
        (self.root / "queries/Q0.ql").write_text("changed")
        with patch.object(replay.subprocess, "run") as engine, self.assertRaisesRegex(ValueError, "digest mismatch"):
            replay.launch(self.root, self.expected, self.tools, self.work / "out")
        engine.assert_not_called()
        self.assertFalse((self.work / "out").exists())

    def test_missing_dependency_even_with_fresh_manifest(self):
        (self.root / "results/Qstar.bqrs").unlink()
        with self.assertRaisesRegex(ValueError, "missing replay dependencies"):
            replay.verified_files(self.root, self.sign())
        with self.assertRaisesRegex(ValueError, "manifest digest mismatch"):
            replay.verified_files(self.root, self.expected)

    @unittest.skipUnless(hasattr(os, "getuid"), "Linux Docker launcher")
    def test_isolated_mounts(self):
        out = self.work / "out"
        def dryrun(cmd, **kwargs):
            mounts = [cmd[i + 1] for i, value in enumerate(cmd) if value == "--mount"]
            self.assertEqual(mounts, [f"type=bind,src={self.root},dst=/bundle,readonly",
                                      f"type=bind,src={self.tools},dst=/toolchain,readonly",
                                      f"type=bind,src={out},dst=/out"])
            self.assertIn("--network=none", cmd)
            self.assertIn("--read-only", cmd)
            self.assertNotEqual(cmd[cmd.index("--user") + 1].split(":")[0], "0")
            self.assertEqual(cmd[cmd.index("--entrypoint") + 2], self.image)
            self.assertEqual(kwargs["input"], Path(replay.__file__).read_bytes())
            (out / "replay-proof.json").write_text("{}")
        with patch.object(replay.subprocess, "check_output", return_value=self.image), \
             patch.object(replay.subprocess, "run", side_effect=dryrun):
            self.assertEqual(replay.launch(self.root, self.expected, self.tools, out), out / "replay-proof.json")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                replay.launch(self.root, self.expected, self.tools, out)

    def test_database_restore_stays_in_private_directory(self):
        bundle = self.work / "database.zip"
        with zipfile.ZipFile(bundle, "w") as raw:
            raw.writestr("../outside", "not allowed")
        with self.assertRaisesRegex(ValueError, "unsafe database entry"):
            replay.unpack_database(bundle, self.work / "restore")
        self.assertFalse((self.work / "outside").exists())

    @unittest.skipUnless(os.environ.get("VARYROOT_REPLAY_TEST_IMAGE"), "requires a local immutable Docker image ID")
    def test_container_checks_again_after_host_preflight(self):
        image = os.environ["VARYROOT_REPLAY_TEST_IMAGE"]
        (self.root / "toolchain.json").write_text(json.dumps(dict(runtime_image=image)))
        frozen = self.sign()
        query = self.root / "queries/Q0.ql"
        original = query.read_bytes()
        actual_run = subprocess.run
        for mode, reason in [("modify", "archive digest mismatch"), ("remove", "incomplete or extra archive files")]:
            query.write_bytes(original)
            out = self.work / mode
            def intervene(command, **kwargs):
                if command[:2] == ["docker", "run"]:
                    if mode == "modify":
                        query.write_bytes(b"changed after host preflight")
                    else:
                        query.unlink()
                    kwargs.update(capture_output=True)
                if command[0]=="docker" and os.environ.get("VARYROOT_DOCKER_SUDO")=="1":
                    command=["sudo","-n",*command]
                return actual_run(command, **kwargs)
            with self.subTest(mode=mode), patch.object(replay.subprocess, "run", side_effect=intervene):
                with self.assertRaises(subprocess.CalledProcessError) as error:
                    replay.launch(self.root, frozen, self.tools, out)
                self.assertIn(reason.encode(), error.exception.stderr)
                self.assertFalse((out / "replay-proof.json").exists())
