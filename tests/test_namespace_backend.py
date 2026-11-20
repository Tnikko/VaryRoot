"""The coordinator's project-private Linux namespace execution backend."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from varyroot.sandbox import Input, Scope, materialize, resolve_image, rootfs_fingerprint, run_role


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux namespace required")
class NamespaceBackendTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.attempt = self.root / "attempt"
        data = b"visible"
        (self.source / "seed.json").write_bytes(data)
        scope = Scope("run", "seed", "development", "1", "A", "seed", "request", "attempt")
        item = Input("seed@1", "seed.json", "seed", hashlib.sha256(data).hexdigest(), len(data))
        materialize(self.attempt, self.source, scope, [item])

    def test_namespace_configuration_never_falls_back_to_docker(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "explicit"):
            resolve_image("varyroot-agent-a:step04")
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": str(self.root / "missing.json")}), \
                self.assertRaises((ValueError, FileNotFoundError)):
            resolve_image("varyroot-agent-a:step04")
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "bogus"}), \
                self.assertRaises(ValueError):
            resolve_image("varyroot-agent-a:step04")

    def test_rootfs_tampering_fails_before_dispatch(self):
        rootfs = self.root / "private-root"
        rootfs.mkdir()
        (rootfs / "worker").write_text("original")
        project = Path(__file__).resolve().parents[1]
        if not self.root.is_relative_to(project):
            self.skipTest("project-local TMPDIR required")
        lock = self.root / "image-lock.json"
        lock.write_text(json.dumps({"schema": 1, "images": {"test:role": {
            "image_id": "sha256:" + "a" * 64,
            "rootfs": rootfs.relative_to(project).as_posix(),
            "rootfs_digest": rootfs_fingerprint(rootfs)}}}))
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": str(lock)}):
            self.assertEqual(resolve_image("test:role"), "sha256:" + "a" * 64)
            (rootfs / "worker").write_text("changed")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                resolve_image("test:role")

    def test_namespace_role_isolated_and_audited(self):
        lock = os.environ.get("VARYROOT_TEST_NAMESPACE_LOCK")
        if not lock:
            self.skipTest("private rootfs fixture not installed")
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": lock}):
            image = resolve_image("varyroot-role:step03")
            program = "import json,os,pathlib; p=pathlib.Path; " \
                "status=p('/proc/self/status').read_text(); " \
                "p('/output/probe.json').write_text(json.dumps({" \
                "'visible':p('/input/seed.json').read_text()," \
                "'secret':p('/input/secret.json').exists()," \
                "'socket':p('/var/run/docker.sock').exists()," \
                "'net':sorted(os.listdir('/sys/class/net'))," \
                "'cap_eff':next(x.split()[1] for x in status.splitlines() if x.startswith('CapEff:'))," \
                "'no_new_privs':next(x.split()[1] for x in status.splitlines() if x.startswith('NoNewPrivs:'))," \
                "'uid':os.getuid()," \
                "'input_writable':os.access('/input',os.W_OK)}))"
            result = run_role(self.attempt, ["python", "-c", program], image=image)
            self.assertEqual(result.returncode, 0, result.stderr)
            probe = json.loads((self.attempt / "output/probe.json").read_text())
            self.assertEqual(probe["visible"], "visible")
            self.assertFalse(probe["secret"] or probe["socket"] or probe["input_writable"])
            self.assertEqual(probe["net"], ["lo"])
            self.assertNotEqual(probe["uid"], 0)
            self.assertEqual(int(probe["cap_eff"], 16), 0)
            self.assertEqual(probe["no_new_privs"], "1")
            audit = json.loads((self.attempt / "execution.json").read_text())
            self.assertEqual(audit["backend"], "namespace")
            self.assertEqual(audit["image_id"], image)
            self.assertRegex(audit["rootfs_digest"], r"^[0-9a-f]{64}$")

    def test_timeout_kills_forked_descendant(self):
        lock = os.environ.get("VARYROOT_TEST_NAMESPACE_LOCK")
        if not lock:
            self.skipTest("private rootfs fixture not installed")
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": lock}):
            image = resolve_image("varyroot-role:step03")
            program = "import os,time,pathlib; pid=os.fork(); " \
                "os.setsid() if pid==0 else None; " \
                "time.sleep(2) if pid==0 else time.sleep(5); " \
                "pathlib.Path('/output/late').write_text('bad') if pid==0 else None"
            with self.assertRaises(subprocess.TimeoutExpired):
                run_role(self.attempt, ["python", "-c", program], image=image, timeout=0.3)
            time.sleep(2.5)
            self.assertFalse((self.attempt / "output/late").exists())
            audit = json.loads((self.attempt / "execution.json").read_text())
            self.assertEqual(audit["completion"], "timeout")

    def test_locked_agent_a_compiler_and_verifier_registry(self):
        lock_name = os.environ.get("VARYROOT_TEST_NAMESPACE_LOCK")
        if not lock_name:
            self.skipTest("private rootfs fixture not installed")
        project = Path(__file__).resolve().parents[1]
        images = json.loads(Path(lock_name).read_text())["images"]
        clang_lock = json.loads((project / "tools/frontend/clang18.lock.json").read_text())
        a_root = project / images["varyroot-agent-a:step04"]["rootfs"]
        for relative, expected in clang_lock["files"].items():
            with self.subTest(relative=relative), \
                    (a_root / "opt/clang" / relative).open("rb") as reader:
                self.assertEqual(hashlib.file_digest(reader, "sha256").hexdigest(), expected)
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": lock_name}):
            a_image = resolve_image("varyroot-agent-a:step04")
            result = run_role(self.attempt, ["clang-18", "--version"], image=a_image)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[:3],
                             clang_lock["compiler"].splitlines()[:3])
            self.assertIn("InstalledDir: /opt/clang/bin", result.stdout)

        v_root = project / images["varyroot-verifier:step05"]["rootfs"]
        registry = json.loads((v_root / "opt/native/registry.json").read_text())
        self.assertTrue(registry)
        for name, record in registry.items():
            binary = v_root / "opt/native" / (name + ".so")
            with self.subTest(name=name), binary.open("rb") as reader:
                self.assertEqual(hashlib.file_digest(reader, "sha256").hexdigest(),
                                 record["binary_sha256"])

    def test_launch_does_not_depend_on_coordinator_cwd(self):
        lock = os.environ.get("VARYROOT_TEST_NAMESPACE_LOCK")
        if not lock:
            self.skipTest("private rootfs fixture not installed")
        original = Path.cwd()
        self.addCleanup(os.chdir, original)
        os.chdir(self.root)
        with patch.dict(os.environ, {"VARYROOT_ROLE_BACKEND": "namespace",
                                     "VARYROOT_NAMESPACE_LOCK": lock}):
            image = resolve_image("varyroot-role:step03")
            result = run_role(self.attempt, ["python", "-c", "print('ok')"], image=image)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")
