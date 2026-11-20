"""Role-visibility rules and Docker process probes for Step 03."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from varyroot.sandbox import Input, Scope, authorize, materialize, run_role


# This probe runs as the role, using ordinary file operations on known canary paths.
PROBE = """
import hashlib, json, os, sys
from pathlib import Path
view = Path('/input')
manifest = json.loads((view/'input_manifest.json').read_bytes())
observed = {}
for value in json.loads(sys.argv[1]):
    try:
        Path(value).read_bytes()
    except OSError as e:
        observed[value] = e.errno
    else:
        observed[value] = 'read'
def write_test(path):
    try:
        with open(path, 'xb') as f:
            f.write(b'write probe')
    except OSError as e:
        return e.errno
    return 'write'
report = {
    'role': manifest['scope']['role'], 'uid': os.getuid(), 'gid': os.getgid(),
    'input_files': sorted(str(p.relative_to(view)) for p in view.rglob('*') if p.is_file()),
    'inputs': {i['path']: hashlib.sha256((view/i['path']).read_bytes()).hexdigest()
               for i in manifest['files']},
    'reads': observed,
    'writes': {p: write_test(p+'/write-probe') for p in ['/input','/opt/role','/output']},
    'interfaces': sorted(os.listdir('/sys/class/net')),
    'docker_socket_visible': Path('/var/run/docker.sock').exists(),
}
Path('/output/probe.json').write_text(json.dumps(report, sort_keys=True))
"""


@unittest.skipUnless(sys.platform.startswith("linux"),
                     "Linux coordinator required")
class SandboxTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "objects"
        self.source.mkdir()
        self.scope = Scope("r", "s", "g", "1", "B", "decide", "req", "try", 3)

    def artifact(self, kind, name, **fields):
        data = (name + "\n").encode()
        path = self.source / name
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(data)
        return Input(name + "@1", name, kind, hashlib.sha256(data).hexdigest(),
                     len(data), **fields)

    def test_copy_and_closed_dependencies(self):
        first = self.artifact("seed", "seed.json")
        second = self.artifact("candidate", "v/case.json", dependencies=(first.ref,))
        with self.assertRaises(PermissionError):
            authorize(self.scope, [second])
        attempt = self.root / "try"
        digest = materialize(attempt, self.source, self.scope, [first, second])
        manifest = (attempt / "input/input_manifest.json").read_bytes()
        self.assertEqual(digest, hashlib.sha256(manifest).hexdigest())
        entry = json.loads(manifest)["files"][0]
        self.assertEqual((entry["id"], entry["version"], entry["size"]),
                         ("seed.json", 1, first.size))
        staged = attempt / "input/seed.json"
        self.assertNotEqual(staged.stat().st_ino, (self.source / "seed.json").stat().st_ino)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o444)
        with self.assertRaises(FileExistsError):
            materialize(attempt, self.source, self.scope, [])
        (attempt / "input").chmod(0o755)
        (attempt / "input/unlisted").touch()
        with self.assertRaisesRegex(ValueError, "unlisted"):
            run_role(attempt, ["true"])

    def test_reject_link_traversal_and_changed_objects(self):
        item = self.artifact("seed", "file")
        (self.source / "link").symlink_to(self.source)
        (self.source / "linkfile").symlink_to(self.source / "file")
        for path in ["../file", "/file", "linkfile", "link/file", "x\\file",
                     "C:/file", "input_manifest.json", "file/../file"]:
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                materialize(self.root / "try", self.source, self.scope, [replace(item, path=path)])
        (self.source / "file").write_bytes(b"xxxxx")
        with self.assertRaisesRegex(ValueError, "digest"):
            materialize(self.root / "try", self.source, self.scope, [item])

    def test_phase_group_and_history(self):
        item = self.artifact("evidence", "label", group="g", reveal_seq=3)
        authorize(self.scope, [item])
        for change in ({"group": "other"}, {"group": None}, {"available_phase": "compile"},
                       {"reveal_seq": 4}, {"reveal_seq": None}, {"reveal_seq": True}):
            with self.subTest(change=change), self.assertRaises(PermissionError):
                authorize(self.scope, [replace(item, **change)])
        for kind in ("evidence", "prediction", "ranking", "query", "selection", "score"):
            with self.subTest(kind=kind), self.assertRaises(PermissionError):
                authorize(replace(self.scope, role="random", phase="select"), [
                    replace(item, kind=kind, reveal_seq=None)])
        for kind in ("evidence", "prediction", "ranking", "spec", "query"):
            with self.subTest(kind=kind), self.assertRaises(PermissionError):
                authorize(replace(self.scope, role="verifier", phase="verify"), [
                    replace(item, kind=kind, reveal_seq=None)])
        with self.assertRaises(PermissionError):
            authorize(replace(self.scope, role="C", phase="compile"), [item])

    @unittest.skipUnless(os.environ.get("VARYROOT_R05_DOCKER") == "1",
                         "set VARYROOT_R05_DOCKER=1 with role image built for Docker probes")
    def test_actual_roles(self):
        kinds = {
            "seed": {}, "case": {"group": "g"}, "pool": {}, "budget": {"group": "g"},
            "policy": {"group": "g"}, "prediction": {"group": "g"}, "ranking": {"group": "g"},
            "handoff": {"group": "g"}, "evidence": {"group": "g", "reveal_seq": 3},
        }
        files = {k: self.artifact(k, k + ".json", **v) for k, v in kinds.items()}
        for name in ("private.sqlite", "future-label.json", "other-group-label.json", "reserve.json"):
            (self.source / name).write_text("coordinator only")
        rows = [
            ("A", "seed", ["seed"]), ("verifier", "verify", ["case"]),
            ("B", "decide", ["seed", "evidence", "prediction"]),
            ("C", "compile", ["handoff"]), ("C", "regress", ["handoff", "evidence"]),
            ("random", "select", ["pool", "budget", "policy"]),
            ("divergence", "select", ["pool", "budget", "policy", "prediction", "ranking"]),
        ]
        for role, phase, keys in rows:
            with self.subTest(role=role, phase=phase):
                attempt = self.root / (role + phase)
                items = [files[key] for key in keys]
                scope = replace(self.scope, role=role, phase=phase, attempt=attempt.name)
                manifest_digest = materialize(attempt, self.source, scope, items)
                allowed = {item.path: item.sha256 for item in items}
                hidden = ["/input/" + p.name for p in self.source.iterdir() if p.name not in allowed]
                hidden.extend(str(p) for p in self.source.iterdir())
                hidden.extend(["/input/../private.sqlite", "/opt/role/IDEA.md"])
                proc = run_role(attempt, ["python", "-c", PROBE, json.dumps(hidden)])
                self.assertEqual(proc.returncode, 0, proc.stderr)
                report = json.loads((attempt / "output/probe.json").read_text())
                self.assertEqual(report["inputs"], allowed)
                self.assertEqual(report["input_files"], sorted([*allowed, "input_manifest.json"]))
                self.assertTrue(all(e in (2, 13, 20) for e in report["reads"].values()), report)
                self.assertEqual(report["uid"], os.geteuid() or 65534)
                self.assertEqual(report["gid"], os.getegid() or 65534)
                self.assertEqual(report["interfaces"], ["lo"])
                self.assertFalse(report["docker_socket_visible"])
                self.assertEqual(report["writes"]["/output"], "write")
                self.assertIn(report["writes"]["/input"], [13, 30])
                self.assertIn(report["writes"]["/opt/role"], [13, 30])
                print(json.dumps(dict(report, phase=phase, manifest_sha256=manifest_digest),
                                 sort_keys=True), flush=True)
