"""Linux coordinator-side role views. Metadata and image selection belong to the coordinator."""
import hashlib
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from contextlib import ExitStack
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path

PHASES = ("seed", "select", "verify", "decide", "compile", "regress")
ROLE_PHASES = {
    "A": {"seed"}, "verifier": {"verify"}, "B": {"select", "decide"},
    "random": {"select"}, "divergence": {"select"}, "C": {"compile", "regress"},
}
KINDS = {
    "A": {"seed", "source", "contract", "domain", "target", "bundle_manifest", "bundle_records"},
    "verifier": {"case", "target", "contract", "domain"},
    "B": {"seed", "candidate", "pool", "contract", "domain", "target", "fact", "spec",
          "bundle_manifest", "bundle_records", "prediction", "selection", "evidence"},
    "C": {"spec", "database", "handoff", "bundle_manifest", "bundle_records", "target",
          "prediction", "evidence"},
    "random": {"pool", "budget", "policy"},
    "divergence": {"pool", "budget", "policy", "prediction", "ranking"},
}
PRIVATE = {"evidence", "prediction", "ranking", "budget", "policy", "selection",
           "handoff", "spec", "database", "case"}
ROLE_IMAGE = "varyroot-role:step03"
MODULES = ("__init__", "__main__", "artifacts", "checks", "handoff", "inference", "ir", "contract_role")
MANIFEST = "input_manifest.json"


@dataclass(frozen=True)
class Scope:
    run: str
    seed: str
    group: str
    repeat: str
    role: str
    phase: str
    request: str
    attempt: str
    watermark: int = 0


@dataclass(frozen=True)
class Input:
    ref: str
    path: str
    kind: str
    sha256: str
    size: int
    group: str | None = None
    available_phase: str = "seed"
    reveal_seq: int | None = None
    schema: str = "json"
    dependencies: tuple[str, ...] = ()


def authorize(scope, items):
    """Inputs refer to the published catalog in this run/seed/repeat's trusted source root."""
    if scope.phase not in ROLE_PHASES.get(scope.role, ()):
        raise ValueError("invalid role/phase")
    for name in ("run", "seed", "group", "repeat", "request", "attempt"):
        if getattr(scope, name) in ("", None):
            raise ValueError("missing scope " + name)
    if type(scope.watermark) is not int or scope.watermark < 0:
        raise ValueError("invalid reveal watermark")
    refs = {i.ref for i in items}
    if len(refs) != len(items) or len({i.path for i in items}) != len(items):
        raise ValueError("duplicate input identity or path")
    for item in items:
        parts = item.path.split("/")
        if (any(p in ("", ".", "..") for p in parts) or "\\" in item.path or ":" in item.path
                or parts[0] == MANIFEST or any(ord(c) < 32 for c in item.path)):
            raise ValueError("invalid role path")
        if not re.fullmatch(r"[^@\s]+@[1-9][0-9]*", item.ref) or not item.schema:
            raise ValueError("invalid versioned ref or schema")
        if not re.fullmatch("[0-9a-f]{64}", item.sha256) or type(item.size) is not int or item.size < 0:
            raise ValueError("invalid file fingerprint")
        if item.kind not in KINDS[scope.role] or PHASES.index(item.available_phase) > PHASES.index(scope.phase):
            raise PermissionError("kind or phase outside grant")
        if (item.group is not None or item.kind in PRIVATE) and item.group != scope.group:
            raise PermissionError("outside group")
        if item.kind == "evidence" or item.reveal_seq is not None:
            if (scope.role not in {"B", "C"} or scope.role == "C" and scope.phase != "regress"
                    or item.group != scope.group or type(item.reveal_seq) is not int
                    or not 0 < item.reveal_seq <= scope.watermark):
                raise PermissionError("outside revealed history")
        if not refs.issuperset(item.dependencies):
            raise PermissionError("ungranted dependency")


def copy_checked(root_fd, item, dest):
    with ExitStack() as stack:
        directory = root_fd
        parts = item.path.split("/")
        for part in parts[:-1]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            stack.callback(os.close, directory)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        reader = stack.enter_context(os.fdopen(descriptor, "rb"))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != item.size:
            raise ValueError("unexpected input type or size")
        dest.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        count = 0
        with dest.open("xb") as writer:
            while chunk := reader.read(1024 * 1024):
                count += len(chunk)
                if count > item.size:
                    raise ValueError("input grew")
                digest.update(chunk)
                writer.write(chunk)
        if count != item.size or digest.hexdigest() != item.sha256:
            raise ValueError("input digest/size changed")
        dest.chmod(0o444)


def role_identity():
    # Match an ordinary coordinator so it owns its results. Root always drops privilege.
    return os.geteuid() or 65534, os.getegid() or 65534


def docker_command():
    return ["sudo", "-n", "docker"] if os.environ.get("VARYROOT_DOCKER_SUDO") == "1" else ["docker"]


def selected_backend():
    backend = os.environ.get("VARYROOT_ROLE_BACKEND")
    if backend is None:
        raise ValueError("explicit VARYROOT_ROLE_BACKEND is required")
    if backend not in {"docker", "namespace"}:
        raise ValueError("unsupported role backend")
    return backend


def rootfs_fingerprint(root):
    """Content and metadata digest for an exported, ordinary-file rootfs."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        record = [path.relative_to(root).as_posix(), stat.S_IMODE(metadata.st_mode)]
        if stat.S_ISREG(metadata.st_mode):
            with path.open("rb") as reader:
                record += ["file", metadata.st_size, hashlib.file_digest(reader, "sha256").hexdigest()]
        elif stat.S_ISDIR(metadata.st_mode):
            record += ["dir"]
        elif stat.S_ISLNK(metadata.st_mode):
            record += ["symlink", os.readlink(path)]
        else:
            raise ValueError("rootfs contains unsupported special file")
        digest.update((json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
    return digest.hexdigest()


def namespace_image(image):
    project = Path(__file__).resolve().parents[1]
    lock_name = os.environ.get("VARYROOT_NAMESPACE_LOCK")
    if not lock_name:
        raise ValueError("namespace backend requires VARYROOT_NAMESPACE_LOCK")
    lock = Path(lock_name).resolve(strict=True)
    if not lock.is_relative_to(project):
        raise ValueError("namespace lock outside project")
    manifest = json.loads(lock.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or not isinstance(manifest.get("images"), dict):
        raise ValueError("invalid namespace image lock")
    entries = manifest["images"]
    entry = entries.get(image)
    if entry is None:
        matches = [value for value in entries.values() if value.get("image_id") == image]
        if len(matches) != 1:
            raise ValueError("unlocked namespace image")
        entry = matches[0]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", entry.get("image_id", "")):
        raise ValueError("invalid namespace image identity")
    if not re.fullmatch(r"[0-9a-f]{64}", entry.get("rootfs_digest", "")):
        raise ValueError("invalid namespace rootfs digest")
    candidate = project / entry["rootfs"]
    if candidate.is_symlink():
        raise ValueError("namespace rootfs symlink")
    rootfs = candidate.resolve(strict=True)
    if not rootfs.is_relative_to(project) or not rootfs.is_dir() or rootfs.is_symlink():
        raise ValueError("namespace rootfs outside project")
    if rootfs_fingerprint(rootfs) != entry["rootfs_digest"]:
        raise ValueError("namespace rootfs digest mismatch")
    return entry, rootfs


def resolve_image(tag):
    if selected_backend() == "namespace":
        return namespace_image(tag)[0]["image_id"]
    return subprocess.check_output([*docker_command(), "image", "inspect", "--format",
                                    "{{.Id}}", tag], text=True).strip()


def write_audit(attempt, audit):
    target = attempt / "execution.json"
    if target.exists():
        raise FileExistsError("execution audit already exists")
    data = (json.dumps(audit, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with target.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def materialize(attempt_dir, source_root, scope, inputs):
    items = tuple(inputs)
    authorize(scope, items)
    attempt = Path(attempt_dir)
    attempt.mkdir(mode=0o700)
    try:
        view = attempt / "input"
        view.mkdir(mode=0o755)
        root_fd = os.open(source_root, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            for item in items:
                copy_checked(root_fd, item, view / item.path)
        finally:
            os.close(root_fd)
        ordered = sorted(items, key=lambda item: item.path)
        entries = []
        for item in ordered:
            artifact_id, version = item.ref.rsplit("@", 1)
            entries.append(dict(asdict(item), id=artifact_id, version=int(version)))
        data = (json.dumps({"schema_version": 1, "scope": asdict(scope), "files": entries},
                           sort_keys=True, separators=(",", ":")) + "\n").encode()
        (view / MANIFEST).write_bytes(data)
        (view / MANIFEST).chmod(0o444)
        for parent, _, _ in os.walk(view):
            Path(parent).chmod(0o555)
        out = attempt / "output"
        out.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(out, *role_identity())
        digest = hashlib.sha256(data).hexdigest()
        (attempt / "manifest.sha256").write_text(digest + "\n", encoding="ascii")
        return digest
    except BaseException:
        shutil.rmtree(attempt)
        raise


def build_image(base="python:3.13-slim", image=ROLE_IMAGE):
    """Stage only explicitly named runtime sources. Docker receives no checkout or data."""
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="varyroot-build-") as tmp:
        stage = Path(tmp)
        (stage / "varyroot").mkdir()
        (stage / "varyroot").chmod(0o755)
        for module in MODULES:
            src = project / "varyroot" / (module + ".py")
            dest = stage / "varyroot" / src.name
            shutil.copyfile(src, dest)
            dest.chmod(0o644)
        shutil.copyfile(project / "tools/roles/Dockerfile", stage / "Dockerfile")
        subprocess.run([*docker_command(), "build", "--network", "none", "--pull=false", "--build-arg",
                        "BASE=" + base, "-t", image, str(stage)], check=True)


def run_role(attempt_dir, argv, *, image=ROLE_IMAGE, timeout=60, output_dir=None):
    """Run one role. Arguments and the image are chosen only by the coordinator."""
    attempt = Path(attempt_dir).resolve(strict=True)
    view = attempt / "input"
    out = Path(output_dir) if output_dir is not None else attempt / "output"
    if any("," in str(path) or path.is_symlink() or not path.is_dir() for path in (view, out)):
        raise ValueError("invalid mount path")
    if any(out.iterdir()):
        raise FileExistsError("output must start empty")
    digest = (attempt / "manifest.sha256").read_text(encoding="ascii").strip()
    if hashlib.sha256((view / MANIFEST).read_bytes()).hexdigest() != digest:
        raise ValueError("manifest changed")
    manifest = json.loads((view / MANIFEST).read_bytes())
    expected = {MANIFEST, *(entry["path"] for entry in manifest["files"])}
    paths = list(view.rglob("*"))
    if any(path.is_symlink() for path in paths) or {
            path.relative_to(view).as_posix() for path in paths if not path.is_dir()} != expected:
        raise ValueError("view contains missing or unlisted files")
    for entry in manifest["files"]:
        path = view / entry["path"]
        if not path.is_file() or path.stat().st_size != entry["size"]:
            raise ValueError("materialized file type/size changed")
        with path.open("rb") as reader:
            if hashlib.file_digest(reader, "sha256").hexdigest() != entry["sha256"]:
                raise ValueError("materialized file digest changed")
    backend = selected_backend()
    entry = rootfs = None
    if backend == "namespace":
        entry, rootfs = namespace_image(image)
    name = "varyroot-" + uuid.uuid4().hex
    uid, gid = role_identity()
    docker_cmd = [
        *docker_command(), "run", "--rm", "--pull", "never", "--name", name, "--network", "none",
        "--read-only", "--user", f"{uid}:{gid}", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--ipc", "none", "--pids-limit", "64",
        "--memory", "256m", "--workdir", "/input", "--mount",
        f"type=bind,src={view},dst=/input,readonly", "--mount", f"type=bind,src={out},dst=/output",
        image, *argv,
    ]
    if backend == "namespace":
        sysdir = attempt / "sys"
        sysdir.mkdir(mode=0o700)
        cmd = ["unshare", "-rnm", "--", sys.executable, "-B",
               str(Path(__file__).with_name("namespace_exec.py")),
               str(sysdir), str(rootfs), str(view), str(out), str(uid), str(gid), *argv]
    else:
        cmd = docker_cmd
    audit = {"backend": backend, "image_id": entry["image_id"] if entry else image,
             "rootfs_digest": entry["rootfs_digest"] if entry else None,
             "manifest_sha256": digest, "role": manifest["scope"]["role"],
             "request_id": manifest["scope"]["request"],
             "attempt_id": manifest["scope"]["attempt"],
             "effective_uid": uid, "effective_gid": gid,
             "network": "isolated_loopback_only" if backend == "namespace" else "none",
             "mounts": {"input": "read_only", "rootfs": "read_only",
                        "output": "exclusive", "tmp": "private_tmpfs"}}
    try:
        if backend == "namespace":
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                audit["completion"] = "timeout"
                write_audit(attempt, audit)
                raise
            result = subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        audit["completion"] = "completed"
        audit["exit_status"] = result.returncode
        write_audit(attempt, audit)
        result.varyroot_audit = audit
        return result
    except BaseException:
        if backend == "docker":
            subprocess.run([*docker_command(), "rm", "-f", name], capture_output=True, timeout=15)
        raise
