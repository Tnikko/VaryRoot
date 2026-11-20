"""Build the offline Clang runtime from a locked, locally installed Ubuntu compiler."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from varyroot.sandbox import docker_command

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools/frontend/clang18.lock.json"
COMPILER = Path("/usr/bin/clang-18")
BASE = "python:3.13-slim"
TOOL_IMAGE = "varyroot-clang:step04"
ROLE_IMAGE = "varyroot-agent-a:step04"
RUNTIME_MODULES = ("__init__", "__main__", "artifacts", "checks", "handoff", "inference",
                   "ir", "frontend", "agent_a")


def output(*argv):
    return subprocess.check_output(argv, text=True).strip()


def fingerprint(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def docker_id(tag):
    return output(*docker_command(), "image", "inspect", "--format", "{{.Id}}", tag)


def inputs():
    executable = COMPILER.resolve(strict=True)
    libs = {}
    for line in output("ldd", executable).splitlines():
        if "not found" in line:
            raise RuntimeError(line)
        match = re.search(r"(/\S+)\s+\(0x", line)
        if match:
            lib = Path(match.group(1))
            libs[lib.name] = lib
    loader, = (k for k in libs if k.startswith("ld-linux"))
    resource = Path(output(COMPILER, "-print-resource-dir"))
    files = {"bin/clang": executable, **{"lib/" + name: src for name, src in libs.items()}}
    for src in sorted(resource.rglob("*")):
        if src.is_file():
            files["resource/" + src.relative_to(resource).as_posix()] = src
    lock = {"schema": 1, "base_image": docker_id(BASE), "compiler": output(COMPILER, "--version"),
            "ubuntu_package": output("dpkg-query", "-W", "clang-18"), "triple": output(COMPILER, "-dumpmachine"),
            "loader": loader, "resource_dir": str(resource), "files": {k: fingerprint(v) for k,v in files.items()}}
    return files, lock


def build(context, tag):
    subprocess.run([*docker_command(), "build", "--pull=false", "--network=none", "-t", tag, str(context)],
                   check=True)


def toolchain(capture=False):
    files, lock = inputs()
    if LOCK.exists():
        if json.loads(LOCK.read_text()) != lock:
            raise RuntimeError("toolchain drift; review the lock before building")
    elif capture:
        LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    else:
        raise FileNotFoundError(LOCK)
    with tempfile.TemporaryDirectory(prefix="varyroot-toolchain-") as tmp:
        stage = Path(tmp)
        for name, source in files.items():
            dest = stage / "tool" / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
        for spelling, mode in (("clang-18", ""), ("clang++-18", "--driver-mode=g++ ")):
            wrapper = stage / spelling
            wrapper.write_text("#!/bin/sh\nexec /opt/clang/lib/" + lock["loader"]
                               + " --library-path /opt/clang/lib /opt/clang/bin/clang "
                               + mode + '-resource-dir /opt/clang/resource "$@"\n')
            wrapper.chmod(0o755)
        (stage / "Dockerfile").write_text(
            "FROM " + lock["base_image"] + "\nCOPY tool /opt/clang\n"
            "COPY clang-18 clang++-18 /usr/bin/\n"
            "ENV TMPDIR=/output PYTHONDONTWRITEBYTECODE=1 LC_ALL=C\n"
            "RUN clang-18 --version && clang-18 -dumpmachine\n")
        build(stage, TOOL_IMAGE)


def role(tag=ROLE_IMAGE):
    with tempfile.TemporaryDirectory(prefix="varyroot-role-a-") as tmp:
        stage = Path(tmp)
        (stage / "varyroot").mkdir(mode=0o755)
        for name in RUNTIME_MODULES:
            dest = stage / "varyroot" / (name + ".py")
            shutil.copyfile(ROOT / "varyroot" / dest.name, dest)
            dest.chmod(0o644)
        (stage / "Dockerfile").write_text("FROM " + docker_id(TOOL_IMAGE) +
            "\nCOPY varyroot /opt/role/varyroot\nENV PYTHONPATH=/opt/role\nUSER 65534:65534\nWORKDIR /input\n")
        build(stage, tag)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", choices=("toolchain","role","role07"))
    p.add_argument("--capture", action="store_true")
    a = p.parse_args()
    if a.stage == "toolchain":
        toolchain(a.capture)
    else:
        role("varyroot-agent-a:step07" if a.stage == "role07" else ROLE_IMAGE)
