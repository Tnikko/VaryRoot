"""Content-address a coordinator-owned directory and restore exactly its recorded files."""
import hashlib
import json
import os
import re

import stat
import tempfile
from pathlib import Path

from .ledger import _check, _digest
from .publication import encode, sync_dir

MANIFEST = "freeze-manifest.json"


def _name(name):
    parts = name.split("/") if isinstance(name, str) else []
    _check(parts and all(re.fullmatch(r"[A-Za-z0-9._+-]+", p) and p not in (".", "..")
                         and not p.endswith(".") and p.split(".")[0].upper() not in
                         {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                          *(f"LPT{i}" for i in range(1, 10))} for p in parts),
           "unsafe archive path")
    _check(parts[0].lower() != MANIFEST, "reserved archive path")


def _regular(path):
    _check(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "expected regular archive file")


def _stream(source, destination=None):
    _regular(source)
    h = hashlib.sha256()
    with source.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
            if destination is not None:
                destination.write(block)
    return h.hexdigest()


def _copy(source, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as output:
        sha = _stream(source, output)
        output.flush()
        os.fsync(output.fileno())
    return sha


def _sync_tree(root):
    for parent, _, _ in os.walk(root, topdown=False):
        sync_dir(parent)


def _inventory(root):
    _check(root.is_dir() and not root.is_symlink(), "expected archive directory")
    files = set()
    spellings = {}
    for parent, dirs, names in os.walk(root, followlinks=False, onerror=_raise):
        for name in dirs + names:
            path = Path(parent) / name
            _check(not path.is_symlink(), "link in archive")
            rel = path.relative_to(root).as_posix()
            _check(spellings.setdefault(rel.casefold(), rel) == rel, "case-colliding archive path")
            if rel != MANIFEST:
                _name(rel)
            if name in names:
                _regular(path)
                files.add(rel)
    return files


def _raise(error):
    raise error


def build_archive(directory, files):
    """Publish a staged directory atomically. Identical retries reuse the original."""
    root = Path(directory)
    root.parent.mkdir(parents=True, exist_ok=True)
    _check(isinstance(files, dict) and files, "empty archive")
    seen = {}
    for name in files:
        _name(name)
        parts = name.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            _check(seen.setdefault(prefix.casefold(), prefix) == prefix, "case-colliding archive path")
    with tempfile.TemporaryDirectory(dir=root.parent, prefix=".freeze-") as tmp:
        stage = Path(tmp) / "archive"
        stage.mkdir()
        entries = {name: _copy(Path(src), stage / name) for name, src in sorted(files.items())}
        raw = encode(dict(schema_version=1, algorithm="sha256", files=entries))
        with (stage / MANIFEST).open("xb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        sha = hashlib.sha256(raw).hexdigest()
        _sync_tree(stage)
        if not root.exists():
            try:
                stage.rename(root)
            except OSError:
                if not root.exists():
                    raise
            sync_dir(root.parent)
        verify_archive(root, sha)
    return sha


def verify_archive(directory, expected_sha=None):
    root = Path(directory)
    inventory = _inventory(root)
    _check(MANIFEST in inventory, "missing archive manifest")
    raw = (root / MANIFEST).read_bytes()
    if expected_sha is not None:
        _digest(expected_sha)
        _check(hashlib.sha256(raw).hexdigest() == expected_sha, "archive manifest digest mismatch")
    data = json.loads(raw)
    _check(type(data) is dict and data.keys() == {"schema_version","algorithm","files"}
           and type(data["schema_version"]) is int and data["schema_version"] == 1
           and data["algorithm"] == "sha256" and raw == encode(data), "invalid archive manifest")
    entries = data["files"]
    _check(isinstance(entries, dict) and entries and set(entries) == inventory - {MANIFEST},
           "missing or unlisted archive file")
    for name, sha in entries.items():
        _name(name)
        _digest(sha)
        _check(_stream(root / name) == sha, "archive digest mismatch: " + name)
    return entries


def restore_archive(directory, expected_sha, empty_destination):
    """Restore atomically into a fresh or empty sibling-staged directory."""
    root, dest = Path(directory), Path(empty_destination)
    _digest(expected_sha)
    entries = verify_archive(root, expected_sha)
    _check(not dest.is_symlink() and (not dest.exists() or dest.is_dir() and not any(dest.iterdir())),
           "restore requires empty destination")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".restore-") as tmp:
        stage = Path(tmp) / "archive"
        stage.mkdir()
        for name, sha in entries.items():
            _check(_copy(root / name, stage / name) == sha, "source changed during restore")
        _check(_copy(root / MANIFEST, stage / MANIFEST) == expected_sha, "manifest changed during restore")
        _sync_tree(stage)
        stage.replace(dest)
        sync_dir(dest.parent)
    return dest
