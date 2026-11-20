"""Verify VM exports and build project-private immutable namespace image locks."""
import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from varyroot.sandbox import rootfs_fingerprint

PROJECT = Path(__file__).resolve().parents[2]
SOURCE_LOCK = PROJECT / "tools/namespace/source-lock.json"
DESTINATION = PROJECT / "toolchains/namespace-v1"


def sha256(path):
    with path.open("rb") as reader:
        return hashlib.file_digest(reader, "sha256").hexdigest()


def extract_verified(archive, destination):
    """Extract a locked export, allowing absolute links inside the future rootfs."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        names = {}
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not name.parts:
                raise ValueError("unsafe archive path")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError("unsupported archive member")
            if name in names:
                raise ValueError("duplicate archive path")
            names[name] = member
        links = {name for name, member in names.items() if member.issym()}
        for name, member in names.items():
            if any(parent in links for parent in name.parents):
                raise ValueError("symlink parent in archive")
            if member.islnk():
                target = PurePosixPath(member.linkname)
                if (target.is_absolute() or ".." in target.parts or target not in names
                        or names[target].issym() or
                        any(parent in links for parent in target.parents)):
                    raise ValueError("unsafe hardlink")
        destination.mkdir()
        tar.extractall(destination, filter="tar")


def run():
    source = json.loads(SOURCE_LOCK.read_text())
    if source.get("schema") != 1:
        raise ValueError("invalid source lock")
    archives = DESTINATION / "export"
    images = {}
    for tag, spec in source["images"].items():
        archive = archives / spec["archive"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", spec["image_id"]):
            raise ValueError("invalid image ID")
        if sha256(archive) != spec["tar_sha256"]:
            raise ValueError("image export digest mismatch: " + tag)
        sidecar = archives / spec["archive"].replace(".tar.gz", ".image_id")
        if sidecar.read_text().strip() != spec["image_id"]:
            raise ValueError("image ID sidecar mismatch: " + tag)
        rootfs = DESTINATION / spec["archive"].removesuffix(".tar.gz")
        if rootfs.exists():
            if rootfs.is_symlink() or rootfs.parent.resolve() != DESTINATION.resolve():
                raise ValueError("unsafe rootfs cleanup")
            shutil.rmtree(rootfs)
        extract_verified(archive, rootfs)
        # Docker creates bind targets at container launch; bwrap needs them
        # present in the exported rootfs before its read-only root bind.
        for mountpoint in ("work", "output"):
            (rootfs / mountpoint).mkdir(exist_ok=True)
        record = dict(image_id=spec["image_id"], tar_sha256=spec["tar_sha256"],
                      rootfs=rootfs.relative_to(PROJECT).as_posix(),
                      rootfs_digest=rootfs_fingerprint(rootfs))
        images[tag] = record
    target = DESTINATION / "image-lock.json"
    data = (json.dumps({"schema": 1, "images": images}, sort_keys=True, indent=2) + "\n").encode()
    temporary = target.with_suffix(".json.tmp")
    with temporary.open("wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, target)
    print(json.dumps({"lock": str(target), "images": images}, sort_keys=True))


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    run()
