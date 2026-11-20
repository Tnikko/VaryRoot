"""Admit only build captures of the pinned original target translation unit."""

import re
import hashlib
import json
import shlex
import subprocess
from pathlib import Path, PurePosixPath


TARGET = PurePosixPath("src/dissectors/ec_vnc.c")


def capture_compile_commands(database_path: Path, source_path: Path, exit_code: int) -> dict:
    source_path = source_path.resolve()
    matches = []
    for row in json.loads(database_path.read_text()):
        candidate = Path(row["directory"], row["file"]).resolve()
        if candidate == source_path:
            matches.append(row)
    if len(matches) != 1:
        raise ValueError("target_translation_unit")
    row = matches[0]
    argv = row.get("arguments") or shlex.split(row["command"])
    capture = {
        "directory": row["directory"],
        "source_path": source_path.as_posix(),
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "argv": argv,
        "exit_code": exit_code,
    }
    return validate_capture(capture, capture["source_sha256"])


def run_target_compile(database_path: Path, source_path: Path) -> dict:
    capture = capture_compile_commands(database_path, source_path, exit_code=0)
    completed = subprocess.run(capture["argv"], cwd=capture["directory"],
                               capture_output=True, text=True, timeout=120, check=False)
    return dict(capture, exit_code=completed.returncode,
                stdout=completed.stdout, stderr=completed.stderr)


def validate_capture(capture: dict, expected_sha256: str) -> dict:
    if capture.get("exit_code") != 0:
        raise ValueError("compile_failed")
    source = PurePosixPath(str(capture.get("source_path", "")))
    if tuple(source.parts[-len(TARGET.parts):]) != TARGET.parts:
        raise ValueError("target_translation_unit")
    actual_digest = capture.get("source_sha256")
    if (not isinstance(actual_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", actual_digest)
            or actual_digest != expected_sha256):
        raise ValueError("source_digest")
    argv = capture.get("argv")
    if not isinstance(argv, list) or str(source) not in argv or "-c" not in argv:
        raise ValueError("target_translation_unit")
    return capture
