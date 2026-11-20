"""Replay a content-addressed, paired CodeQL freeze in an empty offline Docker container."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import zipfile

MANIFEST = "freeze-manifest.json"
LANES = ("Q0", "Qstar")
MODULES = ("__init__", "agent_c", "artifacts", "checks", "coordinates", "handoff", "ir",
           "publication", "registered_cases")
SCRIPTS = ("tools/codeql07/replay.py", "tools/codeql07/runner.py")


def replay_files(repo):
    paths = list(SCRIPTS) + [f"varyroot/{m}.py" for m in MODULES]
    return {"replay/" + name: Path(repo) / name for name in paths}


def check(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with path.open("rb") as stream:
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verified_files(root, expected):
    """Authenticate the inventory before importing or executing any archived Python."""
    check(not root.is_symlink() and root.is_dir(), "invalid archive directory")
    manifest = root / MANIFEST
    check(manifest.is_file() and not manifest.is_symlink() and sha(manifest) == expected,
          "archive manifest digest mismatch")
    data = json.loads(manifest.read_bytes())
    check(data["schema_version"] == 1 and data["algorithm"] == "sha256", "unknown archive schema")
    files = data["files"]
    actual = set()
    for path in root.rglob("*"):
        check(not path.is_symlink(), "link in frozen inventory")
        if not path.is_dir():
            check(path.is_file(), "non-regular frozen file")
            actual.add(path.relative_to(root).as_posix())
    check(actual == set(files) | {MANIFEST} and MANIFEST not in files, "incomplete or extra archive files")
    for name, expected_file in files.items():
        check(sha(root / name) == expected_file, f"archive digest mismatch: {name}")
    required = set(replay_files(Path("."))) | {"database.zip", "toolchain.json", "c1.json", "c4.json",
             "c5.json", "handoff/b6.json", "handoff/manifest.json", "handoff/records.json",
             "queries/qlpack.yml", "budget.json"}
    if "queries/nullable_output.qll" in actual:
        required.update(("queries/nullable_output.qll", "queries/contract.qll"))
    else:
        required.add("queries/shared.qll")
    for lane in LANES:
        required.update((f"queries/{lane}.ql", f"results/{lane}.status.json",
                         f"results/{lane}.csv", f"results/{lane}.bqrs"))
    check(required <= actual, "missing replay dependencies: " + ", ".join(sorted(required - actual)))
    return files


def unpack_database(bundle, destination):
    destination.mkdir()
    with zipfile.ZipFile(bundle) as archive:
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            kind = stat.S_IFMT(member.external_attr >> 16)
            check(path.parts and not path.is_absolute() and ".." not in path.parts
                  and "\\" not in member.filename and kind in (0, stat.S_IFDIR, stat.S_IFREG),
                  "unsafe database entry")
            dest = destination.joinpath(*path.parts)
            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, dest.open("xb") as out:
                    shutil.copyfileobj(src, out)
    configs = list(destination.rglob("codeql-database.yml"))
    check(len(configs) == 1, "expected one restored database")
    return configs[0].parent


def csv_rows(path):
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream, strict=True)
        return next(reader), sorted(tuple(row) for row in reader)


def environment():
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        parts = left.split()
        mounts[parts[4]] = {"options": parts[5].split(","), "filesystem": right.split()[0]}
    for point in ("/", "/bundle", "/toolchain"):
        check("ro" in mounts[point]["options"], f"{point} must be read-only")
    for point in ("/work", "/tmp"):
        check(mounts[point]["filesystem"] == "tmpfs", f"{point} must be private tmpfs")
    check("rw" in mounts["/out"]["options"], "output is not writable")
    check(os.getuid() != 0 and os.getcwd() == "/work", "invalid replay user or working directory")
    check(not any(Path("/work").iterdir()) and not any(Path("/out").iterdir()), "workspace not empty")
    check(sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"], "network not isolated")
    check(not Path("/var/run/docker.sock").exists(), "host Docker socket visible")
    return dict(uid=os.getuid(), mounts=mounts, interfaces=["lo"], initial_workspace=[],
                initial_output=[], docker_socket_visible=False)


def inside(expected, image):
    proof = environment()
    root, work, output, tools = map(Path, ("/bundle", "/work", "/out", "/toolchain"))
    files = verified_files(root, expected)
    lock = json.loads((root / "toolchain.json").read_bytes())
    check(lock["runtime_image"] == image and files["database.zip"] == lock["database_sha256"],
          "runtime or database binding mismatch")
    # Import only the authenticated copies, before site modules from the image.
    sys.path[:0] = [str(root / "replay"), str(root / "replay/tools/codeql07")]
    from runner import Engine, save, tree_sha
    from varyroot.agent_c import verify_outputs, regression

    check(tree_sha(tools) == lock["tool_tree_sha256"], "locked tool tree differs")
    ledger_paths = [name for name in files if Path(name).suffix in (".sqlite", ".sqlite3", ".db")]
    check(not ledger_paths, "original ledger included in archive")
    stage = work / "artifacts"
    stage.mkdir()
    for name in ("queries", "handoff"):
        shutil.copytree(root / name, stage / name)
    shutil.copyfile(root / "toolchain.json", stage / "toolchain.json")
    db = unpack_database(root / "database.zip", work / "restore")
    engine = Engine(tools, work / "engine")
    try:
        engine.execute(stage, db, lock)
    finally:
        save(output / "commands.json", engine.commands)
    comparisons = {}
    for lane in LANES:
        original = root / "results" / (lane + ".csv")
        repeated = stage / "results" / (lane + ".csv")
        status = json.loads((stage / "results" / (lane + ".status.json")).read_bytes())
        check(status["completed"] and status["exit_code"] == 0, f"{lane} replay did not complete")
        check(csv_rows(original) == csv_rows(repeated), f"{lane} decoded result differs")
        comparisons[lane] = dict(frozen_csv=sha(original), replay_csv=sha(repeated),
                                 frozen_bqrs=files[f"results/{lane}.bqrs"],
                                 replay_bqrs=sha(repeated.with_suffix(".bqrs")), csv_multiset_equal=True)
    c1 = json.loads((root / "c1.json").read_bytes())
    c4 = verify_outputs(stage, c1)
    c5 = regression(c1, c4)
    for name, obj in (("c4", c4), ("c5", c5)):
        check(obj == json.loads((root / (name + ".json")).read_bytes()), f"{name} differs")
        save(output / (name + ".json"), obj)
    check(c5["route"] == "freeze", "paired regression is not frozen")
    proof.update(manifest_sha256=expected, verified_files=len(files), runtime_image=image,
                 database_sha256=files["database.zip"], tool_tree_sha256=lock["tool_tree_sha256"],
                 replay_sources={key: files[key] for key in replay_files(Path("."))},
                 mounted_host_inputs=["/bundle", "/toolchain"], mounted_host_output="/out",
                 ledger_files_in_archive=ledger_paths, comparison=comparisons,
                 c4_sha256=sha(output / "c4.json"), c5_sha256=sha(output / "c5.json"), route=c5["route"])
    save(output / "replay-proof.json", proof)


def launch(archive, expected, tools, output):
    files = verified_files(archive, expected)
    script = Path(__file__).resolve()
    check(sha(script) == files["replay/tools/codeql07/replay.py"], "launcher differs from frozen replay source")
    lock = json.loads((archive / "toolchain.json").read_bytes())
    image = lock["runtime_image"]
    check(re.fullmatch("sha256:[a-f0-9]{64}", image), "runtime image must be immutable")
    actual_image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True)
    check(actual_image.strip() == image, "installed runtime image differs")
    check(tools.is_dir(), "missing tool directory")
    paths = [p.resolve() for p in (archive, tools, output)]
    check(all(x != y and x not in y.parents and y not in x.parents
              for i, x in enumerate(paths) for y in paths[i + 1:]), "mounts must be disjoint")
    uid = int(os.environ.get("SUDO_UID", os.getuid())) or 65534
    gid = int(os.environ.get("SUDO_GID", os.getgid())) or 65534
    output.mkdir(parents=True, exist_ok=True)
    check(not any(output.iterdir()), "output directory must be empty")
    if os.getuid() == 0:
        os.chown(output, uid, gid)
    cmd = ["docker", "run", "--rm", "--pull=never", "-i", "--network=none", "--read-only",
           "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", f"{uid}:{gid}",
           "--tmpfs", f"/work:rw,exec,mode=0700,uid={uid},gid={gid}", "--tmpfs", "/tmp:rw,exec,mode=1777",
           "--workdir", "/work", "--env", "HOME=/work", "--env", "PYTHONDONTWRITEBYTECODE=1"]
    for src, dest, ro in zip(paths, ("bundle", "toolchain", "out"), (True, True, False)):
        check("," not in str(src), "comma in Docker mount path")
        cmd.extend(["--mount", f"type=bind,src={src},dst=/{dest}" + (",readonly" if ro else "")])
    cmd.extend(["--entrypoint", "python3", image, "-I", "-B", "-", "--inside", expected, image])
    subprocess.run(cmd, input=script.read_bytes(), check=True)
    check((output / "replay-proof.json").is_file(), "missing replay proof")
    return output / "replay-proof.json"


if __name__ == "__main__":
    if sys.argv[1:2] == ["--inside"]:
        inside(*sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("archive", type=Path)
        parser.add_argument("manifest_sha256")
        parser.add_argument("toolchain", type=Path)
        parser.add_argument("output", type=Path)
        args = parser.parse_args()
        print(launch(args.archive, args.manifest_sha256, args.toolchain, args.output))
