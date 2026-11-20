"""Run a paired sampling policy with its authorized public inputs."""
import json
import tempfile
from pathlib import Path

from .publication import digest, encode, read_file
from .sandbox import Input, Scope, materialize, resolve_image, run_role
from .selector_container import POLICY

TAG = "varyroot-selector:step06"


def payloads(group, ids, matrix, equivalent, k, rng_seed):
    ids = sorted(ids)
    if group not in ("random", "divergence"):
        raise ValueError("unknown sampling policy")
    if len(set(ids)) != len(ids) or any(type(i) is not str or not i for i in ids):
        raise ValueError("pool requires neutral unique string IDs")
    if type(k) is not int or k < 0:
        raise ValueError("invalid sampling budget")
    policy = dict(group=group, version=POLICY)
    files = {"pool": ids, "budget": k, "policy": policy}
    if group == "random":
        if type(rng_seed) not in (int, str):
            raise ValueError("invalid random seed")
        policy["rng_seed"] = rng_seed
    else:
        files["predictions"] = dict(matrix=matrix, equivalent=sorted(equivalent))
    return files


def select(workdir, group, ids, matrix, equivalent, k, rng_seed):
    files = payloads(group, ids, matrix, equivalent, k, rng_seed)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    job = Path(tempfile.mkdtemp(prefix="selector-", dir=workdir))
    source = job / "source"
    source.mkdir()
    inputs = []
    for key, value in files.items():
        path = source / (key + ".json")
        raw = encode(value)
        path.write_bytes(raw)
        kind = "prediction" if key == "predictions" else key
        inputs.append(Input(key + "@1", path.name, kind, digest(raw), len(raw), group=group))
    scope = Scope("sampling", "pool", group, "repeat", group, "select", "sample", "one")
    attempt = job / "role"
    manifest = materialize(attempt, source, scope, inputs)
    image_id = resolve_image(TAG)
    proc = run_role(attempt, ["python", "-I", "-B", "/opt/selector/selector_container.py"], image=image_id)
    if proc.returncode:
        raise RuntimeError("selector failed: " + proc.stderr[-2000:])
    raw = read_file(attempt / "output" / "selection.json")
    result = json.loads(raw)
    audit = json.loads(read_file(attempt / "output" / "audit.json"))
    expected = sorted(["input_manifest.json", *(i.path for i in inputs)])
    if (audit["input_files"] != expected or "ro" not in audit["mounts"]["/input"]
            or "ro" not in audit["mounts"]["/"] or audit["interfaces"] != ["lo"] or not audit["uid"]
            or audit["image_modules"] != ["selector_container.py"]):
        raise ValueError("unexpected runtime selector view")
    chosen = result["selected"]
    if len(set(chosen)) != len(chosen) or len(chosen) > k or not set(chosen) <= set(files["pool"]):
        raise ValueError("invalid role selection")
    audit.update(image=image_id, manifest_sha256=manifest, selection_sha256=digest(raw),
                 input_sha256={i.path: i.sha256 for i in inputs}, attempt_dir=str(attempt))
    return dict(result, audit=audit)
