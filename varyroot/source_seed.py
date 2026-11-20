"""Coordinator entry for the real, pending-only source frontend (Step 04)."""
import argparse
import json
import subprocess
import uuid
from pathlib import Path

from .cli_runner import run_cli
from .ledger import Ledger, LedgerError
from .publication import digest, encode, put, read_file, validate_json
from .sandbox import Input, Scope, materialize, resolve_image, run_role

ROLE_IMAGE = "varyroot-agent-a:step04"
ROLE_IMAGE_07 = "varyroot-agent-a:step07"
REAL_ADAPTER = "openldap_real_v1"
REAL_INPUTS = {
    "proposal.json": "seed",
    "before-canonical.tar.gz": "source",
    "after-canonical.tar.gz": "source",
    "openldap-include.tar.gz": "contract",
    "ubuntu24-libc-headers.tar.gz": "source",
    "curl_config_openldap.h": "source",
    "contract.json": "contract",
    "source-lock.json": "contract",
    "getattr.c": "contract",
    "openldap_role.py": "source",
}


def grants(manifest):
    """The trusted host selects this catalog; the proposal itself cannot grant another file."""
    if not isinstance(manifest, dict):
        raise ValueError("unsupported source catalog")
    adapter = manifest.get("adapter")
    allowed = {"schema_version", "seed", "files"} | ({"adapter"} if adapter == REAL_ADAPTER else set())
    if (set(manifest) != allowed or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or not isinstance(manifest["seed"], str)
            or not manifest["seed"] or not isinstance(manifest["files"], list)):
        raise ValueError("unsupported source catalog")
    items = [Input(**entry) for entry in manifest["files"]]
    if adapter == REAL_ADAPTER:
        if {i.path: i.kind for i in items} != REAL_INPUTS or len(items) != len(REAL_INPUTS):
            raise ValueError("incomplete or extra OpenLDAP source grant")
    else:
        if not items or any(i.kind not in {"seed", "source", "contract", "domain", "target"} for i in items):
            raise ValueError("unsupported Agent A input kind")
        if [i.path for i in items if i.kind == "seed"] != ["proposal.json"]:
            raise ValueError("one seed proposal is required")
    return items


def prepare_seed(workspace, catalog, run_id, *, role_image=ROLE_IMAGE):
    from .agent_a import ledger_inputs

    if role_image not in (ROLE_IMAGE, ROLE_IMAGE_07):
        raise ValueError("unregistered seed role")
    root = Path(workspace).resolve()
    catalog = Path(catalog).resolve(strict=True)
    manifest = json.loads(read_file(catalog))
    items = grants(manifest)
    image_id = resolve_image(role_image)
    request = digest(encode({"run": run_id, "catalog": manifest, "image": image_id}))
    db = Ledger(root)
    run = db.create_run(run_id, "development", seed=manifest["seed"])

    def committed():
        entry = db.seed_package(run_id, version=1)
        ingress = entry["packet"]["ingress"]
        if ingress["request"] != request:
            raise LedgerError("different inputs or image for this seed run")
        if digest(read_file(root / "seed-objects" / ingress["role_output_sha"])) != ingress["role_output_sha"]:
            raise LedgerError("committed seed payload digest mismatch")
        return {"run": run_id, "state": db.run(run_id)["state"], "initial_package_version": 1,
                "seed_sha": ingress["role_output_sha"], "package_sha": entry["packet_sha"],
                "input_manifest_sha": ingress["manifest_sha"], "image": image_id}

    if run["state"] != "draft":
        return committed()
    snapshot = db.snapshot(run_id)
    parent = root / "source-attempts" / request
    parent.mkdir(parents=True, exist_ok=True)
    finished = {}

    def invoke(number):
        folder = parent / (str(number) + "-" + uuid.uuid4().hex)
        scope = Scope(run_id, manifest["seed"], "development", 0, "A", "seed", request,
                      folder.name, snapshot["watermark"])
        sha = materialize(folder, catalog.parent, scope, items)
        db.record_manifest(run_id, "A", sha, expected_snapshot=snapshot["digest"])
        try:
            command = (["python", "/input/openldap_role.py"] if manifest.get("adapter") == REAL_ADAPTER
                       else ["python", "-m", "varyroot.agent_a"])
            proc = run_role(folder, command, image=image_id, timeout=120)
        finally:
            audit_path = folder / "execution.json"
            if audit_path.exists():
                with db.tx() as c:
                    db.event(c, run_id, "role.execution", json.loads(audit_path.read_bytes()))
        finished.update(folder=folder, manifest_sha=sha)
        return proc

    run_cli(invoke)
    raw = read_file(finished["folder"] / "output" / "seed.json")
    seed = validate_json(raw)
    if (seed.get("run_ref") != run_id or seed.get("seed_id") != manifest["seed"]
            or seed.get("state") != "seed_pending" or seed.get("version") != 1
            or any(key not in seed or seed[key] is not None for key in
                   ("before_verdict_ref", "after_verdict_ref", "candidate_check_ref"))
            or "ingress" in seed):
        raise ValueError("role output does not match the pending seed request")
    objects = root / "seed-objects"
    objects.mkdir(exist_ok=True)
    sha = digest(raw)
    put(objects / sha, raw)
    artifacts, roles = ledger_inputs(seed)
    packet = dict(seed, ingress={"request": request, "manifest_sha": finished["manifest_sha"],
                                 "role_output_sha": sha, "image": image_id})
    try:
        db.bind_seed(run_id, run["version"], packet, artifacts=artifacts, roles=roles)
    except LedgerError:
        if db.run(run_id)["state"] == "draft":
            raise
        # A different concurrent invocation may have published the very same request.
        return committed()
    return committed()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_seed(args.workspace, args.catalog, args.run_id), sort_keys=True))


if __name__ == "__main__":
    main()
