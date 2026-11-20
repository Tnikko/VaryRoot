"""Step 03 synthetic file protocol. Run in a new directory on the Linux filesystem."""
import argparse
import copy
import json
import subprocess
from pathlib import Path

from .cli_runner import run_cli, run_request
from .ledger import ContractFixtureLedger as Ledger, pool_hash
from .publication import Publication, digest, encode, put, read_file, validate_json
from .sandbox import Input, Scope, materialize, run_role, resolve_image, ROLE_IMAGE

ROUTES = ("revise", "keep", "unresolved", "gap")
CASE_IDS = {route: f"test-case-{index:02}" for index, route in enumerate(ROUTES, 1)}
FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "m1"


def fixtures(route):
    records = json.loads((FIXTURE / "records.json").read_text())
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    width = 2 if route == "unresolved" else 3
    next(r for r in records if r["id"] == "f.width")["typed_operands"]["value"] = width
    files = {}
    for version in ("initial", "candidate"):
        rows, request = copy.deepcopy(records), manifest.copy()
        guard = next(r for r in rows if r["kind"] == "Clause" and r["field"] == "Guard")
        spec = next(r for r in rows if r["kind"] == "Spec")
        if route != "keep" and version == "initial":
            offset = guard["antecedent"]["args"][1]
            guard.update(antecedent={"op": "lt", "args": [offset, {"var": "capacity"}]},
                         direction="sufficient")
        if route != "keep" and version == "candidate":
            guard.update(version=2, spec_version=2)
            spec.update(version=2, clause_refs=[x if x != "c.guard@1" else "c.guard@2"
                                                for x in spec["clause_refs"]])
            request["spec_ref"] = "s@2"
        files[version + "/manifest.json"] = ("bundle_manifest", request)
        files[version + "/records.json"] = ("bundle_records", rows)
    files["case.json"] = ("case", {"id": CASE_IDS[route], "offset": 6, "width": width,
                                   "capacity": 8, "complete": route != "unresolved", "target": "t@1"})
    files["backend.json"] = ("database", {"observed": [route == "keep", route != "gap"],
                                          "gap": "width_unavailable" if route == "gap" else None})
    return files


class ContractRun:
    def __init__(self, workspace, route, image):
        self.image = image
        self.scenario = route
        self.run = "test:" + CASE_IDS[route]
        self.group = "contract"
        self.root = Path(workspace) / route
        self.root.mkdir(mode=0o700)
        self.catalog = self.root / "catalog"
        self.catalog.mkdir()
        self.db = Ledger(self.root)
        self.pub = Publication(self.db, lease_seconds=90)
        self.db.create_run(self.run, self.group, seed="test:interval", verify=1, repair=1)
        self.files = {}
        for name, (kind, obj) in fixtures(route).items():
            self.store(name, kind, obj)
        self.bundles = [name for name in self.files if "/" in name]

    def store(self, name, kind, obj, phase="seed", reveal_seq=None):
        path = self.catalog / name
        path.parent.mkdir(exist_ok=True)
        data = encode(obj)
        put(path, data)
        self.files[name] = Input(name.replace("/", "-") + "@1", name, kind, digest(data), len(data),
                                 self.group, phase, reveal_seq)

    def advance(self, target, detail):
        self.db.transition(self.run, self.db.run(self.run)["version"], target, detail)

    def launch(self, role, phase, names, worker, request, number):
        snap = self.db.snapshot(self.run)
        for name in names:
            item = self.files[name]
            if item.kind == "evidence" and not any(m["seq"] == item.reveal_seq and
                    m["digest"] == item.sha256 for m in snap["members"]):
                raise ValueError("evidence digest outside this run's reveals")
        scope = Scope(self.run, "test:interval", self.group, 0, role, phase, request, number, snap["watermark"])
        attempt = self.root / (worker + "-" + str(number))
        sha = materialize(attempt, self.catalog, scope, [self.files[n] for n in names])
        self.db.record_manifest(self.run, role, sha, expected_snapshot=snap["digest"])
        proc = run_role(attempt, ["python", "-m", "varyroot.contract_role", worker], image=self.image)
        return proc, attempt, sha

    def stage(self, role, phase, names, worker, output, kind):
        completed = {}
        def invoke(number):
            proc, folder, _ = self.launch(role, phase, names, worker, "test:" + worker, number)
            completed["folder"] = folder
            return proc
        run_cli(invoke)
        obj = validate_json(read_file(completed["folder"] / "output" / output))
        self.store(output, kind, obj, phase)
        return obj

    def execute(self):
        self.advance("seed_pending", {"seed": "test:interval"})
        seed = self.stage("A", "seed", self.bundles, "A", "seed.json", "seed")
        self.advance("seed_accepted", {"fixture_gate": seed, "seed_sha": self.files["seed.json"].sha256})
        registration_context = self.db.snapshot(self.run)["digest"]
        pred = self.stage("B", "select", ["seed.json", *self.bundles], "predict",
                          "predictions.json", "prediction")
        case = json.loads((self.catalog / "case.json").read_bytes())
        item = {"case": case["id"], "target": seed["target"], "contract": seed["contract"],
                "domain": seed["domain"], "verifier": "test:interval-v1",
                "input_sha": self.files["case.json"].sha256}
        pool = pool_hash([item])
        row = self.db.register(self.run, self.db.run(self.run)["version"], "b1", pool,
                               self.files["predictions.json"].sha256, registration_context,
                               pool_cases=[item])
        req, = self.db.select(self.run, "select-b1", row["version"], "b1", pool, [item])
        manifests = {}

        def verify(attempt):
            n = attempt["attempt_id"]
            proc, folder, sha = self.launch("verifier", "verify", ["case.json"], "verifier", req, n)
            manifests[n] = (folder, sha)
            return proc

        def evidence(attempt, proc):
            folder, sha = manifests[attempt["attempt_id"]]
            value = validate_json(read_file(folder / "output" / "evidence.json"))
            if (set(value) != {"case", "target", "label", "input_manifest_sha", "reached", "observed_state"}
                    or value["input_manifest_sha"] != sha or type(value["reached"]) is not bool
                    or not isinstance(value["observed_state"], str) or value["case"] != case["id"]
                    or value["target"] != seed["target"] or value["label"] not in ("positive","negative","pending")):
                raise ValueError("verifier result does not bind selected case and target")
            return value

        ready = run_request(self.pub, req, verify, evidence)
        if ready["action"] != "ready":
            raise RuntimeError("verification ended with " + ready["action"])
        self.db.deliver(self.run, "b1", {req: ready["digest"]})
        self.store("evidence.json", "evidence", self.pub.read(req), "decide", self.db.snapshot(self.run)["watermark"])
        handoff = self.stage("B", "decide", [*self.bundles, "predictions.json", "evidence.json"],
                             "B", "handoff.json", "handoff")
        summary = {k: handoff[k] for k in ("action", "baseline", "final", "revision_ref")}
        summary["handoff_sha"] = self.files["handoff.json"].sha256
        if handoff["action"] == "unresolved":
            self.advance("unresolved", dict(summary, reason="pending_evidence"))
            result = {"state":"unresolved", "freeze_id":None}
        else:
            self.advance("spec_ready", summary)
            self.advance("regressing", {"database": self.files["backend.json"].sha256})
            result = self.stage("C", "regress", ["predictions.json", "evidence.json", "handoff.json", "backend.json"],
                                "C", "result.json", "spec")
            if result["state"] == "frozen":
                self.advance("frozen", {"reason":"contract_gate_pass","test_freeze_id":result["freeze_id"],
                                        "baseline_pass":result["baseline_pass"],"final_pass":result["final_pass"],
                                        "result_sha":self.files["result.json"].sha256})
            else:
                self.advance("partial", {"reason":"backend_gap","gap":result["backend_gap"]})
        return {"run": self.run, "scenario": self.scenario, "image_id": self.image, "decision": summary, "terminal": result, "balances":self.db.balances(self.run),
                "events":self.db.events(self.run), "predictions": {k:v["outcome"] for k,v in pred.items()},
                "artifacts": {k:v.sha256 for k,v in self.files.items()}}


def replay(workspace):
    root = Path(workspace)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    image = resolve_image(ROLE_IMAGE)
    chains = [ContractRun(root, route, image).execute() for route in ROUTES]
    expected = ["frozen", "frozen", "unresolved", "partial"]
    for chain, state in zip(chains, expected, strict=True):
        if chain["terminal"]["state"] != state or bool(chain["terminal"]["freeze_id"]) != (state == "frozen"):
            raise AssertionError((chain["run"], chain["terminal"]))
        if chain["balances"]["B.verify"] != 0 or (state == "unresolved" and "result.json" in chain["artifacts"]):
            raise AssertionError("budget or unresolved handoff regression")
    (root / "chains.json").write_text(json.dumps(chains, indent=2) + "\n")
    return chains


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace")
    parser.add_argument("--seed-inputs", type=Path, help="use the real A worker and hand off at seed_pending")
    parser.add_argument("--run-id", help="versioned source-seed run identity")
    args = parser.parse_args()
    if args.seed_inputs is not None:
        if not args.run_id:
            parser.error("--seed-inputs requires --run-id")
        from .source_seed import prepare_seed
        print(json.dumps(prepare_seed(args.workspace, args.seed_inputs, args.run_id), sort_keys=True))
    else:
        if args.run_id:
            parser.error("--run-id requires --seed-inputs")
        for chain in replay(args.workspace):
            print(chain["run"], chain["decision"]["action"], chain["terminal"]["state"], chain["balances"])
