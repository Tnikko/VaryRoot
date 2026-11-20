"""Offline role contracts for Step 03. Inputs and outputs are synthetic test artifacts."""
import hashlib
import json
import re
import tempfile
import subprocess
import sys
from pathlib import Path

INPUT = Path("/input")
OUTPUT = Path("/output")


def read(name):
    return json.loads((INPUT / name).read_text())


def save(name, obj):
    (OUTPUT / name).write_text(canonical(obj))


def invoke(*args):
    process = subprocess.run([sys.executable, "-m", "varyroot", *args],
                             capture_output=True, text=True)
    if process.returncode:
        sys.stdout.write(process.stdout)
        sys.exit(process.returncode)
    return json.loads(process.stdout)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def record(kind, name, **fields):
    return dict(kind=kind, schema_version=1, id="test." + name, version=1,
                run_ref="test:step03", producer="contract.fixture", depends_on=[], **fields)


def ref(row):
    return f"{row['id']}@{row['version']}"


def validate_envelope(manifest, records):
    require(manifest["files"] == ["records.json"], "unexpected bundle file list")
    with tempfile.TemporaryDirectory(dir=OUTPUT) as scratch:
        root = Path(scratch)
        (root / "records.json").write_text(canonical(records), encoding="utf8")
        path = root / "manifest.json"
        path.write_text(canonical(manifest), encoding="utf8")
        invoke("validate", str(path))


def load_versions(predictions):
    manifests, records = {}, {}
    for version in ("initial", "candidate"):
        manifest = read(version + "/manifest.json")
        require(manifest["files"] == ["records.json"], "unexpected bundle file list")
        target, = manifest["target_refs"]
        # The stored preregistration must match the independently replayed interpreter output.
        require(invoke("explain", str(INPUT / version / "manifest.json"), target) == predictions[version],
                "registered prediction differs from source bundle")
        manifests[version] = manifest
        for row in read(version + "/records.json"):
            key = ref(row)
            require(records.setdefault(key, row) == row, "different bytes for a shared version")
    initial, candidate = (manifests[v] for v in ("initial", "candidate"))
    require(initial | {"spec_ref": candidate["spec_ref"]} == candidate,
            "prediction versions do not share the same observation context")
    return initial, list(records.values())


def build_decision(manifest, pred, evidence, source):
    target, = manifest["target_refs"]
    require(evidence["target"] == target, "verdict target mismatch")
    require(isinstance(evidence["case"], str) and evidence["case"] and
            type(evidence["reached"]) is bool and isinstance(evidence["observed_state"], str)
            and evidence["observed_state"], "invalid verifier observation")
    require(re.fullmatch(r"[0-9a-f]{64}", evidence["input_manifest_sha"]), "invalid verifier input digest")
    label = evidence["label"]
    require(label in {"positive", "negative", "pending"}, "unknown verifier label")
    scope = dict(target_ref=target, contract_ref=manifest["contract_ref"], domain_ref=manifest["domain_ref"])
    expected = {"positive": "report", "negative": "quiet"}.get(label)
    p0, p1 = (pred[v]["outcome"] for v in ("initial", "candidate"))
    baseline, candidate = (pred[v]["spec_ref"] for v in ("initial", "candidate"))
    require(baseline == manifest["spec_ref"], "baseline identity mismatch")
    if expected is None:
        action = "unresolved"
    elif p0 == expected:
        action = "keep"
    elif p1 == expected:
        action = "revise"
    else:
        action = "unresolved"
    final = {"keep": baseline, "revise": candidate, "unresolved": None}[action]
    registration = record("Evidence", "registration", description=canonical(pred))
    facts = record("Snapshot", "fact_snapshot", files={"fact_refs.json": canonical(manifest["fact_refs"])})
    facts["depends_on"] = manifest["fact_refs"]
    basis = record("Evidence", "verifier_payload", description=canonical(evidence))
    observed = record("Observation", "observation", **scope, request_ref=ref(basis), input_ref=ref(basis),
                      path_ref=ref(basis), reached=evidence["reached"], observed_state=evidence["observed_state"],
                      execution_status="fixture_completed")
    verdict = record("Verdict", "verdict", **scope, observation_refs=[ref(observed)], label=label,
                     justification="Synthetic verifier payload for " + evidence["case"])
    rows = [registration, facts, basis, observed, verdict]
    predictions = []
    for version, p in pred.items():
        require(version in {"initial", "candidate"} and all(p[k] == v for k, v in scope.items()),
                "prediction scope mismatch")
        item = record("Prediction", "prediction." + version, **scope, hypothesis_ref=p["spec_ref"],
                      fact_snapshot=ref(facts), outcome=p["outcome"], derivation=p["derivation"],
                      missing_facts=p["missing_facts"], registration_ref=ref(registration))
        predictions.append(ref(item))
        rows.append(item)
    decision = record("Decision", "decision", prediction_refs=sorted(predictions), verdict_refs=[ref(verdict)],
                      parent_spec_ref=baseline, action=action, reason=f"fixture {label}: {p0} / {p1}",
                      remaining_disagreements=[target] if action == "unresolved" else [],
                      next_state="unresolved" if action == "unresolved" else "spec_ready")
    rows.append(decision)
    revision_ref = None
    if action == "revise":
        indexed = {ref(r): r for r in source}
        old, new = (indexed[key]["clause_refs"] for key in (baseline, candidate))
        removed, added = sorted(set(old) - set(new)), sorted(set(new) - set(old))
        require(baseline != candidate and (removed or added), "revision lacks a versioned clause change")
        regression = record("Evidence", "regression_manifest", description=canonical([scope]))
        revision = record("Revision", "revision", trigger_decision_id=ref(decision), parent_spec_ref=baseline,
                          new_spec_ref=candidate, clause_diff=[{"removed": removed, "added": added}],
                          regression_manifest_ref=ref(regression), changed_judgments=[[target, p0, p1, ref(verdict)]],
                          preserved_judgments=[], new_fact_requirements=[])
        rows.extend([regression, revision])
        revision_ref = ref(revision)
    handoff = record("Handoff", "handoff", decision_ref=ref(decision), initial_spec_ref=baseline,
                     final_spec_ref=final, revision_ref=revision_ref)
    rows.append(handoff)
    summary = dict(action=action, baseline=baseline, final=final, revision_ref=revision_ref, target=target)
    return summary, rows


def submit_decision():
    pred, evidence = read("predictions.json"), read("evidence.json")
    manifest, source = load_versions(pred)
    summary, derived = build_decision(manifest, pred, evidence, source)
    records = source + derived
    validate_envelope(manifest, records)
    save("handoff.json", summary | dict(manifest=manifest, records=records,
                                        derived_refs=[ref(item) for item in derived]))


def regress():
    envelope, evidence, pred = read("handoff.json"), read("evidence.json"), read("predictions.json")
    validate_envelope(envelope["manifest"], envelope["records"])
    derived_refs = set(envelope["derived_refs"])
    source = [item for item in envelope["records"] if ref(item) not in derived_refs]
    summary, derived = build_decision(envelope["manifest"], pred, evidence, source)
    require(all(envelope[key] == value for key, value in summary.items()) and
            {ref(r): r for r in derived} ==
            {ref(r): r for r in envelope["records"] if ref(r) in derived_refs},
            "handoff inconsistent with registered predictions or delivered evidence")
    require(summary["action"] in ("keep", "revise"), "unresolved handoff")
    backend = read("backend.json")
    observed = backend["observed"]
    require(isinstance(observed, list) and len(observed) == 2 and all(type(v) is bool for v in observed),
            "expected two query results")
    gap = backend["gap"]
    candidate = "initial" if summary["action"] == "keep" else "candidate"
    predicted = [pred[v]["outcome"] for v in ("initial", candidate)]
    rows = []
    positive = evidence["label"] == "positive"
    for i, lane in enumerate(("Q0", "Qstar")):
        hit = observed[i]
        lane_gap = gap if i == 1 else None
        faithful = (predicted[i] == "report") == hit
        passed = faithful and not lane_gap and (i == 0 or positive == hit)
        rows.append(dict(lane=lane, target=summary["target"], verdict=evidence["label"],
                         prediction=predicted[i], default="no_alert" if predicted[i] == "uncovered" else None,
                         backend_gap=lane_gap, actual="hit" if hit else "no_alert", passed=passed,
                         classification=("TP" if hit else "FN") if positive else ("FP" if hit else "TN")))
    passed = all(r["passed"] for r in rows)
    save("result.json", dict(state="frozen" if passed else "partial",
                             freeze_id="test:" + evidence["case"] if passed else None,
                             backend_gap=gap, observed=observed, predicted=predicted, label=evidence["label"],
                             baseline_pass=rows[0]["passed"], final_pass=rows[1]["passed"], rows=rows))


def main(role):
    if role == "A":
        for version in ("initial", "candidate"):
            invoke("validate", str(INPUT / version / "manifest.json"))
        save("seed.json", {"seed": "test:interval", "versions": ["initial", "candidate"],
                           "target": "t@1", "contract": "k@1", "domain": "d@1"})
    elif role == "predict":
        seed = read("seed.json")
        predictions = {v: invoke("explain", str(INPUT / v / "manifest.json"), seed["target"])
                       for v in seed["versions"]}
        save("predictions.json", predictions)
    elif role == "verifier":
        case = read("case.json")
        exceeds = not (0 <= case["offset"] and case["offset"] + case["width"] <= case["capacity"])
        label = "positive" if exceeds else "negative" if case["complete"] else "pending"
        state = "synthetic_interval_exceeds_capacity" if exceeds else "synthetic_interval_within_capacity"
        save("evidence.json", dict(label=label, case=case["id"], target=case["target"], reached=True,
                                   observed_state=state, input_manifest_sha=hashlib.sha256(
                                       (INPUT / "input_manifest.json").read_bytes()).hexdigest()))
    elif role == "B":
        submit_decision()
    elif role == "C":
        regress()
    else:
        raise ValueError("unknown role")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        print(canonical({"code": "invalid_bundle", "field": "role_contract", "message": str(exc)}))
        sys.exit(2)
    except OSError as exc:
        print(canonical({"code": "io_error", "message": str(exc)}))
        sys.exit(5)
