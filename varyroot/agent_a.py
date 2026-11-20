"""Offline proposal checker for the registered, memory-safe logical-prefix examples."""
import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path

from .__main__ import run as milestone_one
from .artifacts import read_json
from .frontend import analyze_source


SIDES = ("before", "after")
NAMES = ("before", "after", "before_skeleton", "after_skeleton")
HYPOTHESES = ("exit_or_contained", "exit_or_start_inside")
PREFIX = b"/* reviewed skeleton */\n"
ENUM = b"    enum { sample_revision = 1 };\n"
EXPECTED = {"capacity-contract.json": "contract", "proposal.json": "seed", **{name + ".c": "source" for name in NAMES}}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def inputs(folder):
    manifest = read_json(folder / "input_manifest.json")
    scope = manifest["scope"]
    check(manifest["schema_version"] == 1 and scope["role"] == "A" and scope["phase"] == "seed",
          "wrong seed grant")
    files = manifest["files"]
    check(len(files) == len(EXPECTED) and {f["path"]: f["kind"] for f in files} == EXPECTED,
          "seed grant must list the six approved inputs")
    for f in files:
        path = folder / f["path"]
        check(not path.is_symlink() and path.is_file(), "invalid grant file")
        data = path.read_bytes()
        check(f["size"] == len(data) and f["sha256"] == sha(data), "input digest mismatch")
    grants = {f["path"]: f for f in files}
    policy = read_json(folder / "capacity-contract.json")
    authority = grants["capacity-contract.json"]
    check(authority["ref"] == f'{policy["id"]}@{policy["version"]}', "contract grant identity mismatch")
    return scope, read_json(folder / "proposal.json"), policy, grants, {
        key: (folder / (key + ".c")).read_bytes() for key in NAMES}


def inspect_sources(sources, grants, transform):
    views, links = {}, []
    for name, raw in sources.items():
        snapshot = "src." + sha(raw) + "@1"
        skeleton = name.endswith("_skeleton")
        result = analyze_source(raw, relative_path="sample.c", snapshot_ref=snapshot,
                                variant_id=name, manifest_entry=grants[name + ".c"],
                                scope_kind="seed_skeleton" if skeleton else "original_source")
        check(result["status"] == "ok", name + ": " + str(result.get("diagnostics")))
        targets = [t for t in result["targets"] if t["enclosing_decl"]["name"] == "sample"
                   and t["object_name"] == "data" and t["operation"] == "read"]
        check(len(targets) == 1, name + ": non-unique registered target")
        target, = targets
        check(raw[slice(*target["byte_span"])] == b"data[i]" and target["width_bytes"] == 4,
              name + ": unsupported operand or type")
        views[name] = {"target": target, "config": result["config"], "ir": result["ir"]}
    for side in SIDES:
        a, b = (views[key]["target"] for key in (side, side + "_skeleton"))
        original = sources[side]
        removed = []
        shift = len(PREFIX)
        if transform == "drop_unused_enum":
            check(original.count(ENUM) == 1 and original.count(b"sample_revision") == 1,
                  side + ": declaration must be unique and unused")
            i = original.index(ENUM)
            check(i < a["byte_span"][0], "expected declaration before target")
            removed.append({"source_span": [i, i + len(ENUM)], "kind": "enum_constant_declaration",
                            "reason": "literal initializer, no storage or side effects; unused symbol"})
            original = original.replace(ENUM, b"", 1)
            shift -= len(ENUM)
        check(sources[side + "_skeleton"] == PREFIX + original, side + ": changed skeleton semantics")
        check([n + shift for n in a["byte_span"]] == b["byte_span"] and
              (removed or a["ast_path"] == b["ast_path"]), side + ": target mismatch")
        links.append(dict(side=side, original=a["target_ref"], skeleton=b["target_ref"],
                          status="exact_1to1", approval="accepted_for_scope", transform=transform, removed_nodes=removed,
                          config_ref=a["parse_config_ref"], operation=b["operation"],
                          snapshots=[a["snapshot_ref"], b["snapshot_ref"]],
                          original_span=a["byte_span"], skeleton_span=b["byte_span"]))
    return views, links


def approve(p, policy):
    check(set(p) - {"fact_reviews", "initial_hypothesis"} == {"schema_version", "subject", "capacity", "domain", "hypotheses",
                     "skeleton_transform"} and p["schema_version"] == 1, "unsupported proposal")
    check(p["domain"] == "singleton" and p["skeleton_transform"] in ("comment_prefix", "drop_unused_enum")
          and tuple(p["hypotheses"]) == HYPOTHESES, "unregistered clauses, transform or domain")
    check(p.get("initial_hypothesis", HYPOTHESES[0]) in HYPOTHESES, "unregistered initial hypothesis")
    reviews = p.get("fact_reviews", {})
    check(isinstance(reviews, dict) and set(reviews) <= {"width"} and all(
        v in ("pending", "rejected") for v in reviews.values()), "invalid fact review")
    cap = p["capacity"]
    check(set(cap) == {"value", "unit", "approval"}, "invalid capacity declaration")
    check(cap["approval"] in ("approved", "pending", "rejected"), "invalid dependency disposition")
    check(set(policy) == {"schema_version", "id", "version", "reviewer", "provenance", "subject",
                          "symbol", "path", "operand_type", "extent", "approval"} and
          policy["schema_version"] == 1 and type(policy["version"]) is int and policy["version"] >= 1
          and all(isinstance(policy[k], str) and policy[k].strip() for k in ("reviewer", "provenance"))
          and policy["approval"] in ("approved", "pending", "rejected")
          and isinstance(policy["extent"], dict) and set(policy["extent"]) == {"value", "unit"},
          "invalid independent contract")
    if (policy["symbol"], policy["path"], policy["operand_type"]) != ("sample", "sample.c", "unsigned int"):
        return "rejected", "wrong_contract_scope_or_type"
    if policy["subject"] != p["subject"] or p["subject"] != "data":
        return "rejected", "wrong_capacity_object"
    if cap["value"] is None or cap["unit"] is None:
        return "pending", "missing_logical_capacity_or_unit"
    if policy["extent"]["unit"] != "bytes" or cap["unit"] != "bytes":
        return "rejected", "wrong_capacity_unit"
    extent = policy["extent"]["value"]
    if type(cap["value"]) is not int or type(extent) is not int or extent != cap["value"] or not 0 < extent <= 32:
        return "rejected", "unregistered_logical_capacity"
    if "rejected" in (cap["approval"], policy["approval"]):
        return "rejected", "rejected_capacity_review"
    if "pending" in (cap["approval"], policy["approval"]):
        return "pending", "pending_capacity_review"
    return "approved", "matched_independent_contract"


def facts_for(raw, side, width, capacity):
    # Admit a closed, side-effect-free program shape. The front end can index more inputs.
    template = (rb"unsigned sample\(void\) \{\n(?:" + re.escape(ENUM) + rb")?"
                rb"    unsigned data\[8\] = \{0\};\n    unsigned i = ([0-7]);\n"
                rb"(?:    if \(i >= ([0-8])\) (return 0|i = ([0-7]));\n)?"
                rb"    return data\[i\];\n\}\n")
    m = re.fullmatch(template, raw)
    check(m is not None, side + ": unsupported logical-prefix source shape")
    index = int(m[1])
    check((side == "before") == (m[2] is None), side + ": unexpected control structure")
    exit_taken = False
    if m[2] and index >= int(m[2]):
        exit_taken = m[3] == b"return 0"
        if not exit_taken:
            index = int(m[4])
    return {"source": ("bool", True), "propagation": ("bool", True), "sink": ("bool", True),
            "feasible": ("bool", True), "reaches": ("bool", not exit_taken),
            "exit_taken": ("bool", exit_taken), "capacity": ("bytes", capacity),
            "index": ("elements", index), "scale": ("bytes_per_element", width),
            "width": ("bytes", width)}


def make_package(scope, proposal, policy, authority, sources, views, links, scratch):
    status, reason = approve(proposal, policy)
    run = scope["run"]
    def record(kind, key, **fields):
        return dict(kind=kind, id=key, version=1, run_ref=run, producer="agent_a",
                    schema_version=1, depends_on=[], **fields)
    def ref(row):
        return row["id"] + "@1"

    records = []
    for name, view in views.items():
        t = view["target"]
        records.append(record("Snapshot", t["snapshot_ref"].split("@")[0],
                              files={"sample.c": sources[name].decode("ascii")}))
    origins = [views[s]["target"]["snapshot_ref"] for s in SIDES]
    evidence = record("Evidence", "authority." + authority["sha256"], description={
        "grant_ref": authority["ref"], "grant_sha256": authority["sha256"], "contract": policy})
    contract = record("Contract", "logical_prefix", subject="data", approval_status=status,
                      basis_refs=[ref(evidence)], mode="logical_read_prefix")
    domain = record("Domain", "singleton", paths=["fixed_input"], coverage="exhaustive", basis_refs=origins)
    records.extend([evidence, contract, domain])
    def clause(name, field, bindings, condition):
        return record("Clause", "clause." + name, field=field, clause_id=name, spec_version=1,
                      applicability=True, consequent=field, antecedent=condition,
                      bindings=bindings, direction="iff", basis_refs=origins)
    def var(name):
        return {"var": name}
    def op(name, *args):
        return {"op": name, "args": list(args)}
    common = [clause(f.lower(), f, {f.lower(): "bool"}, var(f.lower()))
              for f in ("Source", "Propagation", "Sink")]
    records.extend(common)
    byte_offset = op("to_bytes", var("index"), var("scale"))
    guards = [op("contains", var("capacity"), byte_offset, var("width")),
              op("lt", byte_offset, var("capacity"))]
    specs = []
    for name, predicate in zip(HYPOTHESES, guards, strict=True):
        bindings = {"capacity": "bytes", "index": "elements", "scale": "bytes_per_element",
                    "exit_taken": "bool"}
        if name == HYPOTHESES[0]:
            bindings["width"] = "bytes"
        guard = clause(name, "Guard", bindings, op("or", var("exit_taken"), predicate))
        spec = record("Spec", "spec." + name, clause_refs=[ref(c) for c in [*common, guard]],
                      complete_guard_refs=[])
        records.extend([guard, spec])
        specs.append(ref(spec))
    baseline = specs[HYPOTHESES.index(proposal.get("initial_hypothesis", HYPOTHESES[0]))]
    bundles, predictions = {}, {spec: {} for spec in specs}
    for side in SIDES:
        t = views[side]["target"]
        target = record("TargetRef", t["target_ref"], scope_kind="original_source",
                        snapshot_ref=t["snapshot_ref"], variant_id=side, file="sample.c",
                        file_digest=t["file_digest"], symbol=t["enclosing_decl"]["symbol"],
                        expr_span=t["byte_span"], operation=t["operation"], subject=t["object_name"],
                        mapping_ref=None, mapping_status="origin")
        facts = []
        for slot, (typ, value) in facts_for(sources[side], side, t["width_bytes"], policy["extent"]["value"]).items():
            imported = slot == "capacity"
            disposition = status if imported else proposal.get("fact_reviews", {}).get(slot, "approved")
            operand = {"type": typ, "value": value}
            if imported and disposition != "approved":
                operand = {"type": typ, "missing": reason}
            fact = record("Fact", f"fact.{side}.{slot}", subject="data", relation=slot,
                          typed_operands=operand, path_scope={"path_id": "fixed_input"},
                          source_kind="interface_guarantee" if imported else "source_extracted",
                          source_ref=ref(evidence) if imported else t["snapshot_ref"],
                          approval_status=disposition,
                          target_ref=ref(target), contract_ref=ref(contract), domain_ref=ref(domain))
            facts.append(fact)
        rows = [*records, target, *facts]
        manifest = dict(schema_version=1, files=["records.json"], spec_ref=baseline,
                        fact_refs=[ref(f) for f in facts], target_refs=[ref(target)],
                        domain_ref=ref(domain), contract_ref=ref(contract))
        bundles[side] = {"manifest": manifest, "records": rows}
        (scratch / "records.json").write_text(canonical(rows))
        path = scratch / "manifest.json"
        for spec in specs:
            path.write_text(canonical(dict(manifest, spec_ref=spec)))
            valid = milestone_one(["validate", str(path)])
            check(valid["code"] == "ok", str(valid))
            result = milestone_one(["explain", str(path), ref(target)])
            predictions[spec][side] = result
    assumptions = [{"id": "logical_prefix@1", "subject": proposal["subject"], "basis": proposal["capacity"],
                    "status": status, "reason": reason, "targets": [v["original"] for v in links]}]
    assumptions[0].update(authority_ref=authority["ref"], authority_sha256=authority["sha256"],
                          independent_reviewer=policy["reviewer"])
    assumptions[0]["review"] = "accepted_for_scope" if status == "approved" else status
    assumptions[0]["scope"] = {"domain_ref": ref(domain), "subject": "data", "path": "fixed_input"}
    width_review = proposal.get("fact_reviews", {}).get("width", "approved")
    if width_review != "approved":
        assumptions.append({"id": "width_review@1", "status": width_review, "review": width_review,
                            "reason": "width_fact_review_open", "targets": [v["original"] for v in links]})
    blockers = ["A4_before_missing", "A4_after_missing", "A6_candidate_check_missing"]
    if status != "approved":
        blockers.append("logical_prefix_" + status)
    candidates = []
    for spec in specs:
        results = predictions[spec]
        deps = ["logical_prefix@1"]
        if spec == specs[0] and width_review != "approved":
            deps.append("width_review@1")
        eligible = (len(deps) == 1 and status == "approved"
                    and [results[s]["outcome"] for s in SIDES] == ["report", "quiet"])
        candidates.append({"spec_ref": spec, "eligible_for_review": eligible,
                           "predictions": results, "depends_on": deps})
        if not eligible:
            blockers.append(spec + ":conditional_or_inconclusive")
    return dict(schema_version=1, version=1, seed_id=scope["seed"], run_ref=run, state="seed_pending",
                status="seed_pending", before_verdict_ref=None, after_verdict_ref=None, candidate_check_ref=None,
                baseline_spec_ref=baseline, active_model_ref=baseline, hypothesis_set_ref="hypotheses@1",
                hypotheses=specs, mapping=links, pair={"before": links[0]["original"], "after": links[1]["original"],
                    "basis": "unique registered sample/data read", "policy": "definition"},
                assumptions=assumptions, blockers=blockers, candidates=candidates, bundles=bundles,
                frontend=views, contract_ref=ref(contract), domain_ref=ref(domain))


def ledger_inputs(seed):
    """Build the versioned, dependency-ordered role artifact inputs for Ledger.bind_seed."""
    by_kind = {}
    for b in seed["bundles"].values():
        for row in b["records"]:
            rows = by_kind.setdefault(row["kind"], {})
            key = row["id"] + "@1"
            check(rows.setdefault(key, row) == row, "record identity collision: " + key)
    specs = by_kind["Spec"]
    clauses = by_kind["Clause"]
    def resolved(spec):
        return {"spec": specs[spec], "clauses": [clauses[k] for k in specs[spec]["clause_refs"]]}
    def artifact(value, *deps):
        return {"value": value, "depends_on": list(deps)}
    artifacts = {
        "domain": artifact(by_kind["Domain"]),
        "contracts": artifact({"contracts": by_kind["Contract"], "assumptions": seed["assumptions"],
                               "support": by_kind["Evidence"]}),
        "baseline_spec": artifact(resolved(seed["baseline_spec_ref"])),
        "active_model": artifact(resolved(seed["active_model_ref"])),
        "hypothesis_set": artifact({"specs": [resolved(k) for k in seed["hypotheses"]],
                                    "checks": seed["candidates"]}, "facts", "active_model"),
    }
    for side in SIDES:
        mapping = next(link for link in seed["mapping"] if link["side"] == side)
        inputs = [side, side + "_skeleton"]
        views = [seed["frontend"][key] for key in inputs]
        snapshots = [by_kind["Snapshot"][v["target"]["snapshot_ref"]] for v in views]
        artifacts[side + "_sources"] = artifact({"views": views, "snapshots": snapshots})
        artifacts[side + "_mapping"] = artifact(mapping, side + "_sources")
        facts = [r for r in seed["bundles"][side]["records"] if r["kind"] == "Fact"]
        artifacts[side + "_facts"] = artifact(facts, side + "_mapping", "contracts", "domain")
        artifacts[side + "_basis"] = artifact({"side": side}, side + "_facts")
    artifacts["skeleton"] = artifact({"sides": list(SIDES)}, "before_sources", "after_sources")
    artifacts["mapping"] = artifact(seed["pair"], "before_mapping", "after_mapping")
    artifacts["facts"] = artifact({"sides": list(SIDES)}, "before_facts", "after_facts")
    return artifacts, {name: name for name in artifacts}


def execute(input_dir, output_dir):
    scope, proposal, policy, grants, sources = inputs(input_dir)
    views, links = inspect_sources(sources, grants, proposal["skeleton_transform"])
    with tempfile.TemporaryDirectory(dir=output_dir) as tmp:
        packet = make_package(scope, proposal, policy, grants["capacity-contract.json"],
                              sources, views, links, Path(tmp))
    with (output_dir / "seed.json").open("x", encoding="utf8") as f:
        f.write(canonical(packet))
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("/input"))
    parser.add_argument("--output", type=Path, default=Path("/output"))
    args = parser.parse_args()
    try:
        execute(args.input, args.output)
    except OSError as error:
        print(canonical({"code": "io_error", "reason": str(error)}), end="")
        return 5
    except (ValueError, TypeError, KeyError) as error:
        print(canonical({"code": "seed_input_rejected", "reason": str(error)}), end="")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
