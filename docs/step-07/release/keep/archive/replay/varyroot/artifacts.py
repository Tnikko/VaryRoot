"""Read a manifest-listed array of records from each UTF-8 JSON file."""
import hashlib
import json
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from pathlib import Path

from . import ir
from .checks import Diagnostic, fields, require, strings
from .handoff import OUTCOMES, handoff, revision

SCHEMA = {
    "Snapshot": "files", "Mapping": "basis_refs", "Evidence": "description",
    "Contract": "subject approval_status mode basis_refs", "Domain": "paths coverage basis_refs",
    "TargetRef": "scope_kind snapshot_ref variant_id file file_digest symbol expr_span operation subject mapping_ref mapping_status",
    "Fact": "subject relation typed_operands path_scope source_kind source_ref approval_status target_ref contract_ref domain_ref",
    "Clause": "clause_id spec_version field bindings applicability antecedent consequent direction basis_refs",
    "Spec": "clause_refs complete_guard_refs",
    "Prediction": "hypothesis_ref target_ref contract_ref domain_ref fact_snapshot outcome derivation missing_facts registration_ref",
    "Observation": "request_ref target_ref contract_ref domain_ref input_ref path_ref reached observed_state execution_status",
    "Verdict": "target_ref contract_ref domain_ref observation_refs label justification",
    "Decision": "prediction_refs verdict_refs parent_spec_ref action reason remaining_disagreements next_state",
    "Revision": "trigger_decision_id parent_spec_ref new_spec_ref clause_diff regression_manifest_ref changed_judgments preserved_judgments new_fact_requirements",
    "Handoff": "initial_spec_ref final_spec_ref decision_ref revision_ref",
}
REF_TYPES = {
    "snapshot_ref": "Snapshot", "source_ref": None, "mapping_ref": "Mapping",
    "target_ref": "TargetRef", "contract_ref": "Contract", "domain_ref": "Domain",
    "clause_refs": "Clause", "complete_guard_refs": "Clause", "basis_refs": None,
    "hypothesis_ref": "Spec", "fact_snapshot": "Snapshot", "registration_ref": "Evidence",
    "request_ref": "Evidence", "input_ref": "Evidence", "path_ref": "Evidence",
    "observation_refs": "Observation", "prediction_refs": "Prediction", "verdict_refs": "Verdict",
    "parent_spec_ref": "Spec", "trigger_decision_id": "Decision", "new_spec_ref": "Spec",
    "regression_manifest_ref": "Evidence", "initial_spec_ref": "Spec", "final_spec_ref": "Spec",
    "decision_ref": "Decision", "revision_ref": "Revision",
}
NULLABLE = {"mapping_ref", "final_spec_ref", "revision_ref"}


def read_json(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, k, "duplicate JSON key")
            result[k] = v
        return result

    try:
        return json.loads(path.read_text(encoding="utf8"), object_pairs_hook=unique,
                          parse_constant=invalid_number)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Diagnostic(str(path), str(error)) from error


def invalid_number(value):
    raise Diagnostic("$", "invalid JSON number: " + value)


@dataclass
class Bundle:
    manifest: dict
    records: list

    def index(self):
        return {f'{r["id"]}@{r["version"]}': r for r in self.records}


def load_bundle(path):
    path = Path(path).resolve()
    m = read_json(path)
    fields(m, "schema_version files spec_ref target_refs contract_ref domain_ref fact_refs")
    require(type(m["schema_version"]) is int and m["schema_version"] == 1, "schema_version", "unsupported manifest")
    require(strings(m["files"]) and m["files"] and len(set(m["files"])) == len(m["files"]),
            "files", "expected distinct listed files")
    records = []
    for filename in m["files"]:
        child = (path.parent / filename).resolve()
        require(not Path(filename).is_absolute() and child.is_relative_to(path.parent), "files", "outside bundle")
        items = read_json(child)
        require(isinstance(items, list), filename, "expected record array")
        records.extend(items)
    return Bundle(m, records)


def target(r, get):
    snap = get(r["snapshot_ref"], "Snapshot")
    file = r["file"]
    require(isinstance(file, str) and file and not Path(file).is_absolute()
            and ".." not in Path(file).parts and file in snap["files"], "file", "unknown local source")
    data = snap["files"][file].encode("utf8")
    require(hashlib.sha256(data).hexdigest() == r["file_digest"], "file_digest", "snapshot mismatch")
    span = r["expr_span"]
    require(isinstance(span, list) and len(span) == 2 and all(type(i) is int for i in span)
            and 0 <= span[0] < span[1] <= len(data), "expr_span", "invalid byte interval")
    require(all(i == len(data) or data[i] & 0xc0 != 0x80 for i in span), "expr_span", "splits UTF-8 character")
    origin = r["scope_kind"] == "original_source"
    require(r["scope_kind"] in ("original_source", "seed_skeleton", "counterfactual_case") and
            (r["mapping_ref"] is None) == origin and
            (r["mapping_status"] == "origin" if origin else r["mapping_status"] in
             ("exact_1to1", "split_expression", "ambiguous", "unmapped", "macro_expanded")),
            "mapping_status", "invalid target mapping")


def validate_bundle(bundle):
    try:
        _validate(bundle)
    except Diagnostic as error:
        return [error.detail]
    return []


def _validate(bundle):
    records = {}
    for index, r in enumerate(bundle.records):
        fields(r, "kind schema_version id version producer run_ref depends_on")
        require(type(r["version"]) is int and r["version"] > 0, "version", "expected positive integer")
        require(type(r["schema_version"]) is int and r["schema_version"] == 1, "schema_version", "unsupported record")
        require(all(isinstance(r[k], str) and r[k] for k in ("id", "producer", "run_ref", "kind"))
                and "@" not in r["id"], str(index), "invalid record identity")
        require(r["kind"] in SCHEMA, "kind", "unknown artifact kind")
        try:
            fields(r, SCHEMA[r["kind"]])
        except Diagnostic as error:
            error.detail["field"] = f'{r["id"]}@{r["version"]}.' + error.detail["field"]
            if r["kind"] in ("Clause", "Spec"):
                error.detail["code"] = "invalid_ir"
            raise
        key = f'{r["id"]}@{r["version"]}'
        require(key not in records, key, "duplicate identity")
        records[key] = r

    def get(key, kind):
        require(isinstance(key, str) and key in records, str(key), "unknown versioned reference")
        record = records[key]
        require(kind is None or record["kind"] == kind, key, "unexpected reference kind")
        return record

    graph = {}
    for key, r in records.items():
        deps = set()
        def resolve(ref, kind):
            item = get(ref, kind)
            deps.add(ref)
            return item
        try:
            require(strings(r["depends_on"]), "depends_on", "expected references")
            for ref in r["depends_on"]:
                resolve(ref, None)
            for name, kind in REF_TYPES.items():
                if name not in r or (r[name] is None and name in NULLABLE):
                    continue
                if name.endswith("_refs"):
                    require(strings(r[name]) and len(r[name]) == len(set(r[name])), name, "expected unique references")
                    for ref in r[name]:
                        resolve(ref, kind)
                else:
                    resolve(r[name], kind)
            _content(r, resolve)
        except Diagnostic as error:
            error.detail["field"] = key + "." + error.detail["field"]
            raise
        except (TypeError, KeyError, AttributeError) as error:
            raise Diagnostic(key, "malformed field: " + str(error),
                             "invalid_ir" if r["kind"] in ("Clause", "Fact", "Spec") else "invalid_bundle") from error
        graph[key] = deps
    try:
        list(TopologicalSorter(graph).static_order())
    except CycleError as error:
        raise Diagnostic("depends_on", "dependency cycle: " + str(error.args[1])) from error
    m = bundle.manifest
    for name, kind in (("spec_ref", "Spec"), ("contract_ref", "Contract"), ("domain_ref", "Domain")):
        get(m[name], kind)
    for name, kind in (("target_refs", "TargetRef"), ("fact_refs", "Fact")):
        require(strings(m[name]) and len(set(m[name])) == len(m[name]), name, "expected distinct refs")
        for ref in m[name]:
            get(ref, kind)
    symbols = {"feasible": "bool", "reaches": "bool"}
    for ref in get(m["spec_ref"], "Spec")["clause_refs"]:
        symbols.update(get(ref, "Clause")["bindings"])
    for ref in m["fact_refs"]:
        fact = get(ref, "Fact")
        slot = fact["relation"]
        ir.check(slot not in symbols or fact["typed_operands"]["type"] == symbols[slot],
                 ref + ".typed_operands", "fact and declared slot have different types")


def _content(r, get):
    k = r["kind"]
    for name in ("subject", "relation", "variant_id", "symbol", "operation", "clause_id"):
        if name in r:
            require(isinstance(r[name], str) and r[name], name, "expected nonempty identity")
    if k == "Snapshot":
        require(isinstance(r["files"], dict) and all(isinstance(v, str) for v in r["files"].values()),
                "files", "expected source text map")
    if k in ("Contract", "Fact"):
        require(r["approval_status"] in ("approved", "pending", "rejected"), "approval_status", "invalid approval")
    if k == "Contract":
        require(r["approval_status"] != "approved" or bool(r["basis_refs"]), "basis_refs", "approved contract needs basis")
    if k == "Domain":
        require(strings(r["paths"]) and len(set(r["paths"])) == len(r["paths"]), "paths", "invalid path identities")
        require(r["coverage"] in ("exhaustive", "equivalence_proof", "partial")
                and (r["coverage"] == "partial" or r["basis_refs"]), "coverage", "coverage requires basis")
    elif k == "TargetRef":
        target(r, get)
    elif k == "Fact":
        ir.operand(r)
        p = r["path_scope"]
        require(isinstance(p, dict) and set(p) == {"path_id"} and p["path_id"] in get(r["domain_ref"], "Domain")["paths"],
                "path_scope", "expected path in domain")
        require(r["source_kind"] in ("source_extracted", "interface_guarantee", "skeleton_assumption"),
                "source_kind", "unknown provenance")
        basis = get(r["source_ref"], None)
        require(basis["kind"] in ("Snapshot", "Evidence", "Contract"), "source_ref", "invalid fact provenance")
        if r["approval_status"] == "approved" and basis["kind"] == "Contract":
            require(basis["approval_status"] == "approved", "source_ref", "unapproved contract basis")
    elif k == "Clause":
        ir.clause(r)
    elif k == "Spec":
        clauses = [get(ref, "Clause") for ref in r["clause_refs"]]
        ir.check({c["field"] for c in clauses} == ir.ROLES, "clause_refs", "missing clause role")
        guards = {ref for ref in r["clause_refs"] if get(ref, "Clause")["field"] == "Guard"}
        ir.check(set(r["complete_guard_refs"]) <= guards, "complete_guard_refs", "not a guard of this spec")
        symbols = {"feasible": "bool", "reaches": "bool"}
        for c in clauses:
            for name, typ in c["bindings"].items():
                ir.check(symbols.setdefault(name, typ) == typ, name, "inconsistent binding types")
    elif k == "Prediction":
        require(r["outcome"] in OUTCOMES, "outcome", "not a registrable prediction")
    elif k == "Observation":
        require(type(r["reached"]) is bool, "reached", "expected boolean")
    elif k == "Verdict":
        require(r["label"] in ("positive", "negative", "pending") and r["justification"],
                "label", "invalid verdict")
        for obs_ref in r["observation_refs"]:
            obs = get(obs_ref, "Observation")
            require(all(r[key] == obs[key] for key in ("target_ref", "contract_ref", "domain_ref")),
                    "observation_refs", "observation outside verdict scope")
        require(r["label"] == "pending" or bool(r["observation_refs"]), "observation_refs", "missing observation")
    elif k == "Decision":
        require(r["action"] in ("revise", "keep", "unresolved", "seek_evidence", "correct_reading", "remodel"),
                "action", "unknown decision")
    elif k == "Revision":
        revision(r, get)
    elif k == "Handoff":
        handoff(r, get)
