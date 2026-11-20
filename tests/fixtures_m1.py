"""Build synthetic, versioned records; no queries or real program executions."""
import hashlib
import json
from pathlib import Path


def record(kind, name, **fields):
    return dict(kind=kind, schema_version=1, id=name, version=1, producer="fixture",
                run_ref="synthetic", depends_on=[], **fields)


def example():
    source = record("Snapshot", "src", files={"fixture.txt": "读取 x"})
    target = record("TargetRef", "t", scope_kind="original_source", snapshot_ref="src@1",
                    variant_id="base", file="fixture.txt", symbol="f", expr_span=[7, 8],
                    file_digest=hashlib.sha256("读取 x".encode()).hexdigest(),
                    operation="read", subject="buffer#1", mapping_ref=None, mapping_status="origin")
    domain = record("Domain", "d", paths=["fault"], coverage="exhaustive", basis_refs=["src@1"])
    contract = record("Contract", "k", subject="buffer#1", approval_status="approved",
                      basis_refs=["src@1"], mode="single_access")
    clauses = []
    data = []
    def fact(slot, typ, value):
        data.append(record("Fact", "f." + slot, subject="buffer#1", relation=slot,
                           typed_operands={"type": typ, "value": value},
                           path_scope={"path_id": "fault"}, source_kind="source_extracted",
                           source_ref="src@1", approval_status="approved", target_ref="t@1",
                           domain_ref="d@1", contract_ref="k@1"))

    for field in ["Source", "Propagation", "Sink", "Guard"]:
        slot = field.lower()
        fact(slot, "bool", field != "Guard")
        clauses.append(record("Clause", "c." + slot, clause_id=slot, spec_version=1,
                              field=field, bindings={slot: "bool"}, applicability=True,
                              antecedent={"var": slot}, consequent=field, direction="iff",
                              basis_refs=["src@1"]))
    fact("feasible", "bool", True)
    fact("reaches", "bool", True)
    spec = record("Spec", "s", clause_refs=[c["id"]+"@1" for c in clauses],
                  complete_guard_refs=[])
    return [source, target, domain, contract, *clauses, spec, *data]


def write(directory, records):
    root = Path(directory)
    facts = [f'{r["id"]}@{r["version"]}' for r in records if r["kind"] == "Fact"]
    (root / "records.json").write_text(json.dumps(records, ensure_ascii=False), encoding="utf8")
    manifest = {"schema_version": 1, "files": ["records.json"], "spec_ref": "s@1",
                "target_refs": ["t@1"], "domain_ref": "d@1", "contract_ref": "k@1",
                "fact_refs": facts}
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf8")
    return path
