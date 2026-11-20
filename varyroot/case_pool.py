"""B1 pool for finite toy source shapes with independently granted read contracts."""
import json
import re
from dataclasses import replace

from .artifacts import Bundle, validate_bundle
from .inference import evaluate, ref
from .publication import digest, encode
from .qualification import artifact, prepared
from .registered_cases import FIXTURES, NOTE, proposals
from .verifier_view import project

NPD = re.compile(rb"static unsigned sample\(int missing\) \{\n"
                 rb"    unsigned \*p = missing \? 0 : &live;\n"
                 rb"(?:    if \(!p\) (return 0|p = &live|\(void\)0);\n)?"
                 rb"    return (read_required\(p\));\n\}\n")
OOB = re.compile(rb"unsigned sample\(void\) \{\n    unsigned data\[8\] = \{0\};\n"
                 rb"    unsigned i = ([0-7]);\n"
                 rb"(?:    if \(i >= 2\) (return 0|i = 1);\n)?"
                 rb"    return (data\[i\]|read_span\(data, i, (4|8)\));\n\}\n")


def shape(family, raw):
    """A closed grammar covers the entire translation unit, including the unique read."""
    text = raw.replace(NOTE, b"", 1)
    m = (NPD if family == "npd" else OOB).fullmatch(text)
    if not m:
        raise ValueError("unregistered_structure_or_ambiguous_target")
    if family == "npd":
        target = m[2]
        factors = {"null_branch_action": (m[1] or b"").decode()}
    else:
        target = m[3]
        factors = {"index_initializer": int(m[1]), "branch_action": (m[2] or b"").decode(),
                   "access_width": int(m[4] or 4), "access_form": "slice" if m[4] else "scalar"}
    if raw.count(target) != 1:
        raise ValueError("ambiguous_target")
    start = raw.index(target)
    return dict(factors, comment=NOTE in raw), [start, start + len(target)]


def admit(family, p, policy):
    """Require independently reviewed authority and exactly the declared structural edit."""
    fixture = "npd05/contract.json" if family == "npd" else "agent_a/capacity-contract.json"
    authority = json.loads((FIXTURES / fixture).read_bytes())
    if policy != authority or policy["approval"] != "approved":
        raise ValueError("missing_or_changed_authority")
    a, parent_span = shape(family, p.parent)
    b, child_span = shape(family, p.source)
    changes = [k for k in a if a[k] != b[k]]
    control_form = (family == "oob" and p.focus == "access_form" and a["access_width"] == b["access_width"] == 4
                    and a["access_form"] == "scalar" and b["access_form"] == "slice")
    if (changes != [p.focus] or p.parent.count(p.before) != 1 or
            p.parent.replace(p.before, p.after) != p.source or p.equivalent != (p.focus == "comment" or control_form)):
        raise ValueError("confounded_or_misdeclared_change")
    return a, b, parent_span, child_span


def bindings(family, form, path, capacity):
    if family == "npd":
        absent = path == "absent"
        action = form["null_branch_action"]
        bypass = absent and action == "return 0"
        live = not absent or action == "p = &live"
        values = dict(source=absent, propagation=absent, sink=True, feasible=True, reaches=not bypass,
                      exit=bypass, live=live, check_seen=bool(action), initial_live=not absent,
                      operand="static-live@1" if live else None)
        return {k: ("pointer" if k == "operand" else "bool", v) for k, v in values.items()}
    index = form["index_initializer"]
    taken = index >= 2
    exits = taken and form["branch_action"] == "return 0"
    index = 1 if taken and form["branch_action"] == "i = 1" else index
    return dict(source=("bool", True), propagation=("bool", True), sink=("bool", True), feasible=("bool", True),
                reaches=("bool", not exits), exit_taken=("bool", exits), capacity=("bytes", capacity),
                index=("elements", index), scale=("bytes_per_element", 4), width=("bytes", form["access_width"]))


def ancestry(seed, parent, catalog):
    """Recover a chain of individually admitted transforms to the exact pair parent."""
    if parent == seed:
        return []
    links = {p.source: p for p in catalog}
    trace = []
    while parent != seed:
        if parent not in links or len(trace) >= len(catalog):
            raise ValueError("parent_unbound_to_seed")
        step = links[parent]
        trace.append(step)
        parent = step.parent
    return list(reversed(trace))


def case_record(run, package, original_bundles, family, p, policy, contract, domain, models, baseline, candidate, seed_target):
    a, b, parent_span, span = admit(family, p, policy)
    raw = p.source
    sha = digest(raw)
    key = digest(encode([sha, ref(contract), ref(domain), span]))
    def record(kind, name, **fields):
        return dict(kind=kind, id="b." + key + "." + name, version=1, schema_version=1, run_ref=run,
                    producer="registered_case_pool", depends_on=[], **fields)
    snap = record("Snapshot", "source", files={"sample.c": raw.decode()})
    side = next(side for side in ("before","after") if
                artifact(package, side+"_sources")["views"][0]["target"]["target_ref"]+"@1" == seed_target)
    sources = artifact(package, side+"_sources")
    origin = sources["snapshots"][0]["files"][sources["views"][0]["target"]["file"]].encode()
    repair_names = ("exit.c","rebind.c") if family=="npd" else ("after.c","after_rebound.c")
    chain = ancestry(origin, p.parent, [x for name in repair_names for x in proposals(family,name)])
    parent_target, chain_rows, lineage = seed_target, [], []
    for i, step in enumerate(chain):
        _, _, orig_span, dest_span = admit(family,step,policy)
        stage = "control." + str(i)
        src = record("Snapshot", stage + ".source", files={"sample.c":step.source.decode()})
        link = record("Mapping", stage + ".mapping", basis_refs=[parent_target,ref(src)])
        t = record("TargetRef", stage + ".target", scope_kind="counterfactual_case", snapshot_ref=ref(src),
                   variant_id=digest(step.source), file="sample.c", file_digest=digest(step.source), symbol="sample",
                   expr_span=dest_span, operation="read", subject=contract["subject"],
                   mapping_ref=ref(link), mapping_status="exact_1to1")
        chain_rows.extend([src,link,t])
        lineage.append(dict(operator=step.name, parent_ref=parent_target, target_ref=ref(t),
                            parent_sha=digest(step.parent), source_sha=digest(step.source),
                            parent_span=orig_span, target_span=dest_span, focus=step.focus))
        parent_target=ref(t)
    mapping = record("Mapping", "mapping", basis_refs=[parent_target, ref(snap)])
    target = record("TargetRef", "read", scope_kind="counterfactual_case", snapshot_ref=ref(snap),
                    variant_id=key, file="sample.c", file_digest=sha, symbol="sample", expr_span=span,
                    operation="read", subject=contract["subject"], mapping_ref=ref(mapping), mapping_status="exact_1to1")
    facts = []
    for path in domain["paths"]:
        for name, (typ, value) in bindings(family, b, path, policy["extent"]["value"]).items():
            imported = name == "capacity"
            facts.append(record("Fact", "fact." + path + "." + name, subject=contract["subject"], relation=name,
                                typed_operands={"type": typ, "value": value}, path_scope={"path_id": path},
                                source_kind="interface_guarantee" if imported else "source_extracted",
                                source_ref=contract["basis_refs"][0] if imported else ref(snap),
                                approval_status="approved", target_ref=ref(target), contract_ref=ref(contract),
                                domain_ref=ref(domain)))
    replay = dict(target=target, contract=contract, domain=domain, facts=facts)
    # Preserve seed source references required by inherited spec clauses and the mapping.
    records = {}
    def include(row):
        if records.setdefault(ref(row), row) != row:
            raise ValueError("record_identity_conflict")
    for original in original_bundles.values():
        for row in original["records"]:
            if row["kind"] in ("Snapshot", "TargetRef", "Mapping", "Evidence"):
                include(row)
    for side in ("before", "after"):
        sources = artifact(package, side + "_sources")
        for snap_row in sources["snapshots"]:
            include(snap_row)
        view = sources["views"][0]["target"]
        if view["target_ref"] + "@1" not in records:
            snapshot = records[view["snapshot_ref"]]
            include(dict(kind="TargetRef", id=view["target_ref"], version=1, schema_version=1,
                         run_ref=run, producer=snapshot["producer"], depends_on=[], scope_kind="original_source",
                         snapshot_ref=view["snapshot_ref"], variant_id=side, file=view["file"],
                         file_digest=view["file_digest"], symbol=view.get("enclosing_decl",{}).get("symbol","sample"),
                         expr_span=view["byte_span"], operation=view["operation"], subject=view["object_name"],
                         mapping_ref=None, mapping_status="origin"))
    for model in models.values():
        for row in model["clauses"]:
            include(row)
        include({k: v for k, v in model.items() if k != "clauses"})
    for row in [*artifact(package, "contracts")["support"].values(), contract, domain, *chain_rows, snap, mapping, target, *facts]:
        include(row)
    manifest = dict(schema_version=1, files=["records.json"], spec_ref=baseline, target_refs=[ref(target)],
                    contract_ref=ref(contract), domain_ref=ref(domain), fact_refs=[ref(f) for f in facts])
    bundle = dict(manifest=manifest, records=list(records.values()))
    predictions = {}
    for mid, spec in models.items():
        errors = validate_bundle(Bundle(dict(manifest, spec_ref=mid), bundle["records"]))
        if errors:
            raise ValueError(errors)
        predictions[mid] = evaluate(spec, **replay)["outcome"]
        if predictions[mid] not in ("report", "quiet", "uncovered"):
            raise ValueError("non-admissible case prediction")
    pos = dict(target_ref=target["id"], snapshot_ref=ref(snap), file_digest=sha, byte_span=span,
               operation="read", object_name=target["subject"])
    files = project(raw, pos, policy, {"id": ref(domain), "inputs": list(range(len(domain["paths"])))})
    guard_refs = {mid:[ref(c) for c in m["clauses"] if c["field"]=="Guard"] for mid,m in models.items()}
    semantic_scope = dict(subject=contract["subject"], contract_ref=ref(contract), domain_ref=ref(domain),
                          declared_paths=domain["paths"], approved_extent=policy["extent"],
                          physical_extent_bytes=32 if family=="oob" else 4, element_bytes=4)
    return dict(case_id=key, family=family, operator=p.name, focus=p.focus, baseline=baseline, candidate=candidate,
                predictions=predictions, replay=replay, files=files, bundle=bundle, equivalent=p.equivalent,
                parent_ref=parent_target, parent_seed_version=package["version"], lineage=lineage,
                parent_sha=digest(p.parent), parent_span=parent_span, target_span=span, source_sha=sha,
                target_expression=raw[slice(*span)].decode(), parent_expression=p.parent[slice(*parent_span)].decode(),
                disputed_clause_refs=guard_refs, semantic_invariants=semantic_scope,
                change={"from": a[p.focus], "to": b[p.focus]}, invariant_slots={k:v for k,v in a.items() if k!=p.focus},
                authority_sha=artifact(package, "contracts")["support"][contract["basis_refs"][0]]["description"]["grant_sha256"], contract_ref=ref(contract), domain_ref=ref(domain),
                target_ref=ref(target), clauses={k:v["clause_refs"] for k,v in models.items()})


def build_pool(db, run, image):
    if not image:
        raise ValueError("missing_verifier_image")
    p = db.seed_package(run)
    events = db.events(run)
    a6 = next((e for e in reversed(events) if e["kind"] == "A6.replayed" and
               e["detail"]["version"] == p["version"]), None)
    if not a6 or not any(e["kind"] == "seed_accepted" and e["detail"]["detail"].get("decision") == a6["commit_seq"]
                         for e in events):
        raise ValueError("no_accepted_A6_version")
    before_files, _, contract, domain = prepared(p, "before")
    after_files = prepared(p, "after")[0]
    family = "npd" if contract["subject"] == "p" else "oob"
    folder = FIXTURES / ("npd05" if family == "npd" else "agent_a")
    repairs = ("exit.c", "rebind.c") if family == "npd" else ("after.c", "after_rebound.c")
    repair = next((s for s in repairs if (folder / s).read_bytes() == after_files["unit.c"]), None)
    if before_files["unit.c"] != (folder / "before.c").read_bytes() or repair is None:
        raise ValueError("unsupported_seed_mechanism")
    models = {}
    baseline = ref(artifact(p, "baseline_spec")["spec"])
    for model in [artifact(p, "baseline_spec"), artifact(p, "active_model"), *artifact(p,"hypothesis_set")["specs"]]:
        mid = ref(model["spec"])
        if mid == baseline or mid in a6["detail"]["survivors"]:
            models[mid] = dict(model["spec"], clauses=model["clauses"])
    candidates = [k for k in models if k != baseline]
    if not candidates:
        raise ValueError("no_competing_explanation")
    authority = contract["basis_refs"][0]
    policy = artifact(p,"contracts")["support"][authority]["description"]["contract"]
    options = proposals(family, repair)
    original_bundles = db.seed_package(run, version=1)["packet"]["bundles"]
    cases, rejected, seen = [], [], set()
    # An initial two-edit proposal is actually submitted to the same admission gate.
    # Replacing the extra comment with the original bytes gives the registered single edit.
    corrected = next(x for x in options if not x.equivalent)
    bad = replace(corrected, source=corrected.source.replace(b"    return", NOTE + b"    return", 1))
    for option in [bad, *options]:
        parent_side = "after" if option.parent == after_files["unit.c"] else "before"
        seed_target = artifact(p, parent_side + "_sources")["views"][0]["target"]["target_ref"] + "@1"
        try:
            row = case_record(run, p, original_bundles, family, option, policy, contract, domain, models, baseline,
                              candidates[0], seed_target)
        except ValueError as e:
            if option is not bad:
                raise
            rejected.append(dict(operator=option.name, source_sha=digest(option.source),
                                 repaired_source_sha=digest(corrected.source), reason=str(e)))
            continue
        if row["case_id"] not in seen and row["source_sha"] not in (digest(before_files["unit.c"]), digest(after_files["unit.c"])):
            seen.add(row["case_id"])
            cases.append(row)
    cases.sort(key=lambda row:row["case_id"])
    return dict(cases=cases, rejected=rejected, baseline=baseline, candidates=candidates, models=models,
                family=family, seed_version=p["version"], a6_decision=a6["commit_seq"], image=image,
                regenerated=sum(any(r["source_sha"] == x["repaired_source_sha"] for r in cases) for x in rejected),
                unsupported=["outside_registered_finite_source_grammar"])
