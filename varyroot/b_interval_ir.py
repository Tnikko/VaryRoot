"""Generic patch-derived interval hypotheses and pre-oracle Clang fact projection.

The projection is scoped to one declared symbolic boundary path. It is not a
whole-program reachability or safety verdict.
"""

import hashlib
import re

from . import ir, inference
from .artifacts import Bundle, validate_bundle
from .b_clang_receipt import _node_line, _node_source, _walk, make_receipt
from .b_factor_gate import classify


def _var(name):
    return {"var": name}


def _op(name, *args):
    return {"op": name, "args": list(args)}


def make_interval_pair(run_id, subject):
    """Construct two typed four-role IR specs from a declared interval contract."""
    if not all(isinstance(value, str) and value for value in (run_id, subject)):
        raise ValueError("interval_identity_required")

    def clause(role, suffix, bindings, antecedent):
        row = {"kind": "Clause", "id": f"{run_id}.{suffix}", "version": 1,
               "field": role, "clause_id": suffix, "spec_version": 1,
               "bindings": bindings, "applicability": True,
               "antecedent": antecedent, "consequent": role, "direction": "iff",
               "basis_refs": [f"{run_id}.patch@1"]}
        ir.clause(row)
        return row

    common = [
        clause("Source", "source", {"source": "bool"}, _var("source")),
        clause("Propagation", "propagation", {"source_object": "object", "sink_object": "object"},
               _op("same_object", _var("source_object"), _var("sink_object"))),
        clause("Sink", "sink", {"sink": "bool"}, _var("sink")),
    ]
    contained = _op("contains", _var("capacity"), _var("offset"), _var("width"))
    bindings = {"total_guard": "bool", "remaining_guard": "bool",
                "capacity": "bytes", "offset": "bytes", "width": "bytes"}
    guards = {
        "H_total": clause("Guard", "total_guard", bindings,
                          _op("or", _var("total_guard"), _var("remaining_guard"), contained)),
        "H_remaining": clause("Guard", "remaining_guard", bindings,
                              _op("or", _var("remaining_guard"), contained)),
    }
    specs = {}
    for name, guard in guards.items():
        clauses = [*common, guard]
        specs[name] = {"kind": "Spec", "id": f"{run_id}.{name}", "version": 1,
                       "clauses": clauses,
                       "clause_refs": [f"{row['id']}@1" for row in clauses],
                       "complete_guard_refs": []}
    return {"specs": specs,
            "target": {"id": f"{run_id}.target", "version": 1, "subject": subject},
            "contract": {"id": f"{run_id}.contract", "version": 1,
                         "subject": subject, "approval_status": "approved"},
            "domain": {"id": f"{run_id}.symbolic_path", "version": 1,
                       "paths": ["boundary"], "coverage": "equivalence_proof",
                       "basis_refs": [f"{run_id}.patch@1"],
                       "scope": "declared local path, capacity equals copy width"}}


def _norm(value):
    return re.sub(r"[\s()]", "", value)


def _target_guards(node, source, line, expression, inherited=()):
    if node.get("kind") == "CallExpr" and _node_line(node, source) == line and \
            _norm(_node_source(node, source) or "") == _norm(expression):
        return [inherited]
    children = node.get("inner", [])
    if node.get("kind") == "IfStmt" and len(children) >= 2:
        condition = children[0]
        result = _target_guards(children[1], source, line, expression,
                                inherited + ((condition, True),))
        for child in children[2:]:
            result += _target_guards(child, source, line, expression,
                                     inherited + ((condition, False),))
        return result
    return [row for child in children
            for row in _target_guards(child, source, line, expression, inherited)]


def _guard_guarantees(node, source, required):
    """A true direct comparison or conjunction proves one declared bound."""
    children = node.get("inner", [])
    kind, opcode = node.get("kind"), node.get("opcode")
    if kind in ("ParenExpr", "ImplicitCastExpr") and len(children) == 1:
        return _guard_guarantees(children[0], source, required)
    if kind == "BinaryOperator" and opcode == ">=":
        return _norm(_node_source(node, source) or "") == required
    if kind == "BinaryOperator" and opcode == "&&" and len(children) == 2:
        return any(_guard_guarantees(child, source, required) for child in children)
    if kind == "BinaryOperator" and opcode == "||" and len(children) == 2:
        return all(_guard_guarantees(child, source, required) for child in children)
    return False


def extract_interval_facts(source, ast, cfg, target_line, config):
    """Read declared direct Guard shapes on one Clang target ancestry.

    The offset witness is syntactic and path feasibility remains a declared
    local assumption. Unsupported aliases and guard shapes must not be scored.
    """
    required = {"target_expression", "target_call", "total_expr", "remaining_expr", "pointer_expr", "width"}
    if not isinstance(config, dict) or not required <= set(config) or \
            type(config["width"]) is not int or config["width"] <= 0 or \
            not ast or not cfg or cfg.get("producer") != "clang_cfg" or not cfg.get("blocks"):
        raise ValueError("interval_static_evidence_missing")
    paths = _target_guards(ast, source, target_line, config["target_expression"])
    if len(paths) != 1:
        raise ValueError("target_binding_unproven")
    guards = paths[0]
    width = config["width"]
    total = _norm(config["total_expr"] + ">=" + str(width))
    remaining = _norm(config["remaining_expr"] + ">=" + str(width))
    total_guard = any(positive and _guard_guarantees(guard, source, total)
                      for guard, positive in guards)
    remaining_guard = any(positive and _guard_guarantees(guard, source, remaining)
                          for guard, positive in guards)
    target_nodes = [n for n in _walk(ast) if n.get("kind") == "CallExpr" and
                    _node_line(n, source) == target_line and
                    _norm(_node_source(n, source) or "") == _norm(config["target_expression"])]
    target_offset = target_nodes[0].get("range", {}).get("begin", {}).get("offset")
    if not isinstance(target_offset, int):
        raise ValueError("target_offset_unavailable")
    increments = []
    for node in _walk(ast):
        if node.get("kind") != "CompoundAssignOperator" or node.get("opcode") != "+=":
            continue
        begin = node.get("range", {}).get("begin", {}).get("offset")
        if not isinstance(begin, int) or begin >= target_offset:
            continue
        match = re.fullmatch(re.escape(_norm(config["pointer_expr"])) + r"\+=([1-9][0-9]*)",
                             _norm(_node_source(node, source) or ""))
        if match:
            increments.append(int(match.group(1)))
    if len(increments) != 1:
        raise ValueError("unique_pointer_advance_unproven")
    offset = increments[0]
    capacity = width  # registered boundary partition, not a runtime observation
    return {"total_guard": total_guard, "remaining_guard": remaining_guard,
            "capacity": capacity, "offset": offset, "width": width,
            "reaches": not remaining_guard or capacity - offset >= width,
            "guard_sources": [("" if positive else "!") + (_node_source(guard, source) or "")
                              for guard, positive in guards],
            "fact_origin": "clang_ast_symbolic_boundary"}


def predict_interval(pair, values):
    """Run the existing pure IR interpreter on the registered symbolic path."""
    target, contract, domain = (pair[key] for key in ("target", "contract", "domain"))
    facts = []
    typed = {"source": ("bool", True), "source_object": ("object", "span@1"),
             "sink_object": ("object", "span@1"), "sink": ("bool", True),
             "feasible": ("bool", True), "reaches": ("bool", values["reaches"]),
             **{key: ("bool" if key.endswith("guard") else "bytes", values[key])
                for key in ("total_guard", "remaining_guard", "capacity", "offset", "width")}}
    for name, (kind, value) in typed.items():
        facts.append({"id": f"{target['id']}.{name}", "version": 1,
                      "relation": name, "subject": target["subject"],
                      "path_scope": {"path_id": "boundary"},
                      "typed_operands": {"type": kind, "value": value},
                      "approval_status": "approved", "target_ref": inference.ref(target),
                      "contract_ref": inference.ref(contract), "domain_ref": inference.ref(domain)})
    outcomes = {name: inference.evaluate(spec, target, contract, domain, facts)["outcome"]
                for name, spec in pair["specs"].items()}
    if any(value not in ("report", "quiet", "uncovered") for value in outcomes.values()):
        raise ValueError("interval_ir_prediction_invalid")
    return outcomes


def accept_interval_packet(pair, source, ast, cfg, target_line, config, source_sha256, symbol):
    """A6-check a patch-derived A5 candidate in a declared symbolic path.

    This validates IR schema, source identity and Clang bindings. It never
    consumes independent dynamic observations or asserts whole-program safety.
    """
    raw = source.encode("utf-8")
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != source_sha256:
        raise ValueError("source_lock_mismatch")
    contract_basis = config.get("contract_basis_sha256")
    if not isinstance(contract_basis, str) or not re.fullmatch(r"[0-9a-f]{64}", contract_basis) or \
            contract_basis == actual_sha:
        raise ValueError("independent_contract_basis_required")
    if not isinstance(symbol, str) or not symbol:
        raise ValueError("target_symbol_required")
    values = extract_interval_facts(source, ast, cfg, target_line, config)
    line_bytes = raw.splitlines(keepends=True)
    if target_line < 1 or target_line > len(line_bytes):
        raise ValueError("target_line_unbound")
    expression = config["target_expression"].encode("utf-8")
    if line_bytes[target_line - 1].count(expression) != 1:
        raise ValueError("target_expression_unbound")
    begin = sum(len(line) for line in line_bytes[:target_line - 1]) + line_bytes[target_line - 1].index(expression)
    span = [begin, begin + len(expression)]
    run_id = pair["target"]["id"].removesuffix(".target")

    def record(kind, key, **fields):
        return {"kind": kind, "id": key, "version": 1, "producer": "interval_patch_ast_v1",
                "schema_version": 1, "run_ref": run_id, "depends_on": [], **fields}

    evidence = record("Evidence", run_id + ".patch", description={
        "origin": "patch_guard_differential", "source_sha256": actual_sha,
        "scope": "local symbolic boundary path; no dynamic labels"})
    contract_evidence = record("Evidence", run_id + ".contract_source", description={
        "origin": "independent_capacity_source", "source_sha256": contract_basis})
    snap = record("Snapshot", run_id + ".snapshot", files={"source.c": source})
    target = record("TargetRef", pair["target"]["id"],
                    scope_kind="original_source", snapshot_ref=inference.ref(snap),
                    variant_id=actual_sha[:12], file="source.c", file_digest=actual_sha,
                    symbol=symbol, expr_span=span, operation="read",
                    subject=pair["target"]["subject"], mapping_ref=None,
                    mapping_status="origin")
    contract = record("Contract", pair["contract"]["id"],
                      subject=pair["contract"]["subject"], approval_status="approved",
                      mode="logical_interval", basis_refs=[inference.ref(contract_evidence)])
    domain = record("Domain", pair["domain"]["id"],
                    paths=["boundary"], coverage="equivalence_proof",
                    basis_refs=[inference.ref(contract_evidence)], scope=pair["domain"]["scope"])
    clauses = {}
    specs = {}
    for name, spec in pair["specs"].items():
        for clause in spec["clauses"]:
            clauses[clause["id"]] = record("Clause", clause["id"], **{
                key: clause[key] for key in ("clause_id", "spec_version", "field", "bindings",
                                       "applicability", "antecedent", "consequent", "direction",
                                       "basis_refs")})
        specs[name] = record("Spec", spec["id"], clause_refs=spec["clause_refs"],
                             complete_guard_refs=spec["complete_guard_refs"])
    typed = {"source": ("bool", True), "source_object": ("object", "span@1"),
             "sink_object": ("object", "span@1"), "sink": ("bool", True),
             "feasible": ("bool", True), "reaches": ("bool", values["reaches"]),
             **{key: ("bool" if key.endswith("guard") else "bytes", values[key])
                for key in ("total_guard", "remaining_guard", "capacity", "offset", "width")}}
    facts = [record("Fact", f"{target['id']}.{name}", subject=target["subject"],
                    relation=name, typed_operands={"type": typ, "value": value},
                    path_scope={"path_id": "boundary"},
                    source_kind="source_extracted" if name in ("total_guard", "remaining_guard", "offset")
                    else "skeleton_assumption", source_ref=inference.ref(snap) if name in
                    ("total_guard", "remaining_guard", "offset") else inference.ref(evidence),
                    approval_status="approved", target_ref=inference.ref(target),
                    contract_ref=inference.ref(contract), domain_ref=inference.ref(domain))
             for name, (typ, value) in typed.items()]
    records = [evidence, contract_evidence, snap, target, contract, domain,
               *clauses.values(), *specs.values(), *facts]
    for spec in specs.values():
        manifest = {"schema_version": 1, "files": ["records.json"],
                    "spec_ref": inference.ref(spec), "target_refs": [inference.ref(target)],
                    "contract_ref": inference.ref(contract), "domain_ref": inference.ref(domain),
                    "fact_refs": [inference.ref(fact) for fact in facts]}
        errors = validate_bundle(Bundle(manifest, records))
        if errors:
            raise ValueError("a6_invalid_interval_bundle:" + str(errors))
    return {"a5_origin": "patch_guard_differential", "a6_status": "accepted_for_symbolic_scope",
            "source_sha256": actual_sha, "target_span": span,
            "facts": values, "predictions": predict_interval(pair, values)}


def make_interval_inspector(pair, config, parents, compile_variant):
    """Connect a declared interval seed to the shared pre-oracle retry engine."""
    if set(parents) != {"before", "after"} or not config.get("target_call"):
        raise ValueError("parent_sources_required")

    def inspect(source, parent):
        base_source, base_ast, base_line = parents[parent]
        candidate_ast, candidate_cfg = compile_variant(source)
        if candidate_ast is None:
            return {"clang_receipt": {"producer": "clang_ast", "compile_ok": False}}
        receipt = make_receipt(base_source, source, base_ast, candidate_ast,
                               base_line, config["target_expression"],
                               contract_calls=(config["target_call"],),
                               cfg=candidate_cfg)
        if classify(receipt)["status"] != "admitted":
            return {"clang_receipt": receipt}
        try:
            values = extract_interval_facts(source, candidate_ast, candidate_cfg,
                                            receipt["target_lines"][1], config)
            outcomes = predict_interval(pair, values)
            prediction = [outcomes["H_total"], outcomes["H_remaining"]]
        except (KeyError, TypeError, ValueError):
            prediction = None
        return {"clang_receipt": receipt, "predictions": prediction}

    return inspect
