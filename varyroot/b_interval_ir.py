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
from .b_prompt import strip_source_comments


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
                       "scope": "declared local path, minimal capacity satisfying proven direct bounds"}}


def _norm(value):
    return re.sub(r"[\s()]", "", value)


def _direct_pure_return(node):
    children = node.get("inner", [])
    if node.get("kind") == "CompoundStmt" and len(children) == 1:
        return _direct_pure_return(children[0])
    if node.get("kind") != "ReturnStmt":
        return False
    return not _condition_has_effects(node)


def _condition_has_effects(node):
    return any(child.get("kind") in ("CallExpr", "CompoundAssignOperator") or
               child.get("kind") == "BinaryOperator" and child.get("opcode") == "=" or
               child.get("kind") == "UnaryOperator" and child.get("opcode") in ("++", "--")
               for child in _walk(node))


def _target_guards(node, source, line, expression, inherited=()):
    if node.get("kind") == "CallExpr" and _node_line(node, source) == line and \
            _norm(_node_source(node, source) or "") == _norm(expression):
        return [inherited]
    children = node.get("inner", [])
    if node.get("kind") == "CompoundStmt":
        result, pending = [], ()
        for child in children:
            result += _target_guards(child, source, line, expression, inherited + pending)
            if child.get("kind") == "IfStmt" and len(child.get("inner", [])) == 2:
                condition, then_branch = child["inner"]
                if _direct_pure_return(then_branch) and not _condition_has_effects(condition):
                    pending += ((condition, False),)
                    continue
            pending = ()
        return result
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


def _unwrap(node):
    while node.get("kind") in ("ParenExpr", "ImplicitCastExpr", "CStyleCastExpr") and \
            len(node.get("inner", [])) == 1:
        node = node["inner"][0]
    return node


def _integer(node):
    node = _unwrap(node)
    if node.get("kind") == "IntegerLiteral":
        return int(node["value"], 0)
    children = node.get("inner", [])
    if node.get("kind") == "UnaryOperator" and node.get("opcode") == "-" and len(children) == 1:
        value = _integer(children[0])
        return -value if value is not None else None
    if node.get("kind") == "BinaryOperator" and node.get("opcode") in ("+", "-") and len(children) == 2:
        left, right = _integer(children[0]), _integer(children[1])
        if left is not None and right is not None:
            return left + right if node["opcode"] == "+" else left - right
    return None


def _lower_bound(node, source, positive, config):
    """Return proven lower bounds for one direct boolean condition."""
    node = _unwrap(node)
    children = node.get("inner", [])
    kind, opcode = node.get("kind"), node.get("opcode")
    if kind == "BinaryOperator" and opcode in ("&&", "||") and len(children) == 2:
        if (opcode == "&&") == positive:
            left = _lower_bound(children[0], source, positive, config)
            right = _lower_bound(children[1], source, positive, config)
            return {key: max(left.get(key, 0), right.get(key, 0)) for key in left.keys() | right.keys()}
        # A disjunction on the taken path proves only bounds shared by both arms.
        if positive:
            left = _lower_bound(children[0], source, True, config)
            right = _lower_bound(children[1], source, True, config)
            if left.keys() != right.keys():
                raise ValueError("disjunctive_interval_guard_unproven")
            return {key: min(left[key], right[key]) for key in left.keys() & right.keys()}
        raise ValueError("compound_negative_guard_unproven")
    if kind != "BinaryOperator" or opcode not in ("<", "<=", ">", ">=") or len(children) != 2:
        snippet = _norm(_node_source(node, source) or "")
        if node.get("kind") == "CallExpr" and any(_norm(config[key]) in snippet for key in
                ("total_expr", "remaining_expr", "pointer_expr")):
            raise ValueError("alias_interval_guard_unproven")
        return {}
    if not positive:
        opcode = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}[opcode]
    left, right = children
    left_text, right_text = (_norm(_node_source(part, source) or "") for part in (left, right))
    total, remaining, pointer = (_norm(config[key]) for key in
                                 ("total_expr", "remaining_expr", "pointer_expr"))
    width = config["width"]
    tail = "-" + pointer
    end = remaining[:-len(tail)] if remaining.endswith(tail) else None

    def ptr_plus(part):
        part = _unwrap(part)
        terms = part.get("inner", [])
        return (part.get("kind") == "BinaryOperator" and part.get("opcode") == "+" and
                len(terms) == 2 and
                ((_norm(_node_source(terms[0], source) or "") == pointer and _integer(terms[1]) == width) or
                 (_norm(_node_source(terms[1], source) or "") == pointer and _integer(terms[0]) == width)))

    if end and ((ptr_plus(left) and right_text == end) or
                (left_text == end and ptr_plus(right))):
        if left_text == end:
            opcode = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[opcode]
        if opcode in ("<", "<="):
            return {"remaining": width + (opcode == "<")}
        raise ValueError("upper_interval_bound_unproven")
    for role, expression in (("total", total), ("remaining", remaining)):
        if left_text == expression and (value := _integer(right)) is not None:
            bound_op = opcode
        elif right_text == expression and (value := _integer(left)) is not None:
            bound_op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[opcode]
        else:
            continue
        if bound_op in (">", ">="):
            return {role: value + (bound_op == ">")}
        raise ValueError("upper_interval_bound_unproven")
    # A one-byte check is recognized as insufficient, not as a width guard.
    if end and ((left_text == pointer and right_text == end and opcode == "<") or
                (left_text == end and right_text == pointer and opcode == ">")):
        return {}
    if width and (str(width) in (left_text + right_text)) and \
            (pointer in (left_text + right_text) or total in (left_text + right_text)):
        raise ValueError("complex_interval_guard_unproven")
    return {}


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
    bounds = {}
    for guard, positive in guards:
        for role, minimum in _lower_bound(guard, source, positive, config).items():
            bounds[role] = max(bounds.get(role, 0), minimum)
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
    # Choose the smallest local length satisfying the proven guard bounds.
    # This is a symbolic partition, never a measured allocation size.
    capacity = max(width, bounds.get("total", 0), offset + bounds.get("remaining", 0))
    total_guard = bounds.get("total", 0) >= width
    remaining_guard = (bounds.get("remaining", 0) >= width or
                       bounds.get("total", 0) >= width + offset)
    return {"total_guard": total_guard, "remaining_guard": remaining_guard,
            "capacity": capacity, "offset": offset, "width": width,
            "reaches": True,
            "guard_sources": [("" if positive else "!") + (_node_source(guard, source) or "")
                              for guard, positive in guards],
            "fact_origin": "clang_ast_minimal_satisfying_interval"}


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

    views = {}
    for parent, (base_source, base_ast, base_line) in parents.items():
        view = strip_source_comments(base_source)
        if view != base_source:
            base_ast, _ = compile_variant(view)
            if base_ast is None:
                raise ValueError("parent_reasoning_view_uncompilable")
        views[parent] = (view, base_ast, base_line)

    def inspect(source, parent):
        base_source, base_ast, base_line = views[parent]
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
        return {"clang_receipt": receipt, "facts": values if prediction is not None else None,
                "predictions": prediction}

    return inspect
