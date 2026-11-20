"""Pre-oracle nullable output facts for direct slot checks and exits."""

import re

from . import inference, ir
from .b_clang_receipt import _node_line, _node_source, _walk, make_receipt
from .b_factor_gate import classify
from .b_prompt import strip_source_comments


def _norm(value):
    return re.sub(r"[\s()]", "", value)


def _null_relation(node, source, slot):
    text = _norm(_node_source(node, source) or "")
    slot = _norm(slot)
    if text in (slot, slot + "!=NULL", slot + "!=0", "NULL!=" + slot, "0!=" + slot):
        return "nonnull"
    if text in ("!" + slot, slot + "==NULL", slot + "==0", "NULL==" + slot, "0==" + slot):
        return "null"
    if slot in text:
        raise ValueError("complex_nullable_guard_unproven")
    return None


def _direct_exit(node):
    if node.get("kind") == "CompoundStmt" and len(node.get("inner", [])) == 1:
        node = node["inner"][0]
    if node.get("kind") == "GotoStmt":
        raise ValueError("goto_blocking_unproven")
    return node.get("kind") in ("BreakStmt", "ContinueStmt", "ReturnStmt") and \
        not any(child.get("kind") == "CallExpr" for child in _walk(node))


def extract_nullable_facts(source, ast, cfg, target_line, config):
    """Bind one target and score only direct checks with proved local blocking."""
    required = {"target_expression", "slot_expr", "success_expr", "target_call"}
    if not isinstance(config, dict) or not required <= set(config) or not ast or not cfg or \
            cfg.get("producer") != "clang_cfg" or not cfg.get("blocks"):
        raise ValueError("nullable_static_evidence_missing")
    target = _norm(config["target_expression"])

    def is_target(node):
        return (node.get("kind") in ("MemberExpr", "ArraySubscriptExpr", "UnaryOperator") and
                _node_line(node, source) == target_line and
                _norm(_node_source(node, source) or "") == target)

    matches = [node for node in _walk(ast) if is_target(node)]
    if len(matches) != 1:
        raise ValueError("nullable_target_binding_unproven")

    def contains(node):
        return any(is_target(item) for item in _walk(node))

    def visit(node, check=False, blocked=False):
        if is_target(node):
            return check, blocked
        children = node.get("inner", [])
        kind = node.get("kind")
        if kind == "ForStmt" and len(children) >= 5 and contains(node):
            condition = children[2]
            if condition and not contains(condition):
                terms = condition.get("inner", [])
                if condition.get("kind") == "BinaryOperator" and condition.get("opcode") == "&&" and len(terms) == 2:
                    values = [_norm(_node_source(term, source) or "") for term in terms]
                    success = _norm(config["success_expr"])
                    if success in values:
                        other = terms[1 - values.index(success)]
                        if _null_relation(other, source, config["slot_expr"]) == "nonnull":
                            check = blocked = True
                elif _norm(config["slot_expr"]) in _norm(_node_source(condition, source) or ""):
                    raise ValueError("complex_nullable_loop_guard_unproven")
        if kind == "CompoundStmt":
            for child in children:
                if contains(child):
                    return visit(child, check, blocked)
                if child.get("kind") == "IfStmt" and len(child.get("inner", [])) >= 2:
                    condition, then_branch = child["inner"][:2]
                    relation = _null_relation(condition, source, config["slot_expr"])
                    if relation is not None:
                        check = True
                        if relation == "null" and _direct_exit(then_branch):
                            blocked = True
            raise ValueError("nullable_target_path_unproven")
        if kind == "IfStmt" and len(children) >= 2 and contains(node):
            relation = _null_relation(children[0], source, config["slot_expr"])
            if relation is not None:
                check = True
                if relation == "nonnull" and contains(children[1]):
                    blocked = True
                elif relation == "null" and len(children) > 2 and contains(children[2]):
                    blocked = True
        for child in children:
            if contains(child):
                return visit(child, check, blocked)
        raise ValueError("nullable_target_path_unproven")

    check, blocked = visit(ast)
    return {"check_seen": check, "blocked": blocked, "reaches": not blocked,
            "fact_origin": "clang_ast_direct_nullable_path"}


def make_nullable_pair(run_id, subject):
    """Construct the four-role direct-check versus path-blocking IR pair."""
    def var(name):
        return {"var": name}
    def op(name, *args):
        return {"op": name, "args": list(args)}
    def clause(role, suffix, bindings, antecedent):
        row = {"kind": "Clause", "id": f"{run_id}.{suffix}", "version": 1,
               "field": role, "clause_id": suffix, "spec_version": 1,
               "bindings": bindings, "applicability": True, "antecedent": antecedent,
               "consequent": role, "direction": "iff", "basis_refs": [f"{run_id}.patch@1"]}
        ir.clause(row)
        return row
    common = [clause("Source", "source", {"source": "bool"}, var("source")),
              clause("Propagation", "propagation",
                     {"call_output_slot": "object", "sink_base": "object"},
                     op("same_object", var("call_output_slot"), var("sink_base"))),
              clause("Sink", "sink", {"sink": "bool"}, var("sink"))]
    guards = {name: clause("Guard", name.lower(), {key: "bool", "operand": "pointer"},
                           op("or", var(key), op("not", op("is_null", var("operand")))))
              for name, key in (("H_check", "check_seen"), ("H_path", "blocked"))}
    specs = {}
    for name, guard in guards.items():
        clauses = [*common, guard]
        specs[name] = {"kind": "Spec", "id": f"{run_id}.{name}", "version": 1,
                       "clauses": clauses,
                       "clause_refs": [inference.ref(row) for row in clauses],
                       "complete_guard_refs": []}
    return specs, {"id": f"{run_id}.target", "version": 1, "subject": subject}, \
        {"id": f"{run_id}.contract", "version": 1, "subject": subject,
         "approval_status": "approved"}, \
        {"id": f"{run_id}.domain", "version": 1, "paths": ["null_output"],
         "coverage": "equivalence_proof", "basis_refs": [f"{run_id}.contract@1"]}


def predict_nullable(values, packet=None):
    """Run existing pure IR inference on the declared null-output local path."""
    specs, target, contract, domain = packet or make_nullable_pair("nullable_static", "output_slot")
    typed = {"source": ("bool", True), "call_output_slot": ("object", "slot@1"),
             "sink_base": ("object", "slot@1"), "sink": ("bool", True),
             "operand": ("pointer", None), "feasible": ("bool", True),
             "reaches": ("bool", values["reaches"]),
             "check_seen": ("bool", values["check_seen"]),
             "blocked": ("bool", values["blocked"])}
    facts = [{"id": f"{target['id']}.{name}", "version": 1, "relation": name,
              "subject": target["subject"], "path_scope": {"path_id": "null_output"},
              "typed_operands": {"type": typ, "value": value}, "approval_status": "approved",
              "target_ref": inference.ref(target), "contract_ref": inference.ref(contract),
              "domain_ref": inference.ref(domain)} for name, (typ, value) in typed.items()]
    outcomes = tuple(inference.evaluate(specs[name], target, contract, domain, facts)["outcome"]
                     for name in ("H_check", "H_path"))
    if any(outcome not in ("report", "quiet", "uncovered") for outcome in outcomes):
        raise ValueError("nullable_ir_prediction_invalid")
    return outcomes


def make_nullable_inspector(packet, config, parents, compile_variant):
    """Connect a declared nullable seed to shared static admission and IR."""
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
                               contract_calls=(config["target_call"],), cfg=candidate_cfg)
        if classify(receipt)["status"] != "admitted":
            return {"clang_receipt": receipt}
        try:
            facts = extract_nullable_facts(source, candidate_ast, candidate_cfg,
                                           receipt["target_lines"][1], config)
            predictions = predict_nullable(facts, packet)
        except (KeyError, TypeError, ValueError):
            predictions = None
        return {"clang_receipt": receipt, "facts": facts if predictions is not None else None,
                "predictions": predictions}

    return inspect
