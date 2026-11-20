"""Pure inference on resolved, versioned records. No filesystem or verdict access."""
from dataclasses import dataclass, field

from .checks import Diagnostic
from . import ir

UNKNOWN = object()


def conjunction(values):
    if any(v is False for v in values):
        return False
    return UNKNOWN if UNKNOWN in values else True


def disjunction(values):
    if any(v is True for v in values):
        return True
    return UNKNOWN if UNKNOWN in values else False


def negate(value):
    return UNKNOWN if value is UNKNOWN else not value


def ref(record):
    return f'{record["id"]}@{record["version"]}'


@dataclass
class PathBindings:
    facts: dict
    missing: dict = field(default_factory=dict)
    used: set = field(default_factory=set)

    def value(self, name):
        rows = self.facts.get(name, [])
        known = []
        for r in rows:
            key = ref(r)
            arg = r["typed_operands"]
            if r["approval_status"] != "approved":
                self.missing[key] = "approval_" + r["approval_status"]
            elif "missing" in arg:
                self.missing[key] = arg["missing"]
            else:
                self.used.add(key)
                known.append(arg["value"])
        if not rows:
            self.missing[name] = "unbound"
        if known and any(v != known[0] for v in known):
            for r in rows:
                self.missing[ref(r)] = "inconsistent_binding"
            return UNKNOWN
        return known[0] if known else UNKNOWN


def expression(expr, bindings, nodes):
    value = _expression(expr, bindings, nodes)
    node = {"expression": expr, "value": trace_value(value)}
    if isinstance(expr, dict) and "var" in expr:
        node["fact_refs"] = sorted(ref(f) for f in bindings.facts.get(expr["var"], []))
    nodes.append(node)
    return value


def _expression(expr, bindings, nodes):
    if type(expr) is bool:
        return expr
    if "var" in expr:
        return bindings.value(expr["var"])
    if "value" in expr:
        return expr["value"]
    op = expr["op"]
    args = [expression(arg, bindings, nodes) for arg in expr["args"]]
    if op == "and":
        return conjunction(args)
    if op == "or":
        return disjunction(args)
    if op == "not":
        return negate(args[0])
    if UNKNOWN in args:
        return UNKNOWN
    if op in ("same_object", "eq_bytes"):
        return args[0] == args[1]
    if op == "is_null":
        return args[0] is None
    if op == "blocked":
        return args[0]
    if op == "to_bytes":
        return args[0] * args[1]
    if op == "lt":
        return args[0] < args[1]
    if op == "contains":
        capacity, offset, width = args
        return 0 <= offset and 0 < width and offset + width <= capacity
    raise Diagnostic("op", "unknown operator", "invalid_ir")


def trace_value(value):
    return "U" if value is UNKNOWN else value


def evaluate(spec, target, contract, domain, facts):
    """spec contains resolved 'clauses'; the file adapter resolves exactly clause_refs."""
    try:
        clauses = {ref(c): c for c in spec["clauses"]}
        ir.check(len(clauses) == len(spec["clauses"]) and set(clauses) == set(spec["clause_refs"]),
                 "clause_refs", "resolved clauses do not match spec")
        ir.check({c["field"] for c in clauses.values()} == ir.ROLES, "clauses", "missing clause role")
        ir.check(all(cid in clauses and clauses[cid]["field"] == "Guard"
                     for cid in spec["complete_guard_refs"]), "complete_guard_refs", "invalid guard set")
        ir.check(domain["coverage"] in ("partial", "exhaustive", "equivalence_proof")
                 and len(domain["paths"]) == len(set(domain["paths"])), "domain", "invalid path domain")
        return _evaluate(spec, target, contract, domain, facts)
    except Diagnostic as error:
        return {"outcome": "invalid_ir", "diagnostic": error.detail}
    except (KeyError, TypeError, AttributeError) as error:
        return {"outcome": "invalid_ir", "diagnostic": {"code": "invalid_ir",
                "field": str(error), "message": "malformed resolved input"}}


def _evaluate(spec, target, contract, domain, facts):
    result = {"outcome": "uncovered", "target_ref": ref(target), "spec_ref": ref(spec),
              "contract_ref": ref(contract), "domain_ref": ref(domain),
              "derivation": {"report": [], "quiet": [], "paths": []}, "missing_facts": []}
    trace = result["derivation"]
    if contract["approval_status"] != "approved" or contract["subject"] != target["subject"]:
        result["missing_facts"].append({"fact_id": ref(contract), "reason": "unapproved_or_wrong_subject"})
        return result

    by_path = {path: {} for path in domain["paths"]}
    symbols = {"reaches": "bool", "feasible": "bool"}
    try:
        for c in spec["clauses"]:
            ir.clause(c)
            for name, typ in c["bindings"].items():
                ir.check(symbols.setdefault(name, typ) == typ, name, "inconsistent binding type")
        for f in facts:
            scope = (f["target_ref"], f["subject"], f["domain_ref"], f["contract_ref"])
            if scope != (ref(target), target["subject"], ref(domain), ref(contract)):
                continue
            slot, path = f["relation"], f["path_scope"]["path_id"]
            ir.operand(f)
            ir.check(slot not in symbols or symbols[slot] == f["typed_operands"]["type"],
                     ref(f), "fact type mismatch")
            ir.check(path in by_path, ref(f), "unknown path")
            by_path[path].setdefault(slot, []).append(f)
    except Diagnostic as error:
        return {**result, "outcome": "invalid_ir", "diagnostic": error.detail}

    protected_paths = []
    for path, scoped in sorted(by_path.items()):
        b = PathBindings(scoped)
        proven = {role: [] for role in ir.ROLES}
        failed = []
        guard_matches = {}
        steps = []
        for c in sorted(spec["clauses"], key=ref):
            nodes = []
            app = expression(c["applicability"], b, nodes)
            test = expression(c["antecedent"], b, nodes)
            matches = conjunction([app, test])
            cid, role = ref(c), c["field"]
            steps.append({"clause": cid, "applicability": trace_value(app),
                          "condition": trace_value(test), "evaluations": nodes})
            if matches is True and c["direction"] in ("iff", "sufficient"):
                proven[role].append(cid)
            if role == "Guard":
                guard_matches[cid] = matches
                if app is True and test is False and c["direction"] in ("necessary", "iff"):
                    failed.append(cid)
        complete = spec["complete_guard_refs"]
        if complete and all(guard_matches[cid] is False for cid in complete):
            failed.extend(complete)
        feasible, reaches = b.value("feasible"), b.value("reaches")
        step = {"path_id": path, "subject": target["subject"], "clauses": steps,
                "facts": sorted(b.used), "feasible": trace_value(feasible), "reaches": trace_value(reaches),
                "failed_guards": sorted(set(failed)), "proven": proven}
        trace["paths"].append(step)
        if proven["Sink"] and proven["Guard"]:
            protected_paths.append(path)
        if all(proven[r] for r in ("Source", "Propagation", "Sink")) and failed and feasible is True and reaches is True:
            trace["report"].append(path)
        result["missing_facts"].extend({"path_id": path, "fact_id": key, "reason": reason}
                                       for key, reason in sorted(b.missing.items()))
    if by_path and len(protected_paths) == len(by_path) and domain["coverage"] != "partial" and domain["basis_refs"]:
        trace["quiet"] = protected_paths
        trace["coverage_basis"] = sorted(domain["basis_refs"])
    if not by_path or domain["coverage"] == "partial":
        result["missing_facts"].append({"fact_id": ref(domain), "reason": "incomplete_path_coverage"})
    if trace["report"] and trace["quiet"]:
        result["outcome"] = "spec_conflict"
    elif trace["report"]:
        result["outcome"] = "report"
    elif trace["quiet"]:
        result["outcome"] = "quiet"
    if result["outcome"] == "uncovered" and not result["missing_facts"]:
        result["reason"] = "no_closed_derivation"
    return result
