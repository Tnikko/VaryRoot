"""Typed expression grammar. A value is a variable, a boolean or a typed literal."""
from .checks import require

SIGNATURES = {
    "same_object": (("object", "object"), "bool"),
    "is_null": (("pointer",), "bool"),
    "blocked": (("bool",), "bool"),  # operand is a certified bypass fact
    "to_bytes": (("elements", "bytes_per_element"), "bytes"),
    "contains": (("bytes", "bytes", "bytes"), "bool"),  # capacity, offset, width
    "lt": (("bytes", "bytes"), "bool"),
    "eq_bytes": (("bytes", "bytes"), "bool"),
}
TYPES = {"bool", "object", "pointer", "elements", "bytes_per_element", "bytes"}
ROLES = {"Source", "Propagation", "Guard", "Sink"}

# Meanings of analysis facts, never names of variables to declare in C/C++.
FACT_SEMANTICS = {
    "source": "Analysis fact: the declared source condition holds on this path.",
    "sink": "Analysis fact: the target memory operation is the declared sink.",
    "source_object": "Analysis identity of the source object.",
    "sink_object": "Analysis identity of the object used by the sink.",
    "call_output_slot": "Analysis identity of the output slot reached by a call.",
    "sink_base": "Analysis identity of the base object used by the sink.",
    "check_seen": "Analysis fact: a relevant check is evaluated before the target; it may or may not block the unsafe path.",
    "blocked": "Analysis fact: the unsafe path is prevented from reaching the target.",
    "loop_direct": "Analysis fact: a loop condition directly enforces the declared guard before target evaluation.",
    "total_guard": "Analysis fact: a guard constrains total logical extent, without necessarily constraining the remaining extent.",
    "remaining_guard": "Analysis fact: a guard constrains logical extent remaining from the current position.",
    "reaches": "Analysis fact: this declared path reaches the target operation.",
    "feasible": "Analysis fact: this declared path is feasible within its stated domain.",
    "operand": "Analysis value of the pointer operand on the declared path, including null.",
    "capacity": "Analysis quantity: logical capacity in bytes.",
    "offset": "Analysis quantity: current byte offset from the logical base.",
    "width": "Analysis quantity: bytes read or written by the target operation.",
}


def check(ok, field, reason):
    require(ok, field, reason, "invalid_ir")


def value_type(t, v, path):
    check(isinstance(t, str) and t in TYPES, path, "unknown operand type")
    if t == "bool":
        ok = type(v) is bool
    elif t in {"pointer", "object"}:
        ok = isinstance(v, str) and bool(v) or (t == "pointer" and v is None)
    else:
        ok = type(v) is int and (t != "bytes_per_element" or v > 0)
    check(ok, path, "value does not match declared type")


def expression_type(expr, bindings, path):
    if type(expr) is bool:
        return "bool"
    check(isinstance(expr, dict), path, "expected expression")
    if set(expr) == {"var"}:
        name = expr["var"]
        check(isinstance(name, str) and name in bindings, path, "undeclared variable")
        return bindings[name]
    if set(expr) == {"type", "value"}:
        value_type(expr["type"], expr["value"], path)
        return expr["type"]
    check(set(expr) == {"op", "args"} and isinstance(expr["op"], str), path, "invalid operator")
    op, args = expr["op"], expr["args"]
    check(isinstance(args, list), path, "expected operands")
    types = tuple(expression_type(a, bindings, f"{path}.args[{i}]") for i, a in enumerate(args))
    if op in ("and", "or", "not"):
        check(bool(types) and all(t == "bool" for t in types) and
              (op != "not" or len(types) == 1), path, "invalid logical operands")
        return "bool"
    check(op in SIGNATURES and types == SIGNATURES[op][0], path, "incompatible signature")
    return SIGNATURES[op][1]


def clause(c):
    bindings = c["bindings"]
    check(isinstance(bindings, dict) and all(isinstance(t, str) and t in TYPES
          for t in bindings.values()), "bindings", "invalid symbol table")
    check(c["field"] in ROLES and c["consequent"] == c["field"], "field", "invalid consequent")
    check(c["direction"] in ("iff", "necessary", "sufficient"), "direction", "unknown direction")
    for key in ("applicability", "antecedent"):
        check(expression_type(c[key], bindings, key) == "bool", key, "expected proposition")


def operand(fact):
    arg = fact["typed_operands"]
    check(isinstance(arg, dict) and "type" in arg, "typed_operands", "missing type")
    if set(arg) == {"type", "missing"}:
        check(isinstance(arg["missing"], str) and bool(arg["missing"]) and arg["type"] in TYPES,
              "typed_operands", "invalid missing value")
    else:
        check(set(arg) == {"type", "value"}, "typed_operands", "expected value or missing")
        value_type(arg["type"], arg["value"], "typed_operands")
