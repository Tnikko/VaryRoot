"""One reasoning view for counterfactual generation across defect families."""

import json
import re


_AUDIT = re.compile(r"source_lock|sha256|https?://|[0-9a-f]{64}", re.I)


def strip_source_comments(source):
    """Remove C/C++ comments while preserving strings, chars and line breaks."""
    out, index, state = [], 0, "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code" and char == 'R' and next_char == '"':
            raise ValueError("raw_string_source_unsupported")
        if state == "code" and char == "/" and next_char in ("/", "*"):
            state = "line" if next_char == "/" else "block"
            out.extend((" ", " "))
            index += 2
            continue
        if state in ("line", "block"):
            if state == "block" and char == "*" and next_char == "/":
                out.extend((" ", " "))
                index += 2
                state = "code"
                continue
            if char == "\n":
                out.append(char)
                if state == "line":
                    state = "code"
            else:
                out.append(" ")
            index += 1
            continue
        out.append(char)
        if char in ('"', "'") and state == "code":
            state = char
        elif char == "\\" and state in ('"', "'") and next_char:
            out.append(next_char)
            index += 2
            continue
        elif char == state and state in ('"', "'"):
            state = "code"
        index += 1
    if state == "block":
        raise ValueError("unterminated_source_comment")
    return "".join(out)


def _term(value):
    if type(value) is bool:
        return value
    if not isinstance(value, dict):
        raise ValueError("invalid_ir_term")
    if set(value) == {"var"}:
        return {"var": value["var"]}
    if set(value) == {"type", "value"}:
        return {"type": value["type"], "value": value["value"]}
    if set(value) == {"op", "args"}:
        return {"op": value["op"], "args": [_term(item) for item in value["args"]]}
    raise ValueError("invalid_ir_term")


_ROLES = ("Source", "Propagation", "Guard", "Sink")


def _clause_view(spec):
    view = {}
    for role in _ROLES:
        rows = [row for row in spec["clauses"] if row["field"] == role]
        view[role] = [{"bindings": dict(row["bindings"]), "direction": row["direction"],
                       "applicability": _term(row["applicability"]),
                       "antecedent": _term(row["antecedent"])} for row in rows]
    if not view["Guard"]:
        raise ValueError("missing_guard")
    return view


def hypothesis_pair(left, right):
    """Project all four IR roles from resolved clauses without record metadata."""
    a, b = _clause_view(left), _clause_view(right)
    if a == b:
        raise ValueError("indistinguishable_hypotheses")
    return {"first": a, "second": b,
            "difference": {role: {"first_only": [x for x in a[role] if x not in b[role]],
                                 "second_only": [x for x in b[role] if x not in a[role]]}
                           for role in _ROLES}}


def render_messages(before, after, contract, first, second, feedback=None, max_proposals=6):
    """Build a strict allowlist view. Caller audit fields never enter messages."""
    if not isinstance(before, str) or not isinstance(after, str) or not before or not after:
        raise ValueError("missing_source")
    if type(max_proposals) is not int or not 1 <= max_proposals <= 20:
        raise ValueError("invalid_proposal_limit")
    fields = ("object", "extent", "unit", "operation", "nullability", "success", "capacity")
    semantics = {key: contract[key] for key in fields if key in contract}
    if not {"object", "operation"} <= semantics.keys():
        raise ValueError("missing_contract_semantics")
    if any(not isinstance(value, (str, int)) or type(value) is bool or
           len(str(value)) > 200 or _AUDIT.search(str(value)) for value in semantics.values()):
        raise ValueError("audit_or_invalid_contract_view")
    if feedback is not None and not isinstance(feedback, list):
        raise ValueError("invalid_feedback")
    task = {
        "before": strip_source_comments(before), "after": strip_source_comments(after),
        "contract": semantics,
        "hypotheses": hypothesis_pair(first, second),
        "instructions": (
            "Propose local single-factor source variants that distinguish the two hypotheses. "
            "Keep the target operation, object, contract call, and unrelated program state fixed. "
            f"Return at most {max_proposals} proposals in one JSON object. "
            "Each proposal has parent, factor, "
            "intent, and complete source. Give no safety label or expected oracle result."
            " The parent value must be before or after."
        ),
    }
    if feedback:
        task["static_feedback"] = feedback
    return [
        {"role": "system", "content": "Generate C or C++ counterfactual proposals as JSON only."},
        {"role": "user", "content": json.dumps(task, ensure_ascii=False, sort_keys=True)},
    ]


def build_request(policy, before, after, contract, first, second, feedback=None):
    """Construct the complete provider request from declared generation settings."""
    model = policy["model"]
    max_tokens = policy["max_tokens"]
    if not isinstance(model, str) or not model or type(max_tokens) is not int or max_tokens < 1:
        raise ValueError("invalid_model_settings")
    request = {"model": model, "max_tokens": max_tokens,
               "response_format": {"type": "json_object"},
               "messages": render_messages(before, after, contract, first, second, feedback,
                                           policy["max_proposals_per_round"])}
    for key in ("temperature", "top_p"):
        if key in policy:
            value = policy[key]
            if type(value) not in (int, float) or not 0 <= value <= (2 if key == "temperature" else 1):
                raise ValueError("invalid_model_settings")
            request[key] = value
    return request
