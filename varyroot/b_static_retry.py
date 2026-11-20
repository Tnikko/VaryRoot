"""Pre-oracle generation loop with fixed static feedback and no verdict input."""

from .b_prompt import build_request
from .b_factor_gate import classify


def run(before, after, contract, first, second, policy, invoke, inspect):
    """Invoke a model through an injected client and inspect every raw proposal.

    inspect(source, parent) returns trusted Clang receipt plus pure IR predictions.
    It has no dynamic verifier or ledger capability.
    """
    attempts = policy["max_retries"] + 1
    if type(policy["max_retries"]) is not int or policy["max_retries"] < 0:
        raise ValueError("invalid_retry_budget")
    if type(policy["min_hard_divergent"]) is not int or policy["min_hard_divergent"] < 1:
        raise ValueError("invalid_divergence_target")
    feedback = []
    rows = []
    response_failures = 0
    for attempt in range(attempts):
        request = build_request(policy, before, after, contract, first, second, feedback)
        response = invoke(request)
        proposals = response.get("proposals") if isinstance(response, dict) else None
        if not isinstance(proposals, list):
            proposals = []
            response_failures += 1
        round_feedback = []
        for index, proposal in enumerate(proposals):
            if (not isinstance(proposal, dict) or
                    set(proposal) != {"parent", "factor", "intent", "source"} or
                    any(not isinstance(value, str) or not value
                        for value in proposal.values())):
                row = {"round": attempt, "index": index, "status": "undetermined",
                       "reason": "invalid_proposal_schema", "hard_divergent": False}
            else:
                static = inspect(proposal["source"], proposal["parent"])
                gate = classify(static["clang_receipt"])
                pair = static.get("predictions")
                valid_pair = (isinstance(pair, (tuple, list)) and len(pair) == 2 and
                              all(value in ("report", "quiet", "uncovered") for value in pair))
                if gate["status"] == "admitted" and not valid_pair:
                    gate = {"status": "undetermined", "reason": "static_prediction_unavailable"}
                hard = gate["status"] == "admitted" and tuple(pair) in (("report", "quiet"), ("quiet", "report"))
                row = {"round": attempt, "index": index, **gate, "hard_divergent": hard,
                       "predictions": pair if gate["status"] == "admitted" else None}
                if gate["status"] == "admitted" and not hard:
                    row["reason"] = "same_or_uncovered_prediction"
            rows.append(row)
            round_feedback.append({"index": index, "reason": row["reason"]})
        if sum(row["hard_divergent"] for row in rows) >= policy["min_hard_divergent"]:
            break
        feedback = round_feedback
    counts = {state: sum(row["status"] == state for row in rows)
              for state in ("admitted", "confounded", "undetermined")}
    return {"rows": rows, "raw": len(rows), **counts,
            "hard_divergent": sum(row["hard_divergent"] for row in rows),
            "retry_rounds": attempt, "response_failures": response_failures,
            "unresolved": sum(row["hard_divergent"] for row in rows) < policy["min_hard_divergent"],
            "backend_gap": sum(row["reason"] == "static_prediction_unavailable" for row in rows)}
