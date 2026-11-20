"""Pre-oracle generation with deterministic static feedback."""

import hashlib
import json

from .b_factor_gate import classify
from .b_prompt import build_request, hypothesis_pair


def source_sha256(source):
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    normalized = "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def run(before, after, contract, first, second, policy, invoke, inspect):
    """Inspect proposals using trusted Clang evidence and pure IR predictions."""
    retries = policy["max_retries"]
    minimum = policy.get("min_divergent", policy.get("min_hard_divergent"))
    target = policy.get("divergence_target", "hard")
    if type(retries) is not int or retries < 0 or type(minimum) is not int or minimum < 1:
        raise ValueError("invalid_generation_budget")
    pair_digest = hashlib.sha256(json.dumps(hypothesis_pair(first, second), sort_keys=True).encode()).hexdigest()
    if target not in ("hard", "coverage") or target == "coverage" and (
            policy.get("coverage_pair_sha256") != pair_digest or
            not isinstance(policy.get("coverage_evidence_ref"), str) or
            not policy["coverage_evidence_ref"].strip()):
        raise ValueError("unregistered_divergence_target")
    seen = {source_sha256(before), source_sha256(after)}
    rows, feedback, response_failures = [], [], 0
    for attempt in range(retries + 1):
        response = invoke(build_request(policy, before, after, contract, first, second, feedback))
        proposals = response.get("proposals") if isinstance(response, dict) else None
        if not isinstance(proposals, list):
            proposals = []
            response_failures += 1
        round_feedback = []
        for index, proposal in enumerate(proposals):
            row = {"round": attempt, "index": index, "parent": None, "factor": None,
                   "intent": None, "source": None, "source_sha256": None,
                   "status": "undetermined", "reason": "invalid_proposal_schema",
                   "touched_roles": [], "predictions": None,
                   "hard_divergent": False, "coverage_divergent": False}
            if isinstance(proposal, dict):
                for key in ("parent", "factor", "intent", "source"):
                    row[key] = proposal.get(key)
            valid = (isinstance(proposal, dict) and
                     set(proposal) == {"parent", "factor", "intent", "source"} and
                     all(isinstance(proposal[key], str) and proposal[key] for key in proposal))
            if valid:
                row["source_sha256"] = source_sha256(proposal["source"])
                if index >= policy["max_proposals_per_round"]:
                    row.update(status="confounded", reason="proposal_limit_exceeded")
                elif proposal["parent"] not in ("before", "after"):
                    row.update(status="confounded", reason="invalid_parent")
                elif row["source_sha256"] in seen:
                    row.update(status="confounded", reason="duplicate_or_unchanged_source")
                else:
                    seen.add(row["source_sha256"])
                    static = inspect(proposal["source"], proposal["parent"])
                    row.update(classify(static["clang_receipt"]))
                    pair = static.get("predictions")
                    if row["status"] == "admitted":
                        if not (isinstance(pair, (tuple, list)) and len(pair) == 2 and
                                all(p in ("report", "quiet", "uncovered") for p in pair)):
                            row.update(status="undetermined", reason="static_prediction_unavailable")
                        else:
                            row["predictions"] = list(pair)
                            row["hard_divergent"] = tuple(pair) in (("report", "quiet"), ("quiet", "report"))
                            row["coverage_divergent"] = ("uncovered" in pair and
                                                          any(p in ("report", "quiet") for p in pair))
                            if not row["hard_divergent"] and not row["coverage_divergent"]:
                                row["reason"] = "same_static_prediction"
            rows.append(row)
            round_feedback.append({"index": index, "intent": str(row["intent"] or "")[:160],
                                   "reason": row["reason"], "touched_roles": row["touched_roles"],
                                   "predictions": row["predictions"]})
        if sum(row[target + "_divergent"] for row in rows) >= minimum:
            break
        feedback = round_feedback
    counts = {state: sum(row["status"] == state for row in rows)
              for state in ("admitted", "confounded", "undetermined")}
    return {"rows": rows, "raw": len(rows), **counts,
            "hard_divergent": sum(row["hard_divergent"] for row in rows),
            "coverage_divergent": sum(row["coverage_divergent"] for row in rows),
            "retry_rounds": attempt, "response_failures": response_failures,
            "divergence_target": target, "hypothesis_pair_sha256": pair_digest,
            "coverage_evidence_ref": policy.get("coverage_evidence_ref") if target == "coverage" else None,
            "unresolved": sum(row[target + "_divergent"] for row in rows) < minimum,
            "backend_gap": sum(row["reason"] == "static_prediction_unavailable" for row in rows)}
