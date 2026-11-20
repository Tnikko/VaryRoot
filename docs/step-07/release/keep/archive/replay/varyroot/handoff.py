from .checks import require

OUTCOMES = ("report", "quiet", "uncovered")


def revision(item, get):
    decision = get(item["trigger_decision_id"], "Decision")
    require(decision["action"] == "revise" and decision["parent_spec_ref"] == item["parent_spec_ref"]
            and item["new_spec_ref"] != item["parent_spec_ref"], "parent_spec_ref", "revision parent mismatch")
    seen = set()
    for key in ("changed_judgments", "preserved_judgments"):
        require(isinstance(item[key], list), key, "expected judgment array")
        for entry in item[key]:
            require(isinstance(entry, list) and len(entry) == 4, key, "expected four fields")
            target, old, new, verdict = entry
            get(target, "TargetRef")
            v = get(verdict, "Verdict")
            identity = (target, v["domain_ref"], v["contract_ref"])
            require(v["target_ref"] == target and v["label"] in ("positive", "negative")
                    and identity not in seen, key, "duplicate or incompatible verdict")
            require(old in OUTCOMES and new in OUTCOMES and
                    (old != new) == (key == "changed_judgments"), key, "invalid partition")
            seen.add(identity)


def handoff(item, get):
    d = get(item["decision_ref"], "Decision")
    action = d["action"]
    final, initial = item["final_spec_ref"], item["initial_spec_ref"]
    revision_ref = item["revision_ref"]
    require(action in ("keep", "revise", "unresolved"), "decision_ref", "not a handoff decision")
    ready = action != "unresolved"
    require(d["next_state"] == ("spec_ready" if ready else "unresolved"),
            "next_state", "decision cannot enter requested state")
    if action == "revise":
        r = get(revision_ref, "Revision")
        require(r["trigger_decision_id"] == item["decision_ref"] and
                r["new_spec_ref"] == final, "revision_ref", "revision does not match handoff")
        ancestor = r["parent_spec_ref"]
        visited = set()
        while ancestor != initial:
            require(ancestor and ancestor not in visited, "initial_spec_ref", "baseline outside parent chain")
            visited.add(ancestor)
            ancestor = get(ancestor, "Spec").get("parent_spec_ref")
    else:
        require(revision_ref is None, "revision_ref", "expected explicit null")
        if ready:
            require(initial == final == d["parent_spec_ref"], "final_spec_ref", "keep requires original version")
        else:
            require(final is None, "final_spec_ref", "unresolved cannot release a spec")
