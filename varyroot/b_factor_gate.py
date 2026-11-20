"""Conservative admission of trusted Clang AST and CFG difference receipts."""


PROTECTED = {"target", "contract_call", "object", "loop_state", "unrelated"}
ALLOWED = {"guard", "control_flow"}


def classify(receipt):
    """Return admitted, confounded, or undetermined with deterministic reasons.

    The receipt is produced by a Clang adapter, never by the proposing model.
    Each edit group is a semantic region containing AST node changes.
    """
    if receipt.get("producer") != "clang_ast" or not receipt.get("compile_ok"):
        return {"status": "undetermined", "reason": "compile_or_ast_unavailable"}
    groups = receipt.get("edit_groups")
    if isinstance(groups, list) and any("target" in group.get("roles", []) for group in groups):
        return {"status": "confounded", "reason": "protected_semantics_changed",
                "touched_roles": ["target"]}
    if receipt.get("target_binding") != "exact_1to1":
        return {"status": "undetermined", "reason": "target_binding_unproven"}
    if not isinstance(groups, list) or not groups:
        return {"status": "undetermined", "reason": "missing_ast_difference"}
    if len(groups) != 1:
        return {"status": "confounded", "reason": "multiple_changed_regions",
                "touched_roles": sorted({role for group in groups for role in group.get("roles", [])})}
    group = groups[0]
    roles = set(group.get("roles", []))
    if not roles or not roles <= PROTECTED | ALLOWED:
        return {"status": "undetermined", "reason": "unclassified_ast_change"}
    if roles & PROTECTED:
        return {"status": "confounded", "reason": "protected_semantics_changed",
                "touched_roles": sorted(roles & PROTECTED)}
    if not roles <= ALLOWED:
        return {"status": "undetermined", "reason": "unsupported_change"}
    if group.get("contains_goto"):
        cfg = receipt.get("cfg")
        if not isinstance(cfg, dict) or cfg.get("producer") != "clang_cfg":
            return {"status": "undetermined", "reason": "goto_cfg_unavailable"}
        if cfg.get("target_reachability_changed") is not False:
            return {"status": "confounded", "reason": "goto_changes_target_reachability"}
        if cfg.get("equivalent_blocking") is not True:
            return {"status": "undetermined", "reason": "goto_equivalence_unproven"}
    return {"status": "admitted", "reason": "single_static_factor",
            "touched_roles": sorted(roles)}
