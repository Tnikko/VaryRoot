"""Shared Clang admission and pure IR prediction adapter for Agent B."""

from .b_clang_receipt import make_receipt
from .b_factor_gate import classify
from .b_prompt import strip_source_comments


def make_inspector(packet, config, parents, compile_variant, extract, predict):
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
        facts, predictions, error = None, None, None
        try:
            facts = extract(source, candidate_ast, candidate_cfg,
                            receipt["target_lines"][1], config)
            predictions = predict(packet, facts)
        except (KeyError, TypeError, ValueError) as exc:
            error = str(exc) if isinstance(exc, ValueError) else "static_prediction_unavailable"
        return {"clang_receipt": receipt, "facts": facts if predictions is not None else None,
                "predictions": predictions, "static_error": error}

    return inspect
