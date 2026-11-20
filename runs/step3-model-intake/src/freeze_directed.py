"""Freeze admitted real-model C cases and interpreter predictions before any verdict."""
import json
from pathlib import Path

from admission import derive_facts
from directed_model_pool import classify_proposals
from model_client import write_once
from pool_admission import digest, make_case_facts, predictions
from prepare_model import canonical, prepare


def freeze(project, batch="step4d-directed-v2"):
    if batch not in ('step4d-directed-v2', 'step4d-directed-v3'):
        raise ValueError('unknown directed batch')
    pool_name = batch.removeprefix('step4d-')
    project = Path(project)
    output = project / "runs" / batch / "model-client/runs/step3-model-intake/out"
    report = json.loads((output / "directed-admission.json").read_bytes())
    payload = prepare(project)
    rows = [dict(row) for attempt in report["attempts"] for row in attempt["rows"]]
    if report["unique_global"] != classify_proposals(rows) or report["verdicts_revealed"]:
        raise ValueError("model admission or evidence boundary differs")
    derivations = {}
    admitted = []
    seen = set()
    for attempt in report["attempts"]:
        audit = json.loads((output / f'model-{attempt["call"]:02d}.ast-audit.json').read_bytes())
        source = output / "admission-attempts" / audit["request"] / "output/ast-results.json"
        extracted = json.loads(source.read_bytes())
        for row in rows:
            if row["call"] != attempt["call"] or row["status"] != "admitted":
                continue
            ast = extracted[row["id"]]
            if ast["ast_sha256"] != row["ast_sha256"] or ast["source_sha256"] != row["source_sha256"]:
                raise ValueError("Clang source or AST changed")
            fact = derive_facts(ast)
            case = make_case_facts(project, row["id"], fact)
            got = predictions(payload, case)
            if got != row["predictions"]:
                raise ValueError("registered prediction changed")
            row["target_ast_path"] = fact["target_ast_path"]
            row["class"] = "admitted_divergent" if row["pairs"] else "admitted_no_new_divergence"
            row["reason"] = "hard" if any(pair["kind"] == "hard_divergent" for pair in row["pairs"]) else "coverage" if row["pairs"] else "predictions_equal"
            row["included"] = row["semantic_sha256"] not in seen
            if row["included"]:
                seen.add(row["semantic_sha256"])
                admitted.append(row["id"])
            derivations[row["id"]] = dict(facts=case["facts"], target=case["target"],
                                           predictions=got, ast=fact)
    if not admitted or len(admitted) != report["unique_global"]["unique_admitted"]:
        raise ValueError("frozen denominator differs")
    pool = dict(pool=pool_name, seed_run=payload["seed_run"],
                seed_package_sha256=payload["seed_package_sha256"], proposal_ids=admitted,
                source_sha256={row["id"]: row["source_sha256"] for row in rows if row["id"] in admitted},
                ast_sha256={row["id"]: row["ast_sha256"] for row in rows if row["id"] in admitted},
                prediction_origin="deterministic_interpreter_on_clang18_facts",
                verdicts_revealed=False, observation_status="not_yet_verified")
    admission = dict(schema=1, rows=rows, frozen={pool_name: admitted})
    for name, data in (("derivations.json", derivations), ("admission.json", admission),
                       (f"pool-{pool_name}.json", pool)):
        write_once(output / name, canonical(data))
    refs = ["run-lock.json", "prompt.json", "directed-admission.json",
            "derivations.json", "admission.json", f"pool-{pool_name}.json"]
    refs.extend(f"model-{number:02d}.{part}.json" for number in (1, 2, 3)
                for part in ("request", "response", "meta", "ast-audit"))
    freeze_data = dict(schema=1, kind="pre_oracle_directed_real_model_pool", batch=batch,
                       seed_run=payload["seed_run"], pool_sizes={pool_name: len(admitted)},
                       file_sha256={name: digest((output / name).read_bytes()) for name in refs},
                       raw_proposals=report["counts"]["raw"],
                       admitted=report["counts"]["admitted"],
                       hard_divergent=report["counts"]["hard_divergent"],
                       verdicts_revealed=False)
    write_once(output / "freeze.json", canonical(freeze_data))
    return freeze_data


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--batch", choices=('step4d-directed-v2', 'step4d-directed-v3'), default='step4d-directed-v2')
    args = parser.parse_args()
    print(json.dumps(freeze(args.project, batch=args.batch), sort_keys=True))
