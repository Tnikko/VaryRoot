"""Register a new real-model C candidate pool before independent verification."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from admission import analyze_batch, derive_facts
from model_client import call, write_once
from pool_admission import (
    FIELDS, FACTORS, code_change, digest, make_case_facts,
    pairwise_divergence, predictions,
)
from prepare_model import canonical, prepare


def directed_prompt(payload, batch="step4d-directed"):
    skeletons = payload["skeletons"]
    if batch == "step4d-directed-v3":
        instruction = (
            "以所给 before 源码为基础，给出 4 到 6 个局部单因素变体。只修改内层 "
            "for(i = 0; bvals[i].bv_val != NULL; i++) 正前方的一处代码。"
            "原有 if(bv.bv_val == NULL) break;、外层 for 条件、声明、两次调用与目标表达式逐字符保留。"
            "各例仅插入一条关于 bvals 的判空语句。至少三例在 bvals 为空时判空后继续到首次目标求值，"
            "且正常非空时真实安全读取；至少一例判空后真正阻断目标。"
            "请用互不相同的实际 C 语句，例如空语句、只读取局部值的语句，避免空花括号。"
            "不要使用 `if (bvals == NULL) { }`，这条源码已有独立裁决。"
            "parent 选 before；factor 选 path_block_scope。不要写事实或预测。\n")
    else:
        instruction = (
            "以所给 before/after 源码为基础，给出 4 到 6 个局部单因素变体。"
            "只修改内层 for(i = 0; bvals[i].bv_val != NULL; i++) 正前方的一处代码。"
            "原有 if(bv.bv_val == NULL) break;、外层 for 条件、声明、两次调用与目标表达式逐字符保留。"
            "各例仅插入一条关于 bvals 的判空语句。覆盖判空后汇合并继续、判空后 break、"
            "判空后 return。可以尝试 goto，但需有真实可达的函数末尾返回标签。"
            "至少两例空输出时仍能到达首次目标求值，正常非空输出时仍实际安全读取。"
            "parent 选 before；factor 选 path_block_scope。"
            "不要写推断出的事实或预测。\n")
    return [
        {"role": "system", "content": (
            "你是 C 对照案例源码提案器。只返回 JSON 对象，含 proposals 数组。每项仅包含 "
            "parent、factor、intent、source。source 是完整 C 翻译单元。只提出源码与单因素意图。"
            "不要提供 Fact、标签、规约结果或调用工具。")},
        {"role": "user", "content": instruction
            + canonical({"before": skeletons["before"], "after": skeletons["after"]}).decode()},
    ]


def classify_proposals(rows):
    admitted = [row for row in rows if row.get("status") == "admitted"]
    seen = set()
    unique = []
    for row in admitted:
        key = row["semantic_sha256"]
        if key not in seen:
            seen.add(key)
            unique.append(row)
    hard = lambda row: any(pair["kind"] == "hard_divergent"
                           for pair in pairwise_divergence(row["predictions"]))
    return dict(raw=len(rows), admitted=len(admitted), unique_admitted=len(unique),
                hard_divergent=sum(map(hard, admitted)),
                unique_hard_divergent=sum(map(hard, unique)))


def run(project, *, batch="step4d-directed", calls=3, endpoint="https://api.deepseek.com"):
    project = Path(project)
    if batch not in ("step4d-directed", "step4d-directed-v2", "step4d-directed-v3"):
        raise ValueError("unregistered directed batch")
    payload = prepare(project)
    workspace = project / "runs" / batch / "model-client"
    output = workspace / "runs/step3-model-intake/out"
    output.mkdir(parents=True, exist_ok=True)
    messages = directed_prompt(payload, batch)
    lock = dict(schema=1, kind="new_directed_C_pool", batch=batch, seed=payload["seed_run"],
                seed_package_sha256=payload["seed_package_sha256"], model="deepseek-flash",
                thinking={"type": "disabled"}, reasoning_effort="high", max_tokens=16384,
                top_p=1.0, response_format={"type": "json_object"}, calls=calls,
                prompt_sha256=hashlib.sha256(canonical(messages)).hexdigest())
    for name, data in (("run-lock.json", lock), ("prompt.json", messages)):
        path = output / name
        if not path.exists():
            write_once(path, canonical(data))
        if path.read_bytes() != canonical(data):
            raise ValueError("directed model lock changed: " + name)

    attempts = []
    all_rows = []
    for number in range(1, calls + 1):
        meta_path = output / f"model-{number:02d}.meta.json"
        meta = json.loads(meta_path.read_bytes()) if meta_path.exists() else call(workspace, number, endpoint)
        attempt = dict(call=number, status=meta["status"], response_sha256=meta.get("response_sha256"))
        rows = []
        if meta["status"] == "valid_output":
            raw = json.loads((output / f"model-{number:02d}.response.json").read_bytes())
            items = json.loads(raw["choices"][0]["message"]["content"])["proposals"]
            for index, item in enumerate(items, 1):
                row = dict(id=f"d{number}p{index}", call=number)
                if isinstance(item, dict) and set(item) == FIELDS:
                    row.update(item)
                else:
                    row["status"] = "proposal_defect"
                rows.append(row)
            cases = {}
            for row in rows:
                if row.get("status") or row.get("parent") not in ("before", "after") \
                        or row.get("factor") not in FACTORS or not isinstance(row.get("source"), str):
                    row["status"] = "proposal_defect"
                    continue
                source = row["source"]
                row["source_sha256"] = digest(source)
                row["semantic_sha256"] = digest("".join(source.split()))
                change = code_change(payload["skeletons"][row["parent"]], source, row["factor"])
                if not change["single_factor"]:
                    row.update(status="proposal_defect", reason=change["reason"])
                    continue
                cases[row["id"]] = source
            if cases:
                extracted = analyze_batch(project, cases, f"step4d-directed-{number}",
                                          output / f"model-{number:02d}.ast-audit.json",
                                          run_output=output)
                for row in rows:
                    if row["id"] not in extracted:
                        continue
                    ast = extracted[row["id"]]
                    row["ast_status"] = ast["status"]
                    row["ast_sha256"] = ast.get("ast_sha256")
                    if ast["status"] != "valid":
                        row.update(status="unsupported_shape", reason=ast.get("diagnostic", ast["status"]))
                        continue
                    try:
                        facts = derive_facts(ast)
                        case = make_case_facts(project, row["id"], facts)
                        row["predictions"] = predictions(payload, case)
                        row["pairs"] = pairwise_divergence(row["predictions"])
                        row["status"] = "admitted"
                        row["target_span"] = facts["target_span"]
                    except ValueError as error:
                        row.update(status="unsupported_shape", reason=str(error))
        attempt["counts"] = classify_proposals(rows)
        attempt["rows"] = rows
        attempts.append(attempt)
        all_rows.extend(rows)
    totals = Counter()
    for attempt in attempts:
        totals.update(attempt["counts"])
    report = dict(schema=1, scope="new_real_model_C_candidates", seed=payload["seed_run"],
                  verdicts_revealed=False, counts=dict(totals), unique_global=classify_proposals(all_rows),
                  attempts=attempts)
    report_path = output / "directed-admission.json"
    if report_path.exists() and report_path.read_bytes() != canonical(report):
        raise ValueError("directed admission already frozen with other content")
    if not report_path.exists():
        write_once(report_path, canonical(report))
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--batch", choices=("step4d-directed", "step4d-directed-v2", "step4d-directed-v3"), default="step4d-directed")
    parser.add_argument("--calls", type=int, choices=(1, 2, 3), default=3)
    args = parser.parse_args()
    print(json.dumps(run(args.project, batch=args.batch, calls=args.calls)["counts"], sort_keys=True))
