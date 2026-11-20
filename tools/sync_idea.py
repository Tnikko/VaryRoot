"""Refresh the Markdown description of the interactive design, or pass --check."""
import argparse
import html
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "<!-- BEGIN synchronized framework -->"
END = "<!-- END synchronized framework -->"


def table_row(values):
    return "| " + " | ".join(value.replace("|", r"\|") for value in values) + " |"


def script_data(page, name):
    match = re.search(r"^const " + name + r"=(.*);$", page, re.M)
    if not match:
        raise ValueError(f"Cannot find framework data: {name}")
    return json.loads(match[1])


def describe_plan(page):
    lines = ["### 详细设计与执行计划（待审核）", "",
             "四个建设里程碑依次为类型与工件、协调与提取、校准内环、查询外环。详细设计按六项工作审核：共用接口与 IR、协调器、前端与 A、独立验证器、B、C。执行计划把第一项拆为工件契约和解释器，因此落地时共有七步。首批待审成果为字段契约、状态语义表，以及 NPD、OOB 各一条贯穿实例。[展开执行计划](execution-plan.html)", ""]
    for section in re.findall(r"<details\b[^>]*>(.*?)</details>", page, re.S):
        title = re.search(r"<strong>(.*?)</strong>", section)[1]
        dependency = re.search(r"<small>(.*?)</small>", section)[1]
        number = re.search(r'<span class="num">(\d+)</span>', section)[1]
        lines.extend([f"**{number} · {title}**（{dependency}）", ""])
        for field, value in re.findall(r"<dt>(.*?)</dt><dd>(.*?)</dd>", section, re.S):
            lines.append(f"- **{field}**　{html.unescape(value)}")
        lines.append("")
    if not any("完成条件" in line for line in lines):
        raise ValueError("Execution plan has no acceptance criteria")
    return lines


def shared_section():
    page = (ROOT / "framework.html").read_text(encoding="utf-8")
    plan = (ROOT / "execution-plan.html").read_text(encoding="utf-8")
    flows = script_data(page, "subprocesses")
    lines = [BEGIN, "### 全流程与模块交接", "",
             "协调器负责提交状态。A 登记种子并交付 S₀ 与候选解释；B 先提交选择，再取得独立证据，交付 S* 或带原因的未决结果。C 分别编译两版规约，让 Q₀ 与 Q* 在同一批目标位置接受各自的回归门禁。冻结后的独立评测属于后续阶段。[打开交互总图](framework.html)", "",
             "| 模块 | 读取 | 交付 |", "| --- | --- | --- |"]
    for record in script_data(page, "records"):
        lines.append(table_row([record[1], record[3], record[4]]))
    lines.extend(["", "规约推导沿 TargetRef → Fact → Clause → Prediction 进行。独立取证以相同的目标位置和已核准契约为起点，在声明域内由 Observation 形成 Verdict。两条记录在 Decision 汇合。若形成 Revision，须列出改变的判断、应保持的判断和新增事实需求。协调器在重试时复用已提交的选择与预算记录。", ""])
    for agent, flow in flows.items():
        lines.extend([f"### Agent {agent} · {flow['name']}", "",
                      "| 步骤与执行者 | 输入 → 交付 | 判断与分支去向 |", "| --- | --- | --- |"])
        for idx, (name, role, inputs, outputs, logic, branches) in enumerate(flow["steps"], 1):
            destinations = []
            for label, target in branches:
                if isinstance(target, str):
                    key, index = target.split(":")
                    dest = f"{key}{int(index) + 1}"
                else:
                    dest = "部分结果" if target == -1 else f"{agent}{target + 1}"
                destinations.append(f"{label} → {dest}")
            desc = logic + ("<br>" + "<br>".join(destinations) if destinations else "")
            actor = "大模型" if role == "模型" else "确定性程序"
            lines.append(table_row([f"**{agent}{idx} {name}**<br>{actor}", f"{inputs}<br>→ {outputs}", desc]))
        lines.extend(["", "**停止时交付**　" + flow["stop"], ""])
    lines.extend(describe_plan(plan))
    lines.extend(["**整体验收**　分别走查正常修订、有据保留、证据未决和后端缺口。对成功冻结的修订，既能从查询变化反向定位到原始访问，也能从原证据正向重放规约决定。", "", END])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "IDEA.md"
    original = path.read_text(encoding="utf-8")
    if original.count(BEGIN) != 1 or original.count(END) != 1:
        raise ValueError("Expected exactly one delimited framework section")
    start = original.index(BEGIN)
    finish = original.index(END, start) + len(END)
    updated = original[:start] + shared_section() + original[finish:]
    if args.check and updated != original:
        raise SystemExit("IDEA.md differs from the interactive design")
    if updated != original:
        temp = path.with_name("IDEA.md.sync-tmp")
        with temp.open("x", encoding="utf-8", newline="\n") as out:
            out.write(updated)
        temp.replace(path)
    print("IDEA.md and the interactive design agree.")


if __name__ == "__main__":
    main()
