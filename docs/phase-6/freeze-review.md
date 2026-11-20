# C6 · 成对冻结、部分交付与六阶段走查

本页是阶段 6 的第四项交付，也承载六个阶段的设计终审。以下四条路径采用本地合成位置及指定的观测与查询输出；实际工具链集成留在编码后的验收中。

## 冻结协议

| 冻结清单 | 最低可复核内容 |
| --- | --- |
| 研究输入 | seed、组／重复／父版本、S₀、S*、Decision、Revision 或 keep 依据、重建链、合格裁决及证据水位、全部开发位置 M 与旁表 |
| 实现与运行环境 | 两版查询及传递依赖、同一公共谓词库和条款映射、解释器与能力表、源码快照、构建配置、数据库可取回对象及摘要、提取器与 CLI／包版本、运行命令与必要环境。保存同一数据库快照用于重跑；从源码重建数据库另作语义等价验收 |
| 回归依据 | 默认行为、位置映射与匹配器版本、原始输出、逐位置五列表、双版通过记录、预算／重试账本与实际构建成本。保留未定、不可计分和目标外诊断的归属 |
| 包身份与复取 | 清单使用规定的规范序列化、相对工件名、版本和内容摘要。登记模式版本、哈希算法、打包命令和恢复入口；逐项验证依赖可取回并验算字节摘要。内容摘要用于检测变更，读取与发布权限由协调器控制 |

C6 先核对 B6 状态、本组 M 完整且非空、两侧各自 lane_pass 的依赖摘要及共同数据库／库／匹配口径。keep 分支还须核对查询行为在全部已登记确定位置一致；两侧复用同一完整实现时应有相同的查询核心摘要。revise 分支核对每一项代码和观测差异与条款依赖，无法解释的差异回 C1/C5。冻结前发现某版仍在修复，整组保持处理中；不能越过该版签发编号。

先暂存、校验并持久化包，继承阶段 2 的发布与恢复协议。最后一个数据库事务复查输入水位、双版门禁和工件 ready 状态，并对运行分支及通过的清单摘要建立唯一约束，同步提交 frozen、冻结编号和可见性。重试同一已通过清单取回同一个编号；中断后先按发布意图恢复。旧水位／异摘要重试不得覆盖已冻结包，另开有父引用的版本。独立评测只读取已提交的冻结记录。

partial 有运行 ID、失败版、目标、实际输出或缺失原因、已用与剩余预算、可复核的成功部分及下一责任模块。分别记录 compile_failure、run_failure、unalignable、backend_gap、regression_failure、budget_exhausted，可并列。单版已通过仍保存其结果。任何未通过的整组都不签发冻结编号。设计走查用占位状态 frozen 表示可签发，不生成真实研究编号。

## 四条跨模块路径

| 路径 | A 与独立验证器 | B 的决定 | C 的五列要点与最终去向 |
| --- | --- | --- | --- |
| 正常修订 | 种子前后通过 A4/A6；同对象 NPD 检查后继续有违规见证，提前退出有域内阻断与正常到达见证 | 旧“检查即保护”在继续位置为 quiet，新条款为 report。B6 核对改变和保持的全部位置 | 继续位置 positive；Q₀ 的 quiet／无默认／无缺口／no_alert 计 FN；Q* 的 report／无默认／无缺口／hit 计 TP。其他确定位置也通过后成对冻结 |
| 有据保留 | 有效退出、等价绕行及继续访问的区分证据合格 | 初始条款已要求阻断或有效恢复，关键分歧有裁决，B6 全部通过，keep 无 Revision | 两版同一语义键复用同一谓词，逐位置完全一致。确认同一输入与实测后成对冻结 |
| 证据未决 | 种子本身可接受；开发位置尚有未观测的故障组合，缺完整覆盖依据 | 关键开发裁决 pending，仍有实质分歧且预算耗尽，unresolved | B 交部分结果。无 spec_ready、无 C 构建，C 的五列实测及冻结号均不产生 |
| 后端缺口 | 同对象容量 8 字节、偏移 6，宽度 2 的完整域为 negative，宽度 3 有 positive 见证 | 1B 有宽度事实，修订完整区间条款，B6 通过 | 假设 Q* 所用数据库无法提供宽度，其余查询可运行、目标可唯一对齐。宽度 3 记录 positive／report／无默认／width_unavailable／no_alert，计 FN，整组 partial。若连查询都无法运行则记 unavailable，保留该位置并单列不可计分 |

## 可重放的门禁检查

下列 Python 块给出小型参考判定。输入是人工指定的设计向量；映射向量的候选集代表后端能区分的访问身份。实际构建、提取及进程恢复不在这些向量内。

~~~python
from itertools import product
from collections import Counter

def alignment(target, identities, alerts, complete=True):
    if not complete:
        return "unavailable"
    relevant = [k for k, candidates in identities.items() if target in candidates]
    if not relevant or any(len(identities[k]) != 1 for k in relevant):
        return "unavailable"
    return "hit" if any(k in alerts for k in relevant) else "no_alert"

def row(lane, verdict, prediction, gap, actual):
    expected = "hit" if prediction == "report" else "no_alert"
    default = "no_alert" if prediction == "uncovered" else None
    valid_actual = actual in ("hit", "no_alert")
    score = None
    if valid_actual:
        score = {("positive", "hit"): "TP", ("positive", "no_alert"): "FN",
                 ("negative", "hit"): "FP", ("negative", "no_alert"): "TN"}[verdict, actual]
    reasons = set()
    correct = "report" if verdict == "positive" else "quiet"
    if lane == "star" and prediction != correct:
        reasons.add("B4")
    if gap:
        reasons.add("backend_gap")
    if not valid_actual:
        reasons.add("unavailable")
    elif actual != expected and not gap:
        reasons.add("implementation")
    return default, score, reasons

def finish(decision, members, baseline, final, current=True, shared=True):
    if decision not in {"keep", "revise"}:
        return "stop_B"
    if not members or not current or not shared:
        return "blocked"
    for rows in (baseline, final):
        if set(rows) != members or any(rows.values()):
            return "blocked"
    return "frozen"

unique = {"left": {"t1"}, "right": {"t2"}}
macro = {"same_span": {"t1", "t2"}}
assert alignment("t1", unique, ["right"]) == "no_alert"
assert alignment("t2", unique, ["right", "right"]) == "hit"
assert alignment("t1", macro, ["same_span"]) == "unavailable"
assert alignment("t2", macro, []) == "unavailable"
assert alignment("t3", unique, []) == "unavailable"
assert alignment("t1", unique, [], False) == "unavailable"

counts = Counter()
for lane, v, p, gap, output in product(
        ("base", "star"), ("positive", "negative"), ("report", "quiet", "uncovered"),
        (False, True), ("hit", "no_alert", "unavailable")):
    default, score, reasons = row(lane, v, p, gap, output)
    counts["rows"] += 1
    assert (default is not None) == (p == "uncovered")
    assert (score is None) == (output == "unavailable")
    if score:
        assert (score[0] == "T") == ((output == "hit") == (v == "positive"))
        assert (score[1] == "P") == (output == "hit")
    faithful = (p, output) in {("report", "hit"), ("quiet", "no_alert"),
                                ("uncovered", "no_alert")}
    admissible = lane == "base" or (v, p) in {("negative", "quiet"), ("positive", "report")}
    assert (not reasons) == (not gap and faithful and admissible)
    assert ("backend_gap" in reasons) == gap
    assert ("B4" in reasons) == (not admissible)
    counts["lane_pass"] += int(not reasons)

members = {"continue", "exit"}
old = {"continue": row("base", "positive", "quiet", False, "no_alert")[2],
       "exit": row("base", "negative", "quiet", False, "no_alert")[2]}
new = {"continue": row("star", "positive", "report", False, "hit")[2],
       "exit": row("star", "negative", "quiet", False, "no_alert")[2]}
kept = {"continue": row("base", "positive", "report", False, "hit")[2], "exit": old["exit"]}
assert finish("revise", members, old, new) == "frozen"
assert finish("keep", members, kept, new) == "frozen"
assert finish("unresolved", members, {}, {}) == "stop_B"
gap_row = row("star", "positive", "report", True, "no_alert")
assert gap_row == (None, "FN", {"backend_gap"})
assert finish("revise", {"wide"}, {"wide": set()}, {"wide": gap_row[2]}) == "blocked"
for base_ok, final_ok, current, shared in product((False, True), repeat=4):
    base = {"t": set() if base_ok else {"compile_failure"}}
    star = {"t": set() if final_ok else {"budget_exhausted", "regression_failure"}}
    result = finish("revise", {"t"}, base, star, current, shared)
    assert (result == "frozen") == all((base_ok, final_ok, current, shared))
assert finish("keep", set(), {}, {}) == "blocked"
assert finish("revise", members, {"exit": set()}, new) == "blocked"
assert row("base", "positive", "uncovered", False, "no_alert") == ("no_alert", "FN", set())
assert row("star", "negative", "report", False, "hit")[2] == {"B4"}
print(dict(counts), "alignment=6 paired_gate=16 cross_module_routes=4")
~~~

## 运行时验收留项

本次使用 CPython 3.13.16 重放上述参考判定。72 组确定位置组合中有 8 组通过本版位置门禁；6 个对齐向量、16 组双版冻结前提和 4 条跨模块路径的预期终态均通过断言。组合数描述设计边界，不代表样本量。四条路径的 A、验证器及 B 部分按表走读，程序从给定的决定、位置与查询输出开始核对 C 的终态。

编码后在同一数据库和真实双查询上核对表达式身份、宏碰撞、完整空结果与能力声明；对编译失败、超时、共享库升版、预算竞态、冻结事务提交前后强杀做集成检查。以空白工作区只读解包验摘要，重建查询、重跑已封存数据库并比较规范化的逐位置结果。另从源码重建数据库时记录环境与差异。研究效果由后续独立评测给出。
