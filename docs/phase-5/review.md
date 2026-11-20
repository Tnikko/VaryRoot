# B1–B6 · 正向、负向与返工走查

本页使用设计输入和预期裁决走查。R、Q、U 分别表示 report、quiet、uncovered。positive、negative、pending 是独立证据标签。各行属于说明中指定的独立情景，并非一次运行按行顺序揭示全部证据。

## 位置、证据与去向

| 输入与受控差异 | 预登记及合格证据 | 决定、版本与下游 |
| --- | --- | --- |
| 同一指针、日志和读取位置，N.log 记日志后继续，N.exit 记日志后退出 | 弱充分条款“检查即保护”对两处均 Q。以完整故障域内的阻断或恢复有效为保护，并声明其完备的解释，对两处分别 R、Q。独立证据为 log 的空值访问意图见证，以及 exit 的正常访问见证与完整故障路径阻断依据 | 两解释在 log 有硬分歧。弱条款被反驳，B5 提议修订。若本组清单恰为两个种子位置及这两个开发位置，则 changed 包含 log，preserved 含 exit 及两个种子。B6 核对四处后交 C |
| N.exit 改为同样绕过访问的 N.goto，保持正常访问与退出语义 | 仅有“提前 return 足以保护”的解释在 goto 为 U，缺少适用的充分证明。含充分的路径阻断条款的解释为 Q。确定反例可支撑扩域。改写前后可核对正常输入仍到达同一操作 | U/Q 贡献域差异，negative 不淘汰 U。若把 return 列为保护的必要条件，goto 使该必要形式为假，但故障分支没有 Reaches。只有这个条款时仍为 U，推导诊断与充分条件情景不同；若另有完整 quiet 证明则为 Q。登记为 R 的解释须先在 B4 核查推导忠实度。见[1B 闭合规则](../phase-1/inference.md) |
| 在确实到达目标的路径检验必要条件。仍用 N.log，另设已登记的弱条款“只要保护成立就必须检查 p”，与“保护必须阻断或恢复”对比 | 前者的必要形式在该路径为真，单凭该条款为 U。后者的必要条件被明确证伪，且源、传播、目标与到达均已绑定，得到 R。log 的独立正例证据只反驳明确的 Q | 此行检验必要条件的逻辑方向。U 可记录覆盖空白，不能以漏写推导代替明确的错误预测 |
| 起点相同、宽度 2 与 3，容量 8 字节，偏移 6 | 旧条款“起点在对象内即足以保护任意正宽度”给 Q/Q，具有完整区间保护规则的解释给 Q/R。合格证据为宽度 2 正常访问和声明域完整覆盖，宽度 3 有同对象区间违规见证 | 宽度 3 对旧条款构成明确反驳，触发 Revision，宽度 2 判断保持。若初始条款限定单字节，两处均 U，此时扩域依据和确定裁决另记，不能统计为两次明确反驳 |
| 骨架把另一对象的容量绑定到目标，或同时替换单位和目标 | 入池时可查出的额外变化记 confounded，缺语义保证记 needs_support。若揭示后才发现父骨架失真，旧裁决的适用资格须重查 | 前两者退 B1，零验证预算。后者 B4 → A2，工作包回 seed_pending。保留既有扣费与旧映射，按依赖升版 |
| 本组初始规约已明确允许阻断与恢复，争议是等价退出能否同样保护 | 两种退出均有独立 negative；继续执行的对照有 positive。所声称的路径、对象和声明域均有依据，组内其他确定位置也一致，剩余候选已区分或有域内等价证明 | keep Decision 列明支持位置与范围，B6 全量重放后给 C 原版规约。同样的实验若还有会改变结论的故障模式只得到 pending，且无余额，则 unresolved，只交部分结果 |
| OOB 种子容量为 8，故障输入偏移 9、宽度 9，修复后该故障路径绕过访问，正常路径仍可达。两个解释共享退出保护条款，在继续访问的分支分别将“起点在界内”和“宽度不超过容量”声明为充要保护条件 | 两个解释对种子前后均给 R/Q，因而都能通过种子筛选。开发位置偏移 6、宽度 3、容量 8，两者均给 Q。独立 positive 同时反驳两者。即使没有硬分歧，这个位置仍能暴露共同错误，例如由随机组抽中 | B4 → A5，保留首次 S₀ 与基线引用、骨架和组内证据。升版工作规约和解释集，继承水位与余额；经 A6 回 B 后登记 post_remodel，不能加入原始预登记命中数 |
| 重放发现原登记 Q，而已锁定的解释和事实按 1B 应为 U | 附两条记录的推导与事实版本，注明是否已揭示 | correct_reading，追加 errata 后回 B4。若是事实来源改变，则先作版本失效核查。两类变更均保留初次选择 |
| 修订只断言改变的位置，遗漏已确定且本应保持的位置，或新版本在其上同时导出 R 与 Q | B6 独立取本组台账获得完整 M；分别诊断断言遗漏或 spec_conflict | 返回 B4。保存失败修订与重放诊断，不能发布 spec_ready |

## 可重放的设计向量

以下独立 Python 代码块可直接提取并用 CPython 3.13 执行。选择器向量检查两种增益的次序和已覆盖集合，归因向量检查条件同时出现时的优先级。B6 的两表与重放结果分别提供，模拟“台账给分母，断言给预期”。这些检查仅覆盖表内的规则。

~~~python
from itertools import combinations, product, permutations
from random import Random
from collections import Counter
import sys

def signals(row):
    hard, domain = set(), set()
    for i, j in combinations(range(len(row)), 2):
        values = {row[i], row[j]}
        if values == {"R", "Q"}:
            hard.add((i, j))
        elif len(values) == 2 and "U" in values:
            domain.add((i, j))
    return hard, domain

def select(pool, equivalents, k):
    selected, hard, domain = [], set(), set()
    while len(selected) < k:
        ranks = []
        for key in sorted(pool.keys() - set(selected)):
            h, u = signals(pool[key])
            ranks.append((-len(h - hard), -len(u - domain), key))
        if not ranks:
            break
        a, b, key = min(ranks)
        if a == b == 0:
            remaining = sorted(equivalents - set(selected))
            if not remaining:
                break
            key = remaining[0]
        h, u = signals(pool[key])
        selected.append(key)
        hard.update(h)
        domain.update(u)
    return selected

def sample(ids, k, seed):
    return Random(seed).sample(sorted(ids), min(k, len(ids)))

pool = dict(zip("abcde", ("RQU", "RUQ", "QRU", "QQQ", "UQR")))
expected = list("abed")
for k in range(7):
    assert select(pool, {"d"}, k) == expected[:k]
assert select({"a": "QQ", "b": "UR"}, {"a"}, 2) == ["b", "a"]
assert select({"a": "Q"}, set(), 1) == []
assert select({"a": "Q"}, {"a"}, 1) == ["a"]
rows = list(product("RQU", repeat=3))
for row in rows:
    h, u = signals(row)
    assert len(h) == row.count("R") * row.count("Q")
    assert len(u) == row.count("U") * (3 - row.count("U"))
    assert h.isdisjoint(u)
for ids in permutations(pool):
    assert sample(ids, 3, 71) == sample(pool, 3, 71)
for row in rows:
    altered = dict.fromkeys(pool, row)
    assert sample(altered.keys(), 3, 71) == sample(pool.keys(), 3, 71)

def route(distorted, eligible, faithful, all_refuted, needs_change,
          supported, material_open, can_continue):
    if distorted:
        return "A2"
    if not eligible:
        return "seek" if can_continue else "unresolved"
    if not faithful:
        return "errata"
    if all_refuted:
        return "A5"
    if material_open or not supported:
        return "seek" if can_continue else "unresolved"
    return "revise_to_B6" if needs_change else "keep_to_B6"

counts = Counter()
for args in product((False, True), repeat=8):
    d, e, f, a, change, s, opened, budget = args
    out = route(*args)
    counts[out] += 1
    assert (out == "A2") == d
    assert (out == "errata") == (not d and e and not f)
    assert (out == "A5") == (not d and e and f and a)
    qualified = not d and e and f and not a and s and not opened
    assert (out == "keep_to_B6") == (qualified and not change)
    assert (out == "revise_to_B6") == (qualified and change)
    if out in ("seek", "unresolved"):
        assert (out == "seek") == budget

# TargetRef IDs below abbreviate versioned keys in a single contract/domain.
# M comes from group evidence, pred from independent parent/new replay.
M = {"t1": ("R", "v1"), "t2": ("Q", "v2")}
pred = {"t1": ("Q", "R"), "t2": ("Q", "Q")}
x = ("t1", "Q", "R", "v1")
y = ("t2", "Q", "Q", "v2")

def b6(changed, preserved, replay):
    seen = set()
    for group, records in [(True, changed), (False, preserved)]:
        for key, old, new, verdict in records:
            if key not in M or key in seen or (old != new) != group:
                return False
            if M[key] != (new, verdict) or replay.get(key) != (old, new):
                return False
            seen.add(key)
    return seen == M.keys()

assert b6([x], [y], pred)
for changes, kept, replay in [
        ([x], [], pred), ([x, x], [y], pred), ([x], [x, y], pred),
        ([], [x, y], pred), ([x], [(*y[:3], "stale")], pred),
        ([x], [y, ("pending", "U", "U", "v3")], pred),
        ([x], [y], {**pred, "t2": ("Q", "conflict")}),
        ([x], [y], {**pred, "t1": ("U", "R")}),
        ([x], [y], {**pred, "t2": ("Q", "R")})]:
    assert not b6(changes, kept, replay)
print(sys.version.split()[0], "signals", len(rows), "random", sample(pool, 3, 71),
      "routes", dict(sorted(counts.items())), "b6", 10)
~~~

## 编码后的验收

本轮用 CPython 3.13.16 执行上面的检查块。三个解释的 27 个三值预测向量均符合成对计数。五个目标的 120 种输入顺序和 27 次预测行替换均保持种子 71 的随机结果 c、a、b；分歧策略在给定矩阵上依次选择 a、b、e、d。八个布尔条件的 256 种组合中，128 项回 A2、16 项回 A5、32 项追加勘误、38 项继续取证、38 项未决停止，仅各有 2 项获准送 B6 保留或修订。B6 的 1 个有效断言集通过，9 个破坏完整性或一致性的断言集被拒绝。这些数量描述决策表的边界，无实验频率含义。

| 边界 | 真实运行时须提供的证据 |
| --- | --- |
| 随机选择器只见中性输入 | 进程访问控制和读取审计，含并发抽样、相同案例跨组命中缓存、不同揭示水位及重启。固定接口的函数重放只能验证该接口的输入依赖 |
| 候选池生成与预算 | 在锁定版本下重放同一已生成池。模型再次提案时另测池内容及准入波动；不能用抽样可重放推断生成稳定。事务重试与失败注入须核对每组计费次数和揭示顺序 |
| 归因与定稿 | 使用真实解释器、裁决版本和组内账本重放。并发勘误、失效或预算耗尽期间，旧水位提交应失败。C 只接收有效 spec_ready 快照 |

## 阶段 6 待审计划

| 交付物 | 设计内容与验收条件 |
| --- | --- |
| C1 输入与条款编译契约 | 从 spec_ready 清单取得首次基线及本组定稿，登记条款到谓词、后端事实与工具版本的依赖。相同语义及绑定复用同一实现；语义变更可追到具体 Revision。基线与定稿相同的输入应得到一致查询行为 |
| C2–C4 构建与告警对齐 | 同一数据库快照分别构建两版。按代码版本、文件、表达式跨度、访问角色与上下文匹配告警，区分命中、无告警、构建失败与映射歧义。用同行多访问、宏展开及默认无告警位置验收 |
| C5 差分回归与预算 | 分别登记证据、对应规约预测与查询实测。Q₀ 忠实保留旧条款错误，Q* 须通过全部确定位置。跟踪未覆盖默认、提取缺项、查询实现偏差与规约失效各自的修复路由。用两版相同上限、独立余额和幂等修复请求走查耗尽分支 |
| 冻结、部分交付与复核 | 以完整版本清单封存两版查询、共享模块、工具链、匹配策略、开发位置与决策记录；逐项验收双版通过、单版失败、重试和冻结后升版。仅通过冻结门禁的成对快照可交独立评测 |
