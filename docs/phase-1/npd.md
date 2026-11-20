# NPD 贯穿实例 · 从同一个空值检查到三种路径结果

本例是设计向量。对象为一次读取的操作数 p，契约 K1 保证来源的返回值只有空或指向有效对象两种状态；非空对象在该次访问前保持有效。D1 穷尽这两种输入，控制流与修正操作均为确定性的。每种变体有独立的 TargetRef，所述读取对应同一个父骨架的语义位置。

## 目标、事实与预测登记

原始位置 O 的 scope_kind 为 original_source、mapping_status 为 origin。种子位置 S 指向 O；下表四个位置均为 counterfactual_case，各自通过已核准的 exact_1to1 映射指向 S。诸如 N.log@1 的别名同时绑定工件版本、变体、所属源码快照及表达式跨度。正常输入在四例中都能完成该读取。

输入可为空来自已核准的 interface_guarantee；“检查对象与读取的操作数对应”“日志后是否退出”来自 source_extracted 事实。修正分支对新对象有效性的保证也须独立核准。若“修正总能给出有效对象”仅为 skeleton_assumption 且仍 pending，则不能凭此接受修正分支为确定反例。

S₀ 将“在访问前已对 p 判空”声明为充分保护。S* 在本例闭合模型内将保护定义为“空值无法作为该操作数到达读取”。对每条来源故障路径，提前退出、跳过读取或在到达前将操作数修正为有效值，均可满足该条件。反向推导需要同一路径上的来源、值流、实际到达和保护失败。

| TargetRef | 路径事实 | S₀ → S* | 独立观测与裁决 |
| --- | --- | --- | --- |
| N.log@1 | 同一指针已被检查；记录日志后继续 | quiet → report | 空输入到达目标且操作数仍为空。V.log@1 为 positive |
| N.exit@1 | 故障分支提前退出 | quiet → quiet | 有效输入正常读取；空输入被阻断。穷尽 D1，V.exit@1 为 negative |
| N.goto@1 | 故障分支跳至清理出口，绕过读取 | quiet → quiet | 有效输入正常读取；空输入未到达目标。穷尽 D1，V.goto@1 为 negative |
| N.repair@1 | 判空后将操作数替换为经核准的有效对象，再读取 | quiet → quiet | 正常与故障输入均能到达，两个到达状态都合法。穷尽 D1，V.repair@1 为 negative |

在 N.log 上，S₀ 由检查事实和充分条款闭合 quiet。S* 绑定同一个空来源、同一执行上的值流及实际读取，并确认空值仍到达，于是闭合 report。N.exit 与 N.goto 的故障路径均缺少 Reaches，N.repair 的故障路径虽满足 Reaches，却不满足 Failure。三者的正常可达及保护依据均独立保存。

## Decision 与 Revision

D.n@1 引用旧预测、V.log@1 与对照证据，action 为 revise，父规约为 S₀。下列为其 Revision 的回归字段摘录。四条均属于同一确定位置清单；旧值使用修订前的预测快照。

```json
{
  "trigger_decision_id": "D.n@1",
  "changed_judgments": [
    ["N.log@1", "quiet", "report", "V.log@1"]
  ],
  "preserved_judgments": [
    ["N.exit@1", "quiet", "quiet", "V.exit@1"],
    ["N.goto@1", "quiet", "quiet", "V.goto@1"],
    ["N.repair@1", "quiet", "quiet", "V.repair@1"]
  ],
  "new_fact_requirements": ["故障路径是否到达目标", "到达时的操作数身份与空状态"]
}
```

**方向检查。** 另起独立解释，仅声明“提前 return 足以保护”。对 N.goto 没有其他适用条款时推不出任何方向，输出 uncovered。改为“提前 return 是必要条件”可推出该形式缺失；若故障路径确实绕过目标，仍缺少 Reaches，不能按本版完整公式推出 report。若想表达只凭语法形状报警的弱基线，应另写其报告模式并标记使用了近似的可达性，不能把已证实绕过操作的路径登记成可行到达见证。

**有据保留与未决。** 若以 S* 为初始规约，且上述独立证据均可核对，则生成 keep 决定。若 D1 新增一种修正失败的模式而未观测，原正常观测仍有效，V.repair@1 的保护结论只覆盖旧域；新域可生成 pending 裁决及 unresolved 决定。两条路线均不生成改条款的 Revision。
