# 阶段 2 · 协调器状态与转换

本阶段规定行为，供后续编码验收。协调器是 SQLite 账本的唯一写入角色。一次研究运行、一个逻辑请求、一次物理执行各有自己的状态。术语及持久化边界见[提交与恢复协议](recovery.md)，可见性见[权限与版本协议](visibility.md)，验收向量见[走查记录](review.md)。

## 研究运行

运行键包含 seed、实验组、重复号和运行分支。round 属于该运行的校准轮次。Q₀、Q* 的构建状态各自登记。模型和执行器提交提案；下表的转换均由协调器检查期望状态及运行版本后提交。

| 原状态／发起角色 | 条件与转换 | 留存工件／失败去向 |
| --- | --- | --- |
| draft／A | 登记 TargetRef、映射、契约及候选，进入 seed_pending | 待核准假设留在 A2。种子前后验证单列启动成本 |
| seed_pending／独立验证器、解释器 | A4 的前后证据合格且 A6 的候选与证据相容 → seed_accepted | 证据未决停留或交付部分结果；解释全部不符回 A5 |
| seed_accepted 或新一轮／B | 提交解释、候选池和逐位置预测 → registered | 固定预测批次与输入版本，冲突退回解释构造 |
| registered／选择器 | 原子提交选择、请求、扣费与待派发项 → selected | 余额不足则整批拒绝；重复提交同批次返回原记录 |
| selected／验证器 | 每个请求执行、发布，再按组登记揭示 → adjudicating | 批量首版等该批全部有定论或执行诊断后统一揭示。部分完成仍停在 selected |
| adjudicating／B4–B6 | 校准并提交 Decision。revise 或 keep 通过回查 → spec_ready | 补证开新轮；骨架／契约失真回 A2，解释全被反驳回 A5；材料不足可交付 unresolved |
| spec_ready／C | 为每版登记初次编译、运行和位置匹配 → regressing | 初次构建成本单记。编译失败、明确实现偏差可申请本版修复请求 |
| regressing／C5 | Q₀ 检验原预测与默认；Q* 另需通过全部确定位置。两版门禁均通过 → frozen | 实现偏差回 C2；位置歧义回 C4；规约偏差回 B4 并开新版本。预算耗尽且仍需修复 → partial |
| frozen／评测者 | 接纳完整冻结包，允许交给独立评测 | 修订开启新分支；旧冻结包保留原输入与结果 |

回到 A 或 B 时，在同一事务登记 Decision、父版本、待重新验收的依赖及新状态。已揭示的知识和已用预算随原运行继承，重建解释或改规约不能重置余额。冻结及 partial 均携带终止原因。

## 请求与尝试

| 层次 | 状态链 | 拥有的约束 |
| --- | --- | --- |
| 逻辑请求 request_id | queued → running → publishing → ready → delivered；也可进入 failed 或 conflict | 扣费一次、同一时刻至多一个有效尝试、至多一个被接纳的结果版本。ready 仅对协调器可用 |
| 物理尝试 (request_id, attempt_id) | reserved → live → receipted → accepted；旧尝试可转 aborted | attempt_id 为请求内单调递增整数。专属目录、派发令牌、租约、运行成本和回执与此次尝试绑定 |
| 交付与裁决 | B 的 delivered 写 Reveal；C 的 delivered 把候选构建结果交本版回归 | pending 是成功交付的一种 Verdict；工具失败只有诊断，不能代替正例、反例或待定标签 |

ready 与 delivered 分开恢复。未揭示的 ready 结果无需再执行；已揭示后重复交付返回同一个组内事件。failed 可记录诊断后随该批结束。conflict 挂起自动揭示，保留冲突材料，等待明确裁决；若已有下游结果，则追加争议事件并标记依赖待查。
