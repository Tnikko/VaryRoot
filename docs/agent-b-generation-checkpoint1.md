# Agent B 通用生成检查点 1–2

## 检查点 1：验证前生成协议

`b_prompt.py` 是唯一的 Agent B 请求渲染器。它从 IR 的 Source、Propagation、Guard、Sink 四种条款投影两个假设及逐角色差异，保留条款绑定；契约只投影允许的简短语义字段。源码输入必须由调用方提供最小 before/after 翻译单元。审计元数据、历史裁决和动态标签不进入消息。每轮提案上限与 `parent` 枚举写入统一指令。

`b_static_retry.py` 保存每条原始提案的轮次、父版、因子、意图、源码及规范化摘要。它对父版、修复版和跨轮候选去重，并严格检查父版枚举与轮内上限。可信静态回执经 `b_factor_gate.py` 归为 `admitted`、`confounded`、`undetermined`；只有准入提案获得纯 IR 静态预测。`report/quiet` 记硬分歧，一侧 `uncovered` 记覆盖分歧。默认目标是硬分歧；覆盖目标要求事前登记的假设对摘要及覆盖证据引用。下一轮只收到意图、静态拒绝原因、受保护角色和静态预测。重试预算耗尽返回 `unresolved`。动态 oracle 不在该接口内。

## 检查点 2：离线 Clang 回执

`b_clang_receipt.py` 重放声明的 Clang 编译参数，分别生成目标函数 AST 与基本块 CFG。AST 接收者要求唯一的目标函数定义，目标表达式必须与指定源码行的显式 AST 节点源码切片精确对应。源码差分按行映射实际 AST 节点并归类角色；独占新增的 `goto` 和标签合为一个控制流语义组。CFG 输出原始基本块、后继与摘要。它尚不自动证明任意 `goto` 的目标可达不变和阻断等价；证据不足保持 `undetermined`，不可把图存在当作等价证明。

离线回归重放既有 OpenLDAP NPD 与 Ettercap OOB 源文件及编译参数。Ettercap 修复版的总长 Guard 到剩余长度 Guard 变更落在单个 Guard 组；OpenLDAP 补丁含契约绑定与 Guard 的多处改动，不能将原始补丁误称为单因素候选。测试也验证 `goto` 与独占标签合组及 CFG 边存在。该阶段没有真实模型请求、动态验证或生产账本写入。

## 后续门禁

真实盲池必须先锁假设对、区分目标、重试次数、候选池及预算。每条模型提案经同一三态门禁自动处理；池大小大于验证预算 `K` 后才可登记 Random vs Divergence 消融。历史 OpenLDAP `directed-v3` 只作为下游工程验收样本。

## 双种子离线预登记接线

`b_static_retry` 支持外部规范化源码摘要排除表，历史命中计入 `protocol_rejected.historical_excluded`。早停同时要求 `min_admitted`、`min_divergent`，可要求池内兼有硬分歧与非硬分歧。`b_prompt` 在请求视图中以通用词法规则去除 C/C++ 注释，保留字符串字面量；不支持的原始字符串形式显式拒绝。

`b_interval_ir` 定义通用逻辑区间的 `H_total` 与 `H_remaining` 四角色条款，从已声明编译命令的 Clang AST/CFG 回执抽取目标处的直接 Guard 和正向指针位移，并调用原 `inference.py`。A6 结构门禁核对锁定源码、独立容量来源摘要及完整 IR Bundle。其接受范围仅为 `L=W` 的局部符号路径；路径可满足性及全程序安全仍需独立证据，不得把该静态投影当成动态验证标签。Ettercap 的这套 A5 候选来自补丁结构，不计作 LLM 自主 A5。
