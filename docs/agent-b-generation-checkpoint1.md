# Agent B 通用生成检查点 1

本检查点只实现验证前生成边界。现有 IR 解释器、账本和 B6 决策保持原接口。模型调用与生产账本写入留在审核后的实验阶段。

## 数据流

`b_prompt.hypothesis_pair` 从已解析的 IR `Guard` 条款投影两个竞争解释，只保留方向、适用条件、前件及两边独有条款。`render_messages` 对契约使用对象、范围、单位、操作四个允许字段。源输入是最小 before/after 翻译单元。账本 ID、来源 URL、源码摘要、编译锁、已裁决标签不进入消息。`build_request` 统一生成完整 JSON 请求，模型名与采样参数来自事前策略。

`b_static_retry.run` 只接受模型请求函数和静态检查函数两个注入接口。每条原始提案先经 Clang 结构门禁，再由现有确定性解释器给出两个 IR 预测。只有 `(report, quiet)` 或 `(quiet, report)` 计为 `hard_divergent`。若不足预登记数量，下一轮仅反馈拒绝原因或预测无分歧。达到重试上限后返回 `unresolved`。运行统计包括原始数、三态准入数、硬分歧数、响应格式失败和后端缺口。

`b_factor_gate.classify` 消费静态适配器回执。回执包含 Clang 编译状态、唯一目标绑定、AST 改动区域与角色。目标、契约调用、对象、循环状态或无关语义的改动判为 `confounded`。结构证据缺失判为 `undetermined`。含 `goto` 的控制流改写需同时有 Clang CFG 的目标可达不变与等价阻断证明，才可 `admitted`。适配器回执必须由静态工具产生，不能接受模型自报的角色。真实源码的通用 Clang 差分与 CFG 回执生产器仍需在审核后接线，当前模块遇到缺失证据会停在 `undetermined`。

## 后续接入门禁

审核后用同一请求渲染器接入 OpenLDAP 新盲池和 Ettercap OOB。先锁模型、重试次数、验证预算、候选假设与目标。每条模型提案都进入自动三态门禁，静态预测先于任何动态验证标签。池大小大于 `K` 时才登记 `Random vs Divergence` 配对消融。历史 `directed-v3` 只保留下游 B6、Agent C 与冻结链路工程验收用途，不计自主生成产率或 RQ2 效率。
