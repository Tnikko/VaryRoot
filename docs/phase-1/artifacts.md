# 1A · 工件与依赖表

本版是阶段 1 的接口设计。解释器按[推导规范](inference.md)消费这些记录；两个实例分别给出[空指针](npd.md)和[区间访问](oob.md)的期望结果。示例中的判断是设计验收向量。

## 通用约定

每份工件含 kind、schema_version、id、version、producer、run_ref 和 depends_on[]。引用绑定到具体版本，示例用可读别名缩写版本化引用。运行上下文含种子、组、轮次。所有跨度使用文件相对路径和半开 UTF-8 字节区间，随文件内容摘要一起保存。显示行号由快照换算。引用缺失、重复身份、依赖成环或类型不合法时拒收。事实未知使用显式缺项，不能用零、空指针或 false 代填。

| 工件 | 产生者 → 消费者 | 必填内容与约束 |
| --- | --- | --- |
| TargetRef | 前端／案例构造器 → 全模块 | scope_kind、snapshot_ref、variant_id、file、file_digest、symbol、expr_span、operation、mapping_ref、mapping_status。每个变体内的目标单独编号。 |
| Fact | 前端／A → 解释器、契约核准者 | subject、relation、typed_operands、path_scope、source_kind、source_ref、approval_status。source_kind 取 source_extracted、interface_guarantee、skeleton_assumption；核准状态取 pending、approved、rejected。结论只能使用当前域内可采信的事实，裁决须能追溯到独立依据。 |
| Clause | A／B → 解释器、C | clause_id、spec_version、field、bindings、applicability、antecedent、consequent、direction、basis_refs。field 属于 Source、Propagation、Guard、Sink。条款按版本组成规约；direction 取 sufficient、necessary、iff，明确其所修饰的命题。 |
| Prediction | 解释器 → B、C | hypothesis_ref、target_ref、contract_ref、domain_ref、fact_snapshot、outcome、derivation、missing_facts、registration_ref。冲突和无效 IR 返回单独诊断；不能伪装成已登记的三值预测。 |
| Observation | 验证器 → 裁决器 | request_ref、target_ref、contract_ref、domain_ref、input_ref、path_ref、reached、observed_state、execution_status。未到达时记录阻断原因，观测不到的状态留缺。 |
| Verdict | 裁决器 → B、回归器 | target_ref、contract_ref、domain_ref、observation_refs、label、justification。positive 附违规见证；negative 附正常见证和覆盖依据；pending 附缺口。工具异常记录运行诊断，不能计作一次正常执行。 |
| Decision | B 提案／协调器提交 → 版本管理、A、B、C | prediction_refs、verdict_refs、parent_spec_ref、action、reason、remaining_disagreements、next_state。action 支持 revise、keep、unresolved、seek_evidence、correct_reading、remodel。未决可无确定裁决，但须记录证据缺口。 |
| Revision | B 提案／协调器提交 → B6、C | trigger_decision_id、parent_spec_ref、new_spec_ref、clause_diff、regression_manifest_ref、changed_judgments、preserved_judgments、new_fact_requirements。仅由 revise 决定创建。 |

Contract 以版本标识对象身份、前置条件、计量单位、适用模式、独立来源与核准状态；Domain 以版本标识输入集合、路径约束和覆盖方法。扩大域时建立新版本并重验全称结论。仅改变解释时，可复用同组、同目标、同契约和域下的有效观测，新增预测注明形成时点。

## 目标与映射

scope_kind 取 original_source、seed_skeleton、counterfactual_case。snapshot_ref 区分补丁前后快照；variant_id 区分共享快照或共有父案例的不同变体。原始锚点的 mapping_ref 为空、状态为 origin。子目标的 mapping_ref 指向有版本的映射记录，列出父子 TargetRef、语义角色、对应依据、核准状态；允许沿父链回溯。映射关系与“两个案例标签是否相同”分别判断。

| mapping_status | A3、C4 如何处理 |
| --- | --- |
| exact_1to1 | 经核准且快照一致时沿唯一对应传递位置。仍须检查对象和操作。 |
| split_expression | 登记拆分后各子表达式和角色。能预先唯一确定目标操作时，只匹配指定子表达式；映射仍有歧义时阻断跨位置计分。 |
| ambiguous／unmapped | 保留本地观测，返回位置诊断，等待修订映射。不得任选同一行访问作为命中。 |

映射变化后重新验收依赖该映射的跨位置裁决和回归；有效的本地原始执行记录可以保留。这样可以区分“确实没报”和“当前无法判断是否命中”。

## 可执行的修订断言

changed_judgments 与 preserved_judgments 都是四元组数组，顺序为 `[target_ref_id, old_prediction, expected_new_prediction, verdict_ref]`。预测值取 report、quiet、uncovered。两个列表分别要求新旧值不同、相同。父子规约及登记时的事实快照由 Revision 和预测台账确定；若同一目标出现多个观察域或契约，按 manifest 中的目标、契约、域及 verdict_ref 唯一连接。无法唯一连接时拒收。

B6 用父规约登记记录核对 old_prediction，以新规约重放 expected_new_prediction。要求两表互斥、无重复，并完整覆盖本组清单中的确定开发位置；待定位置另列。C5 独立读取原始清单与裁决，对两个查询分别检查实现忠实度，再以实际告警对确定位置计分。Revision 中的预期值不能代替独立标签，也不能借删减断言缩小回归分母。keep 与 unresolved 仅交付 Decision。
