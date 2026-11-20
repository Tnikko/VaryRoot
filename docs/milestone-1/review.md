# 里程碑 I 实施与复核

工作目录 F:/VaryRoot，Windows，CPython 3.13.16。步骤 01 首次红测为缺少 varyroot 包；实现读取、类型和交接后，先独立运行 7 个测试方法通过，再开始步骤 02。最终全量结果含新增的跨阶段回归，见[命令输出与文件摘要](verification.txt)。

## 文件入口

~~~powershell
$py = uv python find
& $py -m unittest discover -s tests -p "test_*.py" -v
& $py -m varyroot validate tests/fixtures/m1/manifest.json
& $py -m varyroot explain tests/fixtures/m1/manifest.json t@1
~~~

[可重放清单](../../tests/fixtures/m1/manifest.json)列出记录文件和绑定到版本的 spec_ref、target_refs、contract_ref、domain_ref、fact_refs。目标以 target@version 指定。Snapshot 保存用于核对 UTF-8 半开字节跨度的文本。Fact.relation 是所绑定的槽名；typed_operands 保存声明类型与值或显式缺项，path_scope.path_id 必须属于引用的域。每条事实还绑定 target、subject（含对象代次的标识）、contract 和 domain。各作用点应使用独立槽区分状态时刻，例如修正后的 ptr。域的 paths 是当前目标的相关故障路径类，非空覆盖依据由上游提供。真实提取、证据资格审定及账本提交分别由以后步骤接入。

编程接口 evaluate 接收已解析的 Spec（clauses 与 clause_refs 对应）、TargetRef、Contract、Domain 和当前事实集合。外部文件先经 validate_bundle 校验。可用变量、布尔值、类型常量及 op/args 表达式写 antecedent 和 applicability。三值求值只在同一路径、对象、位置、契约与域中组合；正宽度 contains 比较整个数学整数区间。输出包含规约与目标版本、逐路径子表达式值、所查事实、采用事实、缺项与结论。读到 pending/rejected 或缺值的事实给 U；独立的充分条件仍可闭合。未登记的预测没有协调器提交序号。

| 命令状态 | 退出码 | 输出与去向 |
| --- | --- | --- |
| validate 成功或 explain 得到 report／quiet／uncovered | 0 | JSON code 为 ok 或对应预测 |
| 包格式、引用、目标选择、调用参数错误 | 2 | invalid_bundle，附字段 |
| IR 类型、签名或变量声明非法 | 3 | invalid_ir，附诊断 |
| 同一目标两种证明成立 | 4 | spec_conflict，同时保留 report 与 quiet 证明 |
| 文件读取／操作系统错误 | 5 | io_error，附路径和原因 |

## 逐向量结果

下表每个有效格均通过独立进程的 explain 断言；测试输入生成器与额外门禁见[文件回放](../../tests/test_replay.py)及[解释器测试](../../tests/test_inference.py)。

| NPD 输入 | 旧充分条款 | 新阻断或恢复条款 | 关键依据 |
| --- | --- | --- | --- |
| 记日志后继续 | quiet | report | 可行到达且未经修正 |
| 提前退出 | quiet | quiet | bypass 为真，reaches 为假 |
| 等价绕行 | quiet | quiet | bypass 为真，reaches 为假 |
| 重绑定有效对象后继续 | quiet | quiet | reaches 为真，目标指针在已声明契约内非空 |

| OOB 输入，容量 8／偏移 6 | 仅检查起点 | 完整区间 | 仅单字节域 | 完整区间但缺容量单位 |
| --- | --- | --- | --- | --- |
| 宽度 2 | quiet | quiet | uncovered | uncovered，f.capacity@1 |
| 宽度 3 | quiet | report | uncovered | uncovered，f.capacity@1 |

| 其他验收向量 | 实测断言 |
| --- | --- |
| 3×3 合取／析取与 3 个否定 | T/F/U 真值表一致 |
| 两种事实来源 × 两种未核准状态 × 两种到达状态 | pending/rejected 阻断相关证明，返回 uncovered 及 f.ptr@1 |
| 未核准恢复事实，但绕行已独立证明 | quiet，f.ptr@1 单列缺项，不进入采用事实 |
| 两分支分别持有来源和继续访问前提；容量事实属于其他对象 | uncovered |
| 空路径域或部分覆盖；仅必要条件缺少 return 且故障不达 | uncovered |
| 同一适用条件明确为假，充分条件集合先开放后声明完备 | uncovered → report |
| 同时存在独立充分保护和闭合的应报见证 | spec_conflict，两个方向均指向带条款依据的路径 |
| 规约版本、目标跨度、字段缺失、依赖成环、同一身份重复、操作数类型不符 | 结构或类型诊断；不能登记成合法预测 |
| keep、revise、unresolved；错误父引用、错误分区、过期裁决 | 三项合法交接通过，错误引用和断言拒收；keep 只接受同一带版本规约，新包装即使内容相同也拒收 |
| 反转工件顺序及 JSON 键序；有效事实由 @1 升 @2 | 前者输出一致，后者路径证据引用 @2，不再引用 @1 |

## 实现中补上的检查

静态类型检查同时核对条款内部签名和清单所选事实与槽的类型，避免一个合法的字节常量绑定到布尔槽。推导保留子表达式级轨迹，使同样输出 quiet 的“绕开目标”和“恢复后到达”可区分。修订交接检查初始基线属于工作父版本链。此时 validate 验的是版本化工件契约；生产者所声明的全域覆盖、真实程序的轨迹以及全量 B6 分母分别留给其责任模块。

## 步骤 03 待审计划

1. 用 SQLite 登记版本化工件、组、状态和事件。步骤 01/02 CLI 的结果由命令调用者解析，成功和四种失败类型分别路由。先验收同一请求重放与不同输入复用键的拒收。
2. 实现 selection／修复意图、预算、请求和尝试围栏的一致提交；验证重复提交、待定扣费、同一请求重派、旧令牌迟到及两版独立余额。
3. 接通 staging、完成回执、发布恢复和角色 manifest。分别检查等待、取回、重派、读权限及预测揭示水位。进程强杀与断电耐久分别记 R03、R04。
4. 在临时目录接入 A、验证器、B、C 的文件契约桩。逐一验证正常修订、有据保留、证据未决、后端缺口；桩的编号及产物使用测试命名空间。提交四条文件事件链、异常注入结果与 R02/R03/R05 的分项记录后复核。
