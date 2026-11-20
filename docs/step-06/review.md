# 步骤 06 · Agent B 编码复核

本轮从一个已通过 A4/A6 的开发种子启动随机组和分歧组。两组登记同一候选池、两套候选解释的预测及同额预算，再由独立选择器取样并调用步骤 05 验证器。此处的样本数用于核对文件流、证据和账本，不能据此估计未见代码上的规则收益。

## 开发回放

| 种子与策略 | 冻结池 | B 验证请求 | A4 锚点 | 改变／保持 | 终态 |
| --- | ---: | ---: | ---: | ---: | --- |
| NPD 随机组 | 4 | 4 | 2 | 1／5 | revise |
| NPD 分歧组 | 4 | 3 | 2 | 1／4 | revise |
| OOB 随机组 | 9 | 9 | 2 | 0／11 | keep |
| OOB 分歧组 | 9 | 5 | 2 | 0／7 | keep |
| NPD 双组，K=0（各组） | 4 | 0 | 2 | 无修订清单 | unresolved |

NPD 中两组都选到“已检查指针，空值分支继续”的目标，独立验证器观察到违规访问请求，并在实际读取前拦截。旧条款在该位置给出 quiet，修订后给出 report。OOB 两组都覆盖了起点满足约束而整个访问区间超过逻辑前缀的情形；原规约的全区间条件与证据一致，保留原规约版本且 revision_ref 显式为空。两类种子的初始强度不同，不能用两者的终态比较漏洞类型的难度。NPD 上游为版本化种子夹具，OOB 经真实 Agent A；两者均使用生产 A4/A6 与 B 入口。[逐组统计](summary.json)

## 逐步验收

**06a　准入与再生成。** 当前离线提案器仅接受登记的合成源码形状，使用全片段结构匹配、单因素差分、目标字节跨度及独立契约摘要核对准入。宽度变化保留经过逐项核对的父链。对照多改一项、契约依据不符或目标不唯一时，在创建验证请求前拒收。归档的 pre-registration 含父版本、位置、规范文件记录、事实、预测、共享池与来源类型。复核导出器独立重跑提案并逐行比较池与矩阵。当前结果限于确定性生成器，尚无在线模型生成波动的观测。[原始登记示例](raw/pair.divergence/b1/pre-registration.json)

**06b　选择与物理隔离。** 随机进程只取清单、字典序排列的中性案例标识、预算与策略。分歧进程按新增硬分歧、覆盖域差异、稳定标识处理并列，再消耗预登记的等价改写，零增益时记录停止原因。随机容器实测根目录和输入只读、UID 1000、网络仅 lo。替换矩阵并反转原始池顺序后，随机输入、清单和选择结果的字节摘要一致。每个主链批次保存选择器实际看到的文件及输出。[容器审计](role-isolation.json) · [实际分歧选择轨迹](raw/pair.divergence/b1/selection.json)

**06c　计费、揭示与勘误。** NPD 两组共同选中 3 例，OOB 共同选中 5 例。每一共同案例在两组分配了不同 request_id，各自扣一次 B.verify。两个组先完成登记；随机组交付后，分歧组再提交选择。账本分别记录选择与揭示顺序。故障注入走查故意将一个事前预测改错，B6 先返回 correct_reading，追加 B4.errata 后仍可按原提交序号读取原预测。分别对 A2 和 A5 注入已审核的依赖变更，在真实 A4/A6 重新接受后进入 b2；两次均继承余额及原先揭示的组内快照。返工走查截止于新批次登记。[NPD 交叉计费](raw/pair-overlap.json) · [OOB 交叉计费](raw/oob-overlap.json) · [A2](raw/work.A2/events.json) · [A5](raw/work.A5/events.json)

**06d　B6 回查与交接。** B6 读取本组有效裁决，独立重放每个确定目标，再把两个 A4 锚点一并纳入保持检查。核对按目标、契约和域确定身份；重复、遗漏、错裁决或伪造动作均被拒收。独立负向链同时产生 pending 与 case_exec_failure，两个诊断都保留，B 确定位置计数为零。固定批次已结束但仍有余额的未决路径也保留剩余分歧。三类工件均经步骤 01 validate 校验，只有修订和有据保留可进入步骤 07。[逐位置推导与裁决](raw/pair.divergence/b6.json) · [两类排除记录](raw/fixture-partial/b6.json) · [修订交接](handoffs/pair.divergence/manifest.json) · [保留交接](handoffs/oob.divergence/manifest.json) · [未决交接](handoffs/stopped.divergence/manifest.json)

## 运行与复核

Ubuntu 24.04 上使用两个独立 trace 目录执行全量测试。两次均为 116 项通过、零跳过，分别耗时 173.691 秒和 202.982 秒。对 8 个可比组／批次核对了两次运行，另从最终运行重新导出并通过独立 CLI 校验 10 份交接包。修改后的复跑保留每一次选择器授权输入及原始选择结果，并对底层生产账本补加“新登记必须通过种子接受门禁”的检查。逐次重放比较三值矩阵、池摘要、输入文件与选例输出。步骤 06 的候选生成机制目前覆盖登记的 NPD/OOB 家族和有限观察域；等价改写包含词法中性的注释变化，不能据此宣称七类机制已在真实代码上验证。[首轮全量](first-full-tests.txt) · [最终全量](vm-final-tests.txt) · [双次重放](repeated-runs.json)

~~~bash
cd /home/tq/varyroot
export PATH="$HOME/.local/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
export VARYROOT_DOCKER_SUDO=1 VARYROOT_R05_DOCKER=1 VARYROOT_R06_DOCKER=1
export VARYROOT_R07_DOCKER=1 VARYROOT_R08_DOCKER=1 VARYROOT_STEP06_DOCKER=1
sudo -v
varyroot-python3.13 -m tools.verifier.build
varyroot-python3.13 -m tools.selector.build
export VARYROOT_B_TRACE="$PWD/runs/step06-final" VARYROOT_05_TRACE="$PWD/runs/step06-verifier-final"
export VARYROOT_TRACE_DEST="$PWD/runs/step06-legacy-final" VARYROOT_SEED_TRACE_DEST="$PWD/runs/step06-source-final"
varyroot-python3.13 -m unittest discover -s tests -v
varyroot-python3.13 -m tools.calibration.review "$VARYROOT_B_TRACE" docs/step-06 --prior-trace runs/step06-submit
~~~

重跑请为四个 TRACE 变量指定新目录。首次执行可以省略导出命令的 --prior-trace；取得两次独立运行后再比较。[验收台账](../runtime-acceptance.md) · [步骤 07 待审计划](step-07-plan.md)
