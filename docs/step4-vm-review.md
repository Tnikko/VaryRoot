# VaryRoot 本地虚拟机恢复与 Step 4 配对校准复核

日期：2026-11-20。项目根目录：`/home/tq/varyroot`。本机镜像目录：`F:\RootVary\server-reports\2026-11-20-step4-and-backup`。

## 1. 恢复来源与完整性边界

- 将 GitHub `Tnikko/VaryRoot` 的 `83b3762db66879fe83e5160108f7ff99ed5befb9` 放到用户指定的 `/home/tq/varyroot` 根目录，而非其下的 `repo-checkout`。同步 1,311 个已跟踪文件，恢复本机归档中的 257 个运行时文件；原目录中被覆盖的 341 个文件逐项留存于 `runs/recovery-root-backup-20261120/files`，哈希清单为 `sync-manifest.json`。
- 四份历史归档的 SHA-256、Step 3 冻结清单的 19 个输入摘要、双侧 Clang 18.1.3 观察器构建锁及生产 SQLite `integrity_check` 均已核对。恢复后的父种子 `curl-openldap-2018-seed-v4` 为 `seed_accepted`，A4 双侧回执及 A6 接受事件可追溯。`git fsck --full` 通过。
- 7server 当时无法通过跳板机 SSH 取回未推送的工作树，因此这里是**GitHub 最新可取提交加本机已有归档的最新可恢复状态**；不能声称与 7server 断联前的实时工作树逐字节相同。恢复账本与明细见 `review-vm-recovery.md`、`audit-root.json`、`sync-manifest.json`。

## 2. Step 4a：候选构建

- 从冻结的三份模型池及离线基线池读入 9 个候选；每个候选的源 SHA、Clang AST 目标跨度及预测矩阵重新核对。
- 在本地 VM 的锁定角色镜像中以 Clang 18.1.3 重建 9 个独立观察器，9/9 编译成功，`.so` 摘要逐个匹配构建锁。此阶段没有签发 Verdict。原始目录、审计及摘要在本机 `4a-vm-audit.tar.gz`。
- 初次构建发现 Docker 私有 `/tmp` 默认 `noexec`，角色运行参数改为私有 `exec` tmpfs；原失败尝试留在恢复目录，没有覆盖成功记录。

## 3. Step 4b：预登记、选例、独立验证

- 由修复前的 SQLite 快照建立 `runs/step4-paired/production-vm-clean`。四池的随机组与分歧组共 8 组，均使用同一已接受父种子、每组 `K=2`、`rng_seed=431`。全部预测登记与选择提交时，组内揭示水位均为 0。
- 选择请求合计 10 个，全部由非特权、断网、只读输入的验证角色执行并发布。验证输入只包含核准契约、观察域、目标绑定、候选观察器与执行脚本，不含候选规约、预测或其他组标签。原始回执由目标事件重算标签，10/10 均有正常输入上的真实安全访问见证；其中 2 个确定正例、8 个确定反例。
- 一次先导运行因 root 协调器创建的输出目录不可由非特权角色写入而失败。该请求和失败诊断完整保留在原账本，**不并入干净配对实验**。已修正输出目录属主，并从验证前 SQLite 快照重新建账本；未改写或删除先导失败记录。
- 已登记的 `candidate_measure.py` 对第 ② 类正常输入缺少安全读的变体会触发结构断言，归为 `case_exec_failure`；本次选中的 10 个位置均有真实安全读，因此不影响这批标签。下一版若接纳“正常功能可达但目标访问被跳过”的候选，须先升版测量适配器与登记输入摘要，按 `pending` 语义重新验证。

| 候选池 | 随机组选例/标签 | 分歧组选例/标签 | B6 随机组 | B6 分歧组 |
| --- | --- | --- | --- | --- |
| model-01 | 2 / 反、反 | 0 | 未决 | 未决 |
| model-02 | 2 / 反、反 | 1 / 反 | 未决 | 未决 |
| model-03 | 2 / 反、反 | 1 / 反 | 有据保留 | 有据保留 |
| 离线基线 | 1 / 正 | 1 / 正 | 未决 | 未决 |

分歧组在 model-01 选择 0 个，符合冻结池中解释预测一致时的零增益停止策略。这里的次数只描述该固定池，不构成选例策略总体优劣的统计结论。

## 4. Step 4c：B6 交接与 Agent C 能力门禁

- 从组内 `reveal` 账本、发布对象、Clang 提取事实和冻结预测矩阵重新计算全部确定位置；A4 父种子两个锚点按来源引用，并计入每组 B6 回查。8 组均生成通过 Step 01 工件校验的 `Decision`/`Handoff`；model-03 两组交付 `keep` 且 `revision_ref=null`。
- 离线基线正例推翻了 `H_check`，但 `H_loop` 与 `H_path` 对已见证据及冻结池仍无法区分。B6 将其签为 `unresolved` 并记录 `non_unique_revision`，没有任意选择一条替代规约。model-01/02 也保留剩余分歧。
- 对两份 `keep` 交接包实际调用 Agent C 的 `compile_manifest`，均明确返回 `unsupported_contract_mode:success_may_have_null_values`；另 6 份未决包被 `unresolved stops before C` 门禁拦截。本次没有生成 OpenLDAP CodeQL 成对查询或冻结编号。现有 C 编译器仍只支持此前登记的单函数 NPD/OOB 夹具契约，扩展真实 OpenLDAP 后端需要单独设计与审批。

## 5. 测试与留档

- VM 全量测试首轮 177 项中 2 项失败，均为 Agent A 夹具调用 `clang-18 --version` 超过 20 秒；这两项单独重跑通过。全量原样复跑：**177 项，`OK (skipped=32)`，41.945 秒**。首轮失败和复跑日志均保留。
- Docker 物理角色 10 个完成回执及隔离审计不包含在普通用户运行的 32 个跳过测试之内，已单独实测并进入 `raw/` 与 SQLite 事件链。`ledger-final.sqlite3` 的 `PRAGMA integrity_check` 为 `ok`。
- `clean-vm/SHA256SUMS` 列出 64 个报告、回执、事件、账本及交接文件；导出时检查了密钥文件名和认证头标记。项目外的 API 密钥未进入实验输入或归档。

## 6. 当前推进状态

本地 VM 已具备可继续开发的项目根目录和完整 Step 4a–4c 原始证据。当前可下结论的是：在这个固定开发池中，model-03 的两组可保留 `S₀`；其余池尚不足以唯一确定 `S*`。真实 OpenLDAP 的 Agent C 编译能力尚未实现，故 **Step 4 的 CodeQL 成对冻结与后续独立评测尚未完成**。下一接口工作应先定义 `success_may_have_null_values` 的 CodeQL Source/Propagation/Guard/Sink 绑定和跨版本目标表达式对齐，再按既定审批节奏编码与复核。
