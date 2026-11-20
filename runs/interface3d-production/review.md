# 接口增量 3d：生产 A4/A6 门禁实施与复核

日期：2026-11-19。工作区：7server 的 `/dev_sdb/tq/VaryRoot`。本检查点只处理 `curl-openldap-2018-seed-v4` 的受控骨架种子，不修改父版或修复版的原始 `lib/openldap.c`。

## 结论与分母

生产 SQLite 已在事件 58 将 v4 种子从 `seed_pending` 推进到 `seed_accepted`。六个门禁 `before_ok`、`after_ok`、`candidates_ok`、`contracts_ok`、`mapping_ok`、`versions_ok` 均有当前包版本绑定的证据，阻断项为空。唯一真实开发候选的分母为**尝试 1、生产接受 1、待验证 0**；先前的静态检查和 3c 技术修订运行不重复算种子。

这是**骨架和已进入属性分支的有限域结论**。OpenLDAP 契约取自固定的 2.4.45 参考提交 `40421915e08ed1a10b5703973116705a94190ab0` 与 ITS#8820 依据；历史实际部署的 OpenLDAP 版本未获证实。A4 没有证明完整 libcurl 网络入口可达，也没有对父版违规后的行为作推断。

## 实施内容

- 新增 `varyroot/openldap_qualification.py`，使用既有生产 `Ledger`、`Publication`、`sandbox.materialize`、`run_role` 和真实规约解释器。3c 检查点 SQLite 及其请求 ID 没有搬入生产账本；生产重新生成请求 ID、物理尝试 ID、清单摘要和隔离执行回执。
- 对原代码、骨架、AST 访问序号、目标字节跨度、输出槽别名、锁定构建输入和被剪去的节点逐一核对。仅允许剪去已审计的 `;binary` 局部计算以及首次目标求值之后的循环体；原码到骨架映射只在声明范围内签为 `accepted_for_scope`。
- 生产验证器只读入 `binding.json`、`case_runner.py`、`contract.json`、`domain.json`、`measure.py` 和 `observer.so`。输入清单不含候选 Guard、预测矩阵或 CodeQL 输出。两侧均在 `namespace` 后端运行，非特权 UID 1009，输入与根文件系统只读、仅回环网络、无 Docker socket。
- 独立检查每侧四类观测、实际安全读取和裁决回执，并在生产账本中追加 A4 接收事件。A6 随后重算 `H_check`、`H_path`、`H_loop`，逐条比对事前登记预测；三者均为父版 `report`、修复版 `quiet`，均保留。初始基线锁定为 `spec.openldap.H_check@1`。最终四项非侧证据与 `seed_accepted` 在同一个 SQLite 写事务中提交。

## 独立观测与功能元数据

| 侧别 | 生产请求 ID | 裁决 | 故障目标到达 | 正常输入的真实安全读取 | 第④类功能字段 |
| --- | --- | --- | --- | --- | --- |
| 父版 | `a2301fcde4b24b0cb28cb38f70fa5793` | `positive` | ①、④在首次目标求值前观测到空输出 | ②中 2 次 | 违规后行为未定 |
| 修复版 | `bc8be08231614a99b4ec62a81948a554` | `negative` | 四类均无违规，故障路径阻断 | ②中 2 次 | 骨架未请求后续预设属性，`attribute_traversal_truncated=true` |

两侧均为 `exhaustive_finite_domain` 且 `normal_witnesses=[2]`。第④类的遍历截断作为独立功能注记存入接受事件，没有改变内存访问安全标签。

## 负测与恢复

独立账本副本先完成一次全路径 `seed_accepted` 重放；重复调用返回已完成且事件数不增加。另一副本在只有父版回执时仍保持 `seed_pending`。错包版本、错包摘要、错契约摘要、旧观察域摘要、错清单摘要及过期包接收均被拒收。A6 单测将两个候选改为事前登记且与证据不相容的条款，解释器只留下一个候选，决策路由 A5。

生产事件顺序：42–48 为父版请求、围栏执行、发布与接收；49–55 为修复版相同步骤；56 为 `A6.replayed`，57 为范围限定的 `A4.mapping_approved`，58 为 `seed_accepted`。重复请求核验前后生产事件数均为 22。完整事件、两份规范发布对象、重建后与生产摘要逐字节相同的输入清单、执行审计和生产 SQLite 前后备份均在 `out/`。

## 测试与未闭合的环境门禁

- 3c 固定工件：`sha256sum -c SHA256SUMS` 核对 45 个文件。
- 3d 新增单测：`python3.13 -m unittest discover -s runs/interface3d-production/src -p test_qualification.py -v`，6 项通过。
- 生产与两次隔离账本贯通、六项负测、幂等重放、独立审计均通过，命令和原始结果在 `out/`。
- 旧仓库全量测试在服务器宿主环境运行 156 项，10 个失败、4 个错误、32 个跳过；所有失败/错误的共同原因是宿主没有锁定的 `/usr/bin/clang-18`。在锁定的 Clang 18 根文件系统中运行 163 项，留下 3 个旧原生构建测试错误和 32 个跳过；这些旧测试将镜像中的启动脚本当作 VM 宿主 Clang 原二进制核对。试用只限测试命名空间的启动器摘要覆盖后，仍有 3 个原生构建错误，原因是旧 `-shared` 构建路径无法经该启动脚本调用链接器。生产工具锁与原始测试文件均未改动。这一项**尚不能申报仓库全量零失败**，需在后续单独适配测试运行器；它不影响本次已实际运行并逐回执验证的 A4/A6 证据链。
- `R04` 真实存储断电耐久继续待验；进程级围栏和 SQLite 原子提交不能代替断电测试。

## 复核文件

- `out/audit.json`、`out/event-chain.json`：生产状态、六门禁、请求身份与事件链。
- `out/production-{before,after}-receipt.json`、`out/production-{before,after}-input_manifest.json`、`out/production-{before,after}-execution.json`：原始观测、逐字节重建清单与隔离执行。
- `out/production-before.sqlite3`、`out/production-after.sqlite3` 及 `out/production-published-objects/`：生产账本前后快照与已发布对象。
- `out/unit-tests.log`、`out/negative-tests-post.log`、`out/full-tests.log`、`out/locked-tests.log`、`out/launcher-tests.log`：通过项及全量环境限制的原始日志。
