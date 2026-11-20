# 步骤 07 · Agent C、双版回归与成对冻结

Ubuntu 24.04.5 VM 上的 C1–C6 已接通 B6 交接、真实 CodeQL 查询和生产 SQLite 状态机。下表的分母是本组已确定且两版均可计分的开发位置。同一目标可出现在多个单独运行中，各行不能相加作为独立评测样本。[逐组汇总](summary.json) · [逐位置对照表](locations.md)

|路径|共同位置|Q₀（TP/TN/FP/FN）|Q*（TP/TN/FP/FN）|生产终态|
|---|---:|---|---|---|
|NPD，修改弱 Guard|5|2/2/0/1|3/2/0/0|成对冻结|
|OOB，有据保留全区间条款|7|3/4/0/0|3/4/0/0|成对冻结，两版查询字节一致|
|NPD，B 确定证据不足|—|—|—|未决止于 B，C 两账户均零消耗|
|OOB，从起点检查修订为全区间检查，后端要求外部函数体|7|2/4/0/1|2/4/0/1|部分交付，无冻结编号|
|NPD，旧规约适用域未覆盖一个正例|6|2/3/0/1|3/3/0/0|基线按默认无告警，最终版命中，成对冻结|

每条路径位于 `release/<路径>/`。其中 `events.json` 提供含提交序号的生产事件，`receipt.json` 提供预算与签发结果。有查询的各组还提供 `archive/` 中的 B6 交接、数据库包、建库命令、查询、BQRS、原始解码 CSV、查询和解码分别记录的退出状态、逐表达式对齐表 C4 及五列回归表 C5。未决路径保留 B6 原件。[修订](release/revise/receipt.json) · [保留](release/keep/receipt.json) · [未决](release/unresolved/b6.json) · [后端缺口](release/gap/receipt.json) · [未覆盖](release/uncovered/receipt.json)

## 四种零告警如何计分

- **受保护。** 确定反例、明确 `quiet`、唯一对齐且完整运行无告警，记录 TN。[保留组 C5](release/keep/archive/c5.json)
- **旧规约适用域不足。** NPD 位置 `b.d0ab62…read@1` 的基线预测为 `uncovered`，独立证据为正例。默认列记录 `no_alert`，实际输出同为无告警，计 FN。修订后的同位置计 TP。[未覆盖组 C5](release/uncovered/archive/c5.json)
- **后端事实缺失。** 弱起点 OOB 交接来自真实 B 的 `revise`。在 `library-body` 能力配置下，数据库中只有 `read_span` 声明，缺少该配置要求的函数体。位置 `b.854320…read@1` 的最终预测为 `report`，查询与解码成功，唯一定位后实测无告警，计 FN 并登记缺口。另一种基于已核准接口实参的配置可以取得宽度。这里验证了已声明能力与数据来源的边界。[能力](release/gap/archive/c1.json) · [实测回归](release/gap/archive/c5.json)
- **无法测量。** 对真实 Q* 子进程注入 SIGKILL，退出码为 -9，该版五个位置全部 `unavailable`，可计分位置为零。另一独立位置实验中，重复宏实参的两个 AST 访问落入同一后端坐标，二者均拒绝计分。[中断原始记录](interruption.json) · [宏及多字节坐标](alignment.md)

## 返工、修复与账本

B6 现按本组生效的多批次依赖构造分母。A2 场景继承 b1 两条、排除失效两条、加入 b2 两条；A5 场景继承 b1 两条、加入 b2 两条。两者各加两个有效种子锚点，均得到六个确定位置、一项改变与五项保持。A2 使用了受控的契约返工决定。另一个故障注入向 C 提交错误的 B6 保留决定，复用原观测、运行双版 CodeQL。C5 在五个位置上测得最终版一个忠实于规约的 FN，生产账本回写 `adjudicating`，两版修复余额各为 1。[跨批次原件](upstream-batches.json) · [C5 → B4 回执](b4-fault/proof.json) · [回退事件](b4-fault/events.json)

OOB 保留组首轮两版各有两个实现性漏报。相同名字的函数位于不同源码快照，Guard 谓词误用了其他文件的分支条件。修复将分支限定到同一源文件及所在函数，两版复用同一实现。修复前的数据库、查询与 BQRS 已归档并重新解码。账本在扣费前登记父轮，两版各用一次额度，修复后七个位置全部正确。已核验的归档格式支持本次一个共享修复父轮；涉及多个不同付费父轮时，现行门禁会拦截签发。[父轮 C5](release/keep/archive/repair/parent-c5.json) · [诊断输出](shared-repair/debug.csv) · [预算与事件](release/keep/events.json) · [冻结事务测试](freeze-transactions.txt)

## 坐标、构建与重放

查询运行参数固定为 `--ram=2304 --threads=1`。离线 CLI 2.27.2 和 `codeql/cpp-all` 12.2.0 的工具树摘要、提取器、GCC、Python、运行镜像和数据库分别登记。坐标规则依据本次 BQRS 的实测输出，逐行使用原始快照换算 UTF-8 半开字节跨度。中文注释后的 `values[index]` 位于第 5 行第 21–33 列，字节跨度为 [128,141)。宏、内联和非 BMP 字符的单独测量见坐标报告。[工具链锁](runtime-lock.json) · [表达式对齐表](alignment.md) · [构建原始日志](release/revise/archive/database-build-log.json)

冻结包随附数据库和重放所需项目源码。工具树和镜像按摘要从 VM 的已安装离线工具读取。重放以普通 UID 运行，输入只读，仅有回环网卡，工作目录和输出目录初始为空。导入数据库后重新运行两版查询、重新解码、重建 C4/C5。比较项为解码行的多重集和完整逐位置结果；重新生成的 BQRS 二进制摘要另行保留。每个成对冻结回执只签发一个编号。[修订重放](isolated-revise/replay-proof.json) · [保留重放](isolated-keep/replay-proof.json) · [未覆盖基线组重放](isolated-uncovered/replay-proof.json)

## 命令与验收范围

在 Ubuntu 工程根目录运行。快速坐标测试可用 `varyroot-python3.13 -m unittest discover -s tests -p test_coordinates07.py -v`。全量命令、环境与结果见 [测试命令](commands.md) 和 [完整日志](vm-final-tests.txt)。Linux 上的真实 CodeQL 与 Docker 端到端执行另保留逐命令输出；单元测试计数不替代这些实测。[修订组查询执行](release/revise/archive/build-log.json) · [重放命令](isolated-revise/commands.json)

本次 C 编译器仅接纳已登记 NPD/OOB 单函数读取、接口、源码形态与条款组合。NPD 上游使用版本化种子夹具，提案器为离线确定性实现，部分等价变化是词法改写。跨批回查、冻结与重放验证的是框架在这些输入上的行为。未见真实仓库的检出率、告警质量与人工复核成本仍需独立评测。存储断电项 R04 保持待验。[运行时验收台账](../runtime-acceptance.md)

## 最终全量复跑

在新测试目录开启全部 Docker、Clang、真实冻结账本和重放集成开关后，153 项测试通过，耗时 483.249 秒，跳过 0 项。三个签发包另行完成真实 CodeQL 离线重放。[全量日志](vm-final-tests.txt)
