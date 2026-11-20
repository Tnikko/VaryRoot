# 步骤 05　独立验证器、A4 与 A6

全量回归启用三组容器测试开关，99 个测试通过、0 跳过，耗时 70.758 秒。 独立复跑使用新运行目录再次完成 99 项测试，0 跳过，耗时 78.856 秒。

正式实现位于虚拟机 /home/tq/varyroot。前一轮的 step-05-plan.md 与批准的 05a–05d 范围一致。新增的 NPD 上游采用版本化种子夹具，OOB 上游调用步骤 04 的 Agent A 容器。两者共用生产账本、回执发布协议和规约解释器。

## 可重放的种子结果

| 种子或故障 | 观察与裁决 | 事务结果 |
| --- | --- | --- |
| OOB 修正索引后继续 | 单次正常调用中，修复前请求 [12,16)，超过独立核准的 8 字节逻辑前缀；修复后实际读取 [4,8)，读取次数与原程序返回值核对通过。物理数组为 32 字节。 | 两条候选均与前后裁决相容，进入 seed_accepted。 |
| OOB 早退 | 同一源包只含固定索引 3，修复后唯一执行在目标前退出。域已穷尽，但没有正常读取见证。 | after 为 pending，A4 停在 seed_pending。 |
| NPD 早退及重绑定 | 输入为正常与缺失两种模式。缺失输入在修复前到达要求非空的读取接口，探针先记录意图；修复后分别记录阻断、或初始为空且重绑定一次后读取已登记的静态对象。正常输入独立到达同一目标。 | 两种修复分别通过生产 A4/A6。恒判受保护的候选被排除。 |
| 契约欠缺、对象不符或观察域退役 | 每项记录独立原因与相关引用。过期回执不能提交到当前域；当前域另发请求后可恢复。 | A4 阻断时保留候选。 |
| 基线不相容或其余候选全部不相容 | A4 已有两侧合格证据。A6 从当前工件重算初始基线、工作规约及各竞争解释，并保存逐路径推导。 | 路由 A5。该状态下无法跳过新种子的接受门禁登记 B 批次。 |
| A2 更新修复前来源 | 旧 before 回执带 v1，直接提交被拒；改标 v2 仍因绑定不符被拒。after 已提交裁决与当前依赖及镜像吻合。 | v2 只补发 before 请求，A6 全量重算后再次接受。 |

[种子与失败事件链](seed-events.json) · [独立观测与覆盖裁决](verifier-receipts.json)

## 探针与证据

原生驱动用锁定的 Clang 18 在宿主编译，受限角色进程执行已登记的库。构建时将源字节摘要、访问跨度、二进制摘要、独立契约、观察域和正常输入编号绑定。验证器接收源、目标、契约和域四个白名单工件。真实容器目录检查记录了清单本身、四个输入、只读错误 30、仅 lo 和无 Docker socket。[角色实测](role-view.json) · [构建记录](image-build.txt) · [环境](environment.json)

物理容量等于契约容量的独立向量使用真实 8 或 255 字节对象。原生程序先求出操作数，将标量交给 Python 数学整数观察器，再决定是否执行读取。C17 与 C++17 的负偏移、尾部越界、零宽度均为零次实际读取。贴边的两字节读取和已定义窄化后的读取有参考值；同一有序副作用表达式都留下 [1,2] 且仅出现一次。257 经无符号 8 位转换后偏移为 1，254 加宽度 3 的数学终点为 257。有符号源加法超出可表示范围时返回案例失败，无有效后值。[原生逐向量记录](native-observations.json)

覆盖以当前适配器登记的有限集合逐成员核对。正例有合格违规见证即可；反例同时需要全域覆盖以及正常输入成员上的安全读取。只有故障输入安全到达、所有路径早退、零宽度或漏测第二种故障模式，均不能签发反例。本版通过有限枚举签发 negative，尚未接入等价类证明签发器。前置观测支持登记的合成访问，未对任意 C/C++ 表达式提供插桩保真结论。

## 发布、预算与复核修正

- A 的启动验证单独记请求，B 的每次选例按逻辑请求扣费。零宽度和缺少一个故障模式的两个独立请求，均返回 pending、各扣一次；取回同一回执不另扣。
- 错对象请求按 case_exec_failure 封存且没有裁决。在验证通道注入替代子进程并实发 SIGKILL 后，基础设施失败沿同一 request_id 派发第二次尝试。另一次注入在角色已封存有效回执后破坏返回通道，协调器直接取回，前后两侧各只执行一次。
- 复核期间修正了封存回执的优先级、故障态绕过 A5、初始基线与工作规约混用、正常输入见证资格，以及 A2 后骨架变换的再核对。A4 通过请求、物理尝试、清单摘要、已发布工件、两侧依赖与包版本核对证据；A6 在同一 SQLite 写事务检查当前版本并推进。
- A4 以独立契约核准原因细分 pending_capacity_review、missing_logical_capacity_or_unit、wrong_capacity_object，并定位 Fact。上轮已发布的解释器预测保留原始诊断文本。旧 10 秒并发栅栏在本机另行重复 6 次，每次既验证选例也验证修复并发。实测均通过，保留原等待值。[并发复测](concurrency.json)

## 命令与交付边界

~~~bash
cd /home/tq/varyroot
export PATH="$HOME/.local/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
export VARYROOT_DOCKER_SUDO=1 VARYROOT_R05_DOCKER=1 VARYROOT_R06_DOCKER=1 VARYROOT_R07_DOCKER=1
sudo -v
varyroot-python3.13 -m tools.verifier.build
export VARYROOT_05_TRACE="$PWD/runs/step05-final"
export VARYROOT_TRACE_DEST="$PWD/runs/step05-legacy-final"
export VARYROOT_SEED_TRACE_DEST="$PWD/runs/step05-source-final"
varyroot-python3.13 -m unittest discover -s tests -v
varyroot-python3.13 -m tools.verifier.review "$VARYROOT_05_TRACE" docs/step-05
~~~

重放测试时为三个 TRACE 变量选择新的空目录。R07 的登记夹具运行时验收通过，R08 的验证器和 A4/A6 分项通过。B、随机选择器及 B6 的实测由步骤 06 承接。[全量测试日志](vm-final-tests.txt) · [独立复跑日志](audit-tests.txt) · [台账](../runtime-acceptance.md) · [步骤 06 待审计划](step-06-plan.md)
