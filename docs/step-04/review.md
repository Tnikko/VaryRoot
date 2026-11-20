# 步骤 04　源码前端与 Agent A 编码复核

Ubuntu 虚拟机的正式开发目录为 `/home/tq/varyroot`。源码提案、独立契约、已登记的原文件和骨架，已通过只读角色视图交给实际 Clang 与 Agent A。协调器收到的终态为 `seed_pending`。每个种子保留输入版本、目标、候选及逐位置推导，供下一步独立验证。

最终全量回归通过 80 个测试，耗时 41.830 秒，启用了容器测试，无跳过。角色镜像及原始种子事件使用同一镜像摘要。

## 工具链与可复核范围

- Ubuntu 24.04.5 LTS，项目位于 ext4。宿主测试进程使用 CPython 3.13.2，Agent A 容器使用 CPython 3.13.18。Clang 包版本为 `1:18.1.3-1ubuntu1`，目标为 `x86_64-pc-linux-gnu`。固定 C17 / C++17 和两档优化，记录 256 个编译器、资源和依赖文件的摘要。[环境与镜像](environment.json) · [工具链锁](../../tools/frontend/clang18.lock.json)
- 镜像从本地固定基底离线构建，角色运行时关闭网络、挂载只读根与只读输入，输出只写入本尝试目录。归档路径、摘要和成功加载记录见环境文件。此次在同一 Docker 引擎验证归档可读和镜像程序摘要一致，空白环境整包重放仍属于 R11。
- 源码位置前端接受已登记夹具及经宿主清单授权的自含整数／固定数组子集。宏、内联走查使用单独登记的 C++ 翻译单元。Agent A 的事实抽取覆盖一个受控 C 函数、一个逻辑可读区间、一处数组读取、单输入路径和两条候选 Guard。数组物理容量充足，违规预测针对独立契约规定的逻辑前缀。骨架允许消去无引用、以常量初始化的局部枚举；改变保护逻辑或删除被使用的声明会被拒收。此范围尚未验收多翻译单元、任意补丁切片、通用桩合成或真实项目覆盖率。

## 逐位置结果

| 输入与查询精度 | 实测结果 |
| --- | --- |
| 第 6 行的两个下标读取 | 仅给行号得到两个候选；字节区间分别为 [213,219) 和 [222,228)，各自唯一。 |
| 重复宏实参 | 两处 AST 节点共用拼写 [256,262)、展开 [251,255)。宏定义内使用位置分别为 [59,60)、[65,66)。仅有相同展开位置的 IR 指令保留歧义。 |
| 同一内联定义的两个调用点 | AST 始终保留一处定义与两个调用点。O0 查到 0 个内联实例，O2 查到两个，inlinedAt 分别回到第 10 行第 12、25 字节列。 |
| 同行有多字节注释 | `values[index]` 位于 [128,141)，字符列 21、字节列 25。实测切片与步骤 01 的 Snapshot 校验均通过。 |
| 访问角色与空匹配 | C++ 夹具区分 5 读、1 写、1 读写；不存在的位置返回 unmapped。 |

[逐向量 JSON](mappings.json)

## 交接、门禁与返工

1. 真实角色链依次写入 created、manifest、seed_package、seed_pending。合法输入对两条候选均得出修复前 report、修复后 quiet。退出与修正索引后继续访问通过不同路径推导。验证器裁决和 A6 引用为空，重复提交同一清单返回既有收据。[种子事件与推导](seed-chain.json)
2. 待审核、未知容量单位、错误容量对象分别走真实 Docker、SQLite 和独立进程的 validate / explain。三份工件结构有效，报告前提均为 uncovered，生产种子接受调用遭门禁拒绝。独立契约的身份、摘要和审查状态随 Fact 入包；提案无法自批。另测得仅访问宽度待审时，完整区间候选缺项，只依赖起点的候选仍可作出预测。
3. A2 用真实 Agent A 产出的包修改修复前来源节点的测试审查标记，检查依赖传播。子包 v2 回到 seed_pending，修复前裁决、相关映射与候选需重新核对，修复后裁决仍适用。A5 只替换工作规约和解释集，保留首次基线、两侧裁决、已揭示水位和预算；追加预测为 post_remodel。两条链实际提交 SQLite；种子通过及裁决签发使用明确隔离的测试证明，修改的工作规约内容为返工协议夹具。[真实种子包返工事件](source-rework.json) · [独立账本对照](rework.json)
4. 集成首跑发现尾部 LF 与步骤 03 的规范 JSON 字节约定冲突，修正角色发布编码并加入逐字节断言。测试账本现在使用独立文件与显式测试类，仿照测试组或请求名无法令生产账本放行。首次单测复跑发现一个旧并发用例触及 10 秒进程栅栏，已在最终全量运行中复核。[首跑诊断](first-integration.txt) · [全量回归](vm-final-tests.txt)

## 实际执行与重放

以下命令在虚拟机项目根目录执行。第一次捕获工具链锁使用 `toolchain --capture`。后续 toolchain 构建先核对锁，role 再构建角色。现有归档也可直接通过 docker load 取回该版本的角色镜像。

~~~bash
cd /home/tq/varyroot
export PATH="$HOME/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1 VARYROOT_DOCKER_SUDO=1 VARYROOT_R05_DOCKER=1 VARYROOT_R06_DOCKER=1
sudo -v
varyroot-python3.13 -m tools.frontend.build toolchain
varyroot-python3.13 -m tools.frontend.build role
VARYROOT_TRACE_DEST="$PWD/runs/step04-contract-submission" \
VARYROOT_SEED_TRACE_DEST="$PWD/runs/step04-source-submission" \
VARYROOT_REWORK_REPORT="$PWD/docs/step-04/rework.json" \
varyroot-python3.13 -m unittest discover -s tests -v
~~~

复跑时使用新的 TRACE_DEST 和 SEED_TRACE_DEST，保留原始台账。R06 更新为前端分项通过；步骤 07 接入实际 CodeQL 后复核跨工具消歧。R07 和 R08 的独立验证器部分留待步骤 05。[运行时验收台账](../runtime-acceptance.md) · [步骤 05 待审计划](step-05-plan.md)
