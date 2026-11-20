# 7server 接口增量 1 + 2 工程检查点复核

日期：2026-11-19。范围仅为协调器命名空间后端、项目私有根文件系统与工具锁；
真实 curl/OpenLDAP 源码适配为[独立待审设计](step03-interface-design.md)，未实施，
开发集该候选仍记“尝试 1、生产接受 0”。

## 实施与审计边界

1. `run_role` 现要求显式设置 `VARYROOT_ROLE_BACKEND=docker|namespace`。
   `namespace` 必须另外给出位于项目内的 `VARYROOT_NAMESPACE_LOCK`。
   缺配置、未登记镜像、摘要不符或命名空间启动失败直接拒绝；没有宿主执行或共享
   Docker 回退。构建镜像用的 `docker_id` 与生产派发的 `resolve_image`
   已分开，生产 Agent A、验证器、选择器和步骤 03 文件桩均经统一解析入口。
2. `unshare -rnm` 与 `bwrap` 将角色放进独立用户、挂载、网络和 PID 命名空间。
   根文件系统与 manifest 视图只读，输出目录独占，临时目录为私有 tmpfs。
   进程超时时杀独立进程组，并由 `--die-with-parent` 与 PID 命名空间清理
   `setsid()` 的延迟子进程。每个尝试落 `execution.json`，Agent A 与验证器
   再把后端、镜像 ID、根文件系统摘要、请求／尝试 ID、UID、挂载、网络及退出状态
   记入生产 SQLite 事件。
3. 原 VM 四个镜像按原镜像 ID 导出。传输后逐个核对 tar SHA-256 和 ID sidecar；
   解包器先检查路径、重复条目、符号链接父路径及硬链接目标，再提取。导出镜像
   为 `bwrap` 补入空的 `/work`、`/output` 挂载点后计算内容及模式清单摘要。
   运行前重新计算根文件系统摘要；修改单个文件会在派发前被拒绝。
   [来源锁](../../tools/namespace/source-lock.json)、
   [运行锁](../../toolchains/namespace-v1/image-lock.json)。
4. Agent A 根文件系统的 `/opt/clang` 文件逐项与
   `tools/frontend/clang18.lock.json` 的 256 个文件对照，Clang 运行输出的版本
   `18.1.3 (1ubuntu1)` 和目标 `x86_64-pc-linux-gnu` 一致。
   `InstalledDir` 因容器内重定位由 `/usr/bin` 变为 `/opt/clang/bin`，
   已明确写入测试，不作为编译器版本漂移。验证器 registry 中 22 个已登记原生
   `.so` 的 SHA-256 均逐项匹配；本轮只复核已有观察器，未构建新观察器。

四份项目私有根文件系统与解包材料均位于
`/dev_sdb/tq/VaryRoot/toolchains/namespace-v1/`。运行锁的 SHA-256：
`ae0fdd2c6eb1d697f9ebb807414d5e5c86cb5f0d87c534100878aeb1c373008e`。
服务器上的全部写入，包括临时目录、账本、测试日志、根文件系统和复核包，均位于
`/dev_sdb/tq/VaryRoot`。

## 实测结果

| 证据 | 结果 |
| --- | --- |
| 七个角色／阶段物理视图 | A、验证器、B、C 编译、C 回归、随机、分歧全部非 root，只见 `lo`，无 Docker socket；`/input` 与角色代码只读；随机输入恰为 `budget.json`、`input_manifest.json`、`policy.json`、`pool.json`，没有预测或排序 |
| 命名空间单元 | 无锁、未知后端、根目录篡改均拒绝；任意工作目录可启动；`CapEff=0`、`NoNewPrivs=1`；`setsid()` 延迟子进程超时后不能写入 `/output` |
| 步骤 03 四条文件链 | `revise`、`keep`、`unresolved`、`gap` 经真实解释器和命名空间角色完成，2 项测试通过 |
| 生产 Agent A 与 A4/A6 | 真实协调器把受控 OOB 输入派到锁定的 Agent A 根目录，交付 `seed_pending`；受控 NPD/OOB 验证器、资格门禁、缺证与错误契约路由通过 |
| 预算与恢复 | 保存的生产账本中，同一 `B.verify` 请求第一次物理尝试退出 `137`、第二次退出 `0`；`B.verify` 余额最终为 0，没有按重试重复扣费；A2 升版后旧侧回执被拒，未变更侧按依赖复用 |
| 受影响模块回归 | 37 项、0 失败、0 错误，耗时 328.958 秒；覆盖 A、验证器、B、随机选择器、文件桩、沙箱及镜像导入 |
| 最终配置复跑 | 严格显式后端配置、工作目录无关启动与根目录篡改拦截落码后，19 项关键路径重新执行，0 失败、0 错误，耗时 74.421 秒 |

日志在本目录的 `sandbox-matrix.log`（原始位置
`toolchains/namespace-v1/sandbox-matrix.log`）、`source-chain.log`、
`budget-recovery.log`、`affected-regression.log`、
`final-focused.log`；SQLite 原始账本保留在
`source-ledger/` 与 `routes/`。由账本和日志重建的
[机器摘要](summary.json)包含每次执行审计与请求／尝试对应关系。

## 全量回归及已知边界

在 7server 宿主直接执行 `unittest discover -s tests -v` 的记录为
150 项，10 失败、4 错误、7 跳过。逐项 traceback 的共同原因是宿主没有
`/usr/bin/clang-18`：旧 `test_agent_a`、`test_frontend`、
`test_probe05`、`test_domain05`、`test_seed_ledger` 直接在宿主编译，
未走本次锁定的角色根文件系统。生产 Agent A 内的 Clang 18 实测通过，
因此这 14 项不能视为生产后端失败，也**不能声称全量测试通过**。
[完整失败日志](full-regression.log)保留每条 traceback。

命名空间后端尚无 Docker `--memory=256m` 与 `--pids-limit=64` 对应的
cgroup 资源限额。本检查点只验收权限、文件、网络、进程树超时与围栏；
不得把资源耗尽隔离宣称为与旧 Docker 后端等同。R04 真实存储断电耐久
仍待验。Agent C 的 CodeQL 工具树已在项目目录，但本轮未改写其单独的
冻结重放入口。真实 curl NPD 的 A2/A4/A6 尚未实施。

## 文件与命令

关键代码：`varyroot/sandbox.py`、`varyroot/namespace_exec.py`、
`varyroot/source_seed.py`、`varyroot/verify_request.py`、
`varyroot/selector.py`、`varyroot/contract_replay.py`、
`tools/namespace/import_rootfs.py`。新增测试：
`tests/test_namespace_backend.py`、`tests/test_namespace_import.py`。

服务器测试前设置：

```bash
cd /dev_sdb/tq/VaryRoot
export TMPDIR=$PWD/.tmp
export VARYROOT_ROLE_BACKEND=namespace
export VARYROOT_NAMESPACE_LOCK=$PWD/toolchains/namespace-v1/image-lock.json
export VARYROOT_TEST_NAMESPACE_LOCK=$VARYROOT_NAMESPACE_LOCK
export VARYROOT_R05_DOCKER=1 VARYROOT_R06_DOCKER=1 VARYROOT_R07_DOCKER=1
export VARYROOT_STEP06_DOCKER=1 VARYROOT_R08_DOCKER=1
PYTHONPATH=. toolchains/cpython-3.13.2-linux-x86_64-gnu/bin/python3.13 \
  -m unittest tests.test_namespace_backend tests.test_namespace_import \
  tests.test_sandbox tests.test_contract_replay tests.test_source_seed \
  tests.test_seed05 tests.test_routes05 tests.test_selector06 \
  tests.test_agent_b06 tests.test_b606 -v
```

下一步仅提交[真实 NPD 接口增量 3 设计](step03-interface-design.md)审核；
该项通过前不修改前端、验证器或生产种子状态。
