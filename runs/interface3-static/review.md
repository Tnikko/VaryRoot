# curl/OpenLDAP NPD 的 3a+3b 静态检查点复核

## 结论与范围

同一个开发候选计为尝试 1、生产接受 0、当前待验证种子 1。最终生产运行
`curl-openldap-2018-seed-v4` 停在 `seed_pending`。两次技术修订运行
`v1`、`v2`、`v3` 已在 SQLite 追加 `unresolved` 终态和后继引用，不另计种子。
本轮只签发静态映射、受控骨架和 A4 之前的规约预测。A4/A6 无回执，未签发
`seed_accepted`，也未将预测称为独立证据标签。

## 3a 真实 TU 与映射

父提交 `535432c0adb62fe167ec09621500470b6fa4eb0f`，修复提交
`9889db043393092e9d4b5a42720bba0b3d58deba`，补丁摘要
`c2794773d94987daf7b6bcd8affd4e6b57c213eb557ca24b10350aa8ed83f7e2`。
从前一检查点的 Git 根树校验归档解出两侧完整 curl 树，未改写
`lib/openldap.c`。其 SHA-256 分别为
`90a0753679d24e80d7e55749c17fa6febe3b07b834e60c66a15a5df2afb88353`
和
`6e272b5bdf807550bb1270a73e032bdcda661f0670616cd76eb71722363fd6e0`。

两侧原始 TU 通过 `varyroot-agent-a:step04` 的已锁定命名空间运行
Clang 18.1.3，`-std=gnu17 -fsyntax-only` 均返回 0。角色根文件系统摘要
`211370e2a6900554288c2bd0ab99d0a5064ade0279eefbbae54ba6d94ad19110`。
完整命令模板、输入摘要、配置头生成过程见 `compile-context.json`、
`catalog/source-lock.json`。容器断网、非特权、只读输入与根文件系统，
`execution.json` 和生产 SQLite 事件链见 `review-data.json`、`ledger-backup.sqlite3`。

Clang AST 在 `ldap_recv` 内层 `for` 条件唯一定位首个
`bvals[i].bv_val`。父版为第 550 行、UTF-8 半开字节跨度
`[15935,15950)`，修复版为第 550 行 `[15940,15955)`。两侧 AST 路径均为
`[5,16,4,15,4,3,2,0,0]`。`review-data.json` 保留同函数其他
`bv.bv_val` 及后续 `bvals[i].bv_val` 的节点与跨度，均未充作目标。
父版两次调用末实参 AST 指向 `bvp`，其 `VarDecl` 初始化为取
`bvals` 地址；修复版两次调用末实参直接取同一 `bvals` 地址。
对象同一性由引用的 AST 声明 ID 核对，落盘时转为稳定 AST 路径和源码跨度。

### 编译配置的精确边界

`curl_config_openldap.h` 来自该 curl 树运行 `buildconf` 与
`./configure --disable-ldap --without-ssl --without-libidn2 --without-brotli`
生成的配置，再对四个已记录宏作明确的解析配置变换，开启 OpenLDAP 代码分支。
生成步骤、基配置摘要和变换清单均锁定。OpenLDAP 2.4.45 发布归档提供原始头，
其配置生成了 `lber_types.h` 与 `ldap_features.h`；C 开发头来自原 Ubuntu
24.04 虚拟机的 `libc6-dev 2.39-0ubuntu8.12` 和
`linux-libc-dev 6.8.0-149.149`，全部作为摘要校验的只读输入。
这是一套离线、可重放的**语法与 AST 解析配置**，不声称历史构建参数或链接成功。

## 3b 契约、骨架与规约回放

外部契约范围固定为 OpenLDAP 2.4.45 参考提交
`40421915e08ed1a10b5703973116705a94190ab0`。
`getattr.c`、`ldap.h`、`lber.h` 与许可证摘要见
`catalog/source-lock.json`。成功返回而输出值为空的独立依据还包括
[OpenLDAP ITS#8820 原始报告](https://lists.openldap.org/hyperkitty/list/openldap-bugs@openldap.org/thread/UERCE4KA4F4MWN7OIPH6WKKBCFQFHTWR/)
与[维护者回复](https://lists.openldap.org/hyperkitty/list/openldap-bugs@openldap.org/thread/OGZWDPYGBSLDXRBFOF5UMYLEE3KGZHH7/)。
参考版本并无历史部署版本证明，契约限于本次静态建模。维护者提出的后续属性
可能被跳过属于另一个功能性质，本轮 NPD 标签没有把它混入。

AST 切片从原码逐段保留 `bvp=&bvals`／`&bvals`、两次调用、
`rc` 循环条件、`bv.bv_val` 的不同对象检查和内层目标条件。
`before-skeleton.c`、`after-skeleton.c` 均用锁定 Clang 18 通过语法检查，
目标表达式再次经 AST 唯一定位并映射为 `exact_1to1`。
切片把目标之前的外层消息处理抽象为“已进入属性分支”的适用前提，
把第一次条件求值后的循环体删去。该保真范围在映射中标记
`pending_A4`，须由后续 A4 核查真实可达性，当前不据此签发确定标签。

三份候选 `H_check`、`H_path`、`H_loop` 的 Guard 方向均显式锁为
`iff`。步骤 02 真实解释器对父版三者均推导 `report`，对修复版三者
均推导 `quiet`。见 `predictions.json` 的逐条事实引用与推导轨迹，
预登记预测摘要在 `review-data.json`。静态事实投影进一步验证解释可区分：
“检查后继续”对应 `quiet/report/report`，
“`goto cleanup` 绕开目标”对应 `quiet/quiet/uncovered`
（顺序为 `H_check/H_path/H_loop`）。投影没有独立 Oracle 标签。
把外部契约改成 `pending` 后，同一解释器返回 `uncovered`。

## 生产门禁与测试

正常协调器入口 `varyroot.source_seed` 在生产 SQLite 写入 v4 包，
角色回执记录命名空间后端、镜像 ID、根摘要和输入清单摘要。
在缺少 A4/A6 时调用 `accept_seed` 被生产门禁拒收，列出
`before_ok`、`after_ok`、`candidates_ok`、
`contracts_ok`、`mapping_ok`、`versions_ok`。
种子状态仍为 `seed_pending`，`before_verdict_ref`、
`after_verdict_ref`、`candidate_check_ref` 均为 `null`。
`intake-current.json` 给出唯一候选分母与技术修订去向。

使用项目内 CPython 3.13.2、`VARYROOT_ROLE_BACKEND=namespace`、
`VARYROOT_NAMESPACE_LOCK=toolchains/namespace-v1/image-lock.json`，
`VARYROOT_REAL_OPENLDAP_CATALOG=runs/interface3-static/catalog/catalog.json`
运行 `python3.13 -m unittest tests.test_openldap_seed
tests.test_source_seed.SourceRequestTests -v`，6 项通过、0 跳过。
其中包含两次角色重放逐字节一致、目标与别名结构核对、
未核准契约阻断和真实协调器 A4/A6 门禁拒收。
另将白名单里的 `contract.json` 实际改为 `pending` 后，经同一锁定
角色执行并签出 `seed_pending`，三份候选的双侧预测均为 `uncovered`；
这项测试验证了负测并非只改解释器的内存事实。
`final-tests.log` 保存原始输出。

另试跑包含旧 `test_seed_ledger` 的 11 项组合，8 项通过、
2 项跳过、1 项因宿主缺少 `/usr/bin/clang-18` 而失败，
见 `focused-tests.log`。该旧测试直接在宿主运行
`varyroot.agent_a`；本检查点的 Clang 18 实测全部通过锁定角色命名空间。
未以该失败冒充项目全量回归通过。

## 下一检查点尚待验证

3c 需在相同参考契约下建立前置观察器及四类有限域，核查父版非法状态到达、
修复版阻断与正常安全到达，并对功能遍历差异单独记录。
在 3c 的独立证据进入 A4 且 A6 核对候选之前，生产接受计数保持 0。
