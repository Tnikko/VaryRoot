# 7server 检查点 3.0 + 3.1 复核报告

日期：2026-11-19。项目：`/dev_sdb/tq/VaryRoot`。种子：`curl-openldap-2018-seed-v4`，生产状态保持 `seed_accepted`。本轮是**真实模型提案接口与候选池波动摸底**；没有向生产 B 揭示任何候选裁决，也没有运行配对校准或评测。

## 3.0：迁机后的旧测试门禁

- 问题：锁定 Clang 18.1.3 根文件系统的 `/usr/bin/clang-18` 是包装脚本。旧 `-shared` 一步式构建的自派生前端会误将 `-cc1` 作为动态加载器输入，复现为 `-cc1: error while loading shared libraries`。
- 修复范围：仅在 `runs/step3-model-intake/src/clang_shim.py` 与 `locked_suite.py` 中加入**测试专用**编译/链接分步适配器，将锁定 Clang ELF 与锁定 GNU gold 用于旧原生测试。生产 `tools/frontend/clang18.lock.json` 未更改。RED 记录 `out/native-red.log`，GREEN 记录 `out/native-green.log`。
- 命令：`toolchains/cpython-3.13.2-linux-x86_64-gnu/bin/python3.13 runs/step3-model-intake/src/locked_suite.py python -m unittest discover -v -s tests`（实际命令及环境由 `locked_suite.py` 固化）。结果 `out/full-suite.log`：167 项，135 通过、32 按既有环境门槛跳过、0 失败/错误，107.067 秒。**不能将其表述为 167 项零跳过。**
- 补充实跑：在项目私有 namespace 锁下，`tests/test_agent_b06.py` 的 3 项 B 集成测试全部通过（135.774 秒）；`tests/test_namespace_backend.py` 的 6 项隔离与进程树测试全部通过（11.840 秒）。其余旧跳过项尚未以此解释为已执行。
- 新增 3.1 单元测试：`python3.13 -m unittest discover -v -s runs/step3-model-intake/src -p 'test_*.py'`，8 项通过，6.084 秒（`out/intake-tests.log`）。

## 3.1：真实 DeepSeek 提案的输入与网络边界

- 输入来自**已接受**的生产种子：双侧源码骨架、精确目标映射、已核准 OpenLDAP 2.4.45 参考契约、`S₀=spec.openldap.H_check@1` 与 `H_check/H_path/H_loop` 三解释；其字节摘要见 `out/proposal-input.json`、`out/prompt.json` 和 `out/run-lock.json`。提示词摘要 `6c8d1fa7f045d48c8e282a434ce8a29d0acd12de571b320561287e98a486e589`。输入排除裁决、`reserve` 样本和密钥；模型只给 C 代码与单因素意图。
- 7server 的 `api.deepseek.com` DNS 查询失败，已解析 IP 的直连 443 也超时。API key 只负责认证，不解决 DNS/路由。实际使用服务器侧独立提案客户端，经项目外的 SSH 反向端口转发、Windows 本机仅 loopback 的受限桥、VPN 7900 访问官方 API。验证器、选择器与 Agent C 的断网角色环境未开放网络。服务端秘密文件位于 `/dev_sdb/tq/.secrets/deepseek_api.txt`（目录 700，文件 600），不在项目、输入清单或归档中。
- 固定调用：`POST /chat/completions`，`model=deepseek-flash`、`thinking.enabled`、`reasoning_effort=high`、`max_tokens=32768`、`top_p=1.0`、JSON 对象响应；未传工具或温度。三次独立请求字节摘要相同。服务端响应仅返回 `model=deepseek-flash` 与相同 `system_fingerprint`，未提供可独立确认的后端完整版本号。每次均 HTTP 200、`finish_reason=stop`、有效 JSON、无自动重试；请求、原始响应（含 `reasoning_content`）、元数据、缓存 token 与耗时均单独留存于 `out/model-0*.json`。
- 三次依次生成 5、6、6 个原始提案，总计 17 个；合计 30,827 tokens。按调用时官网费率与缓存命中计算，估算费用区间为 USD 0.009566–0.019132，非结算账单。三次响应耗时 18.37、28.235、17.931 秒。

## 前端准入、预测与冻结结果

每个变体均经正式 `varyroot.sandbox.materialize/run_role` 的 namespace Agent A 角色、锁定 Clang 18 解析；`Fact` 由 AST 目标/别名/路径抽取与原种子已核准的外部契约拼接，三份预测由步骤 02 真实 `evaluate()` 计算。模型文本不提供 `Fact`、标签或批准。每个入池目标记录 AST 路径、半开字节跨度、源码/AST 摘要与输出槽链。完整逐案记录在 `out/admission.json`，逐条输入事实和预测在 `out/derivations.json`，正式 AST 角色回执在 `out/ast-admission.json`。

| 冻结池 | 原始提案 | 准入有分歧 | 准入无新增分歧 | 提案自身缺陷 | 合理但当前不支持 | 冻结唯一变体 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| model-01 | 5 | 0 | 3（含池内重复 1） | 0 | 2 | 2 |
| model-02 | 6 | 2 | 2 | 0 | 2 | 4 |
| model-03 | 6 | 1 | 3（含跨池重复 2） | 0 | 2 | 2 |
| 合计 | 17 | 3 | 8 | 0 | 6 | 8 |

三条“有分歧”均为**适用域差异**：`H_check=quiet`、`H_path=quiet`、`H_loop=uncovered`；硬分歧 `report/quiet` 为 **0**。关键原因是局部 `if(bvals==NULL) break` 的真实路径已经阻断，解释器不能仅因 `H_loop` 的必要 Guard 缺失而忽略 `reaches=false`，强推 `report`。这些变体不能据此淘汰 `H_loop`。池内外重复在保留原始提案计数后从后续冻结池排除。

离线确定性对照的两例中，“判空后继续”的前置 AST 事实使 `H_check=quiet`、`H_path=report`、`H_loop=report`，产生一条硬分歧；“判空后提前退出”与 model-02 一例源码相同，被排除重复。离线对照不能算入三次模型产出的硬分歧。

`out/pool-model-01.json`、`pool-model-02.json`、`pool-model-03.json` 与 `pool-offline-baseline.json` 已哈希锁定，并由 `out/freeze.json` 绑定请求、原始回复、AST 回执、推导、池清单和工具锁。三份模型池互不重叠。**这只是独立裁决前的静态准入池**：`observation_status=not_yet_verified`，尚无 B 的 `selection`、验证预算扣减或开发集标签，不能宣称候选已经确定正反，也不能据此评价随机与分歧选例策略的优劣。

## 复核与限制

1. 逐条核对了 17 个源码对父骨架的差分。6 个 `unsupported_shape` 包括外层 `while` 改写、`bv` 分支形态改变、嵌套正向包围目标以及输出槽别名/错误对象条件；它们保留为合法研究缺口，不被算作模型语法失败。实际 17 例没有编译失败或多因素拒收，因此“提案自身缺陷”为 0。
2. `out/freeze.json` 的 19 个文件摘要和 Clang/namespace 工具锁可逐项核验。已接受生产种子仍可通过门禁；本轮没有改写生产 SQLite 的 B 状态。
3. 旧测试的 32 项跳过与当前受控前端形态限制继续作为边界记录。3.1 只做一个真实种子、三次采样；`R08` 的真实模型池波动现在有原始记录，但跨池 `S^* / Q^*` 收敛、取证预算和误报质量尚未测量。
4. 归档生成前对项目内交付文件执行密钥原文及 Bearer 认证头模式扫描，归档不含服务器凭据。完整证据同步到本机 `F:\RootVary\server-reports\2026-11-19-step3-model-intake`。
