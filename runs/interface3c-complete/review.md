# curl/OpenLDAP 3c 全域观测复核

本轮在 7server 的 /dev_sdb/tq/VaryRoot/runs/interface3c-complete 中完成受控骨架的四类有限域观测。生产种子 curl-openldap-2018-seed-v4 保持 seed_pending，开发候选分母为尝试 1、生产接受 0、待验证 1。3d 的 A4/A6 生产门禁未运行。

## 双侧逐类结果

| 输入类 | 父版 | 修复版 |
| --- | --- | --- |
| ① LDAP_SUCCESS、空输出、有效属性名 | 首次目标求值前记录 bvals 为空、i=0，违规事件 1，实际目标读取 0 | 属性接口调用 1 次；外层条件阻断目标，违规 0，实际读取 0 |
| ② LDAP_SUCCESS、有效对象和带哨兵数组 | 已映射目标条件依次读取索引 0、1，真实读取 2，正常见证 1 | 同左 |
| ③ 非成功、空输出 | 属性接口调用 1 次，目标未到达，读取 0 | 同左 |
| ④ 空值属性后预设另一个可用属性 | 首次目标求值前记录违规；探针随后向外层循环返回停止信号，下游功能行为记为未定 | 属性接口只调用首次，预设的第二个属性未被请求；遍历截断字段为 true |

父版独立裁决为 positive，违规输入为 ① 和 ④。修复版独立裁决为 negative，四类有限域均已观测，第 ② 类提供真实安全访问及正常功能见证。两侧 coverage_basis 均为 exhaustive_finite_domain，missing 均为空，normal_witnesses 均为 [2]。回执中的 parent case ④ 第二次接口调用标记 after_violation，属于探针停止序列，不用于推断原程序在无效访问之后的行为。

## 来源与方法

实验输入绑定 3a/3b 已登记的父版、修复版骨架摘要与唯一目标表达式跨度。build.py 校验字节摘要及目标唯一性，只将该表达式替换为 observe(rc,bvals,i)，不修改原始 lib/openldap.c。observe 在对象和索引检查后，对有效数组执行 owner[index].bv_val 的真实读取，对空对象在索引前记违规并返回停止值。C 源码、编译和链接命令、锁定 Clang 18.1.3 与 GNU gold 版本、输入头文件及两个 .so 摘要见 out/build-lock.json 和 out/header-digests.json。编译输入和两个生成后的 C 文件均随包保存。

验证器通过项目的 namespace 后端运行。out/before-input_manifest.json 与 out/after-input_manifest.json 的白名单只含契约、观察域、目标绑定、观察器和执行脚本，不含候选 Guard、预测或查询输出。执行审计及角色内检查记录非特权 UID 1009、只读输入、仅 lo、无 Docker socket。每类输入在验证器内独立子进程执行，子进程异常退出或超时返回 case_exec_failure，不参与正反裁决。源表达式未定义和无关故障的具体路径仍需由后续真实案例适配验证。

两侧原始回执在 out/before-raw.json、out/after-raw.json。协调器在独立检查点 SQLite 使用 Publication 发布和读取，重复提交保持同一 ready 摘要。七项绑定负测每侧覆盖请求、尝试、清单、观察域、映射状态、种子包及契约摘要。生产 SQLite 只读核对，未接入 A4/A6。out/receipt-ledger.sqlite3 保存检查点发布状态，out/audit.json 保存独立重算结果。

## 复核与边界

实际运行 13 项相关测试全部通过，包含全域结果、篡改事件拒收、子进程崩溃与超时分类、旧版前端和步骤 05 的裁决与围栏回归。日志见 out/final-tests.log。旧 partial_sample 回执仍保存在 interface3c-review 中，本轮新目录和新请求不覆盖旧记录。

本轮结果成立于经 Clang 18 编译的 3b 最小骨架和 OpenLDAP 2.4.45 参考契约。原代码到骨架的路径保真仍标记 pending_A4。修复版第 ④ 类的功能字段证明该骨架没有请求预设的第二个属性，不代表完整 libcurl 程序的功能评价。3d 须先核查契约资格、原码到骨架映射与双侧观察域版本，再由 A4/A6 事务性核准候选及种子状态。
