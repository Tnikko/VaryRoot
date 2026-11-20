# C/C++ 漏洞研究候选集

本目录按空指针解引用、缓冲区越界、释放后使用分别保存 100 条**候选记录**。每条记录独立存为 `CVE-*.json`，各类的 `index.json` 和根目录的 `summary.json` 用于清点。`collect.py` 从 NVD CVE 2.0 API 按 CWE 编号获取原始记录，依据描述中的原生项目关键词、漏洞关键词和补丁链接筛选；`_nvd_cache/` 保留查询快照。重新运行：`python collect.py`。

首轮机制归组见 [mechanism_report.md](mechanism_report.md)，300 条逐项映射和证据状态见 [mechanism_assignments.csv](mechanism_assignments.csv)。运行 `python analyze_mechanisms.py` 可重建两份分析文件。此归组以描述为主，只有报告注明的 4 条检查了上游补丁；不能将自动归组数视为已核验的机制覆盖率。

| 子目录 | 首轮筛选 | 深审重点 |
| --- | --- | --- |
| `null_pointer_dereference/` | CWE-476，描述明确空指针解引用 | 空值来源的契约、受检查值与实际使用值的同一性、空值路径可达性 |
| `buffer_out_of_bounds/` | CWE-125 读 50 条、CWE-787 写 50 条 | 缓冲区身份、容量、偏移、访问宽度及单位；核对实际读写方向后按根因归组 |
| `use_after_free/` | CWE-416 | 明确释放事件、同一分配对象后续访问、单线程事件顺序、无中间重分配 |

## 证据等级和使用限制

当前 300 条均标记为 `candidate_source_and_patch_not_independently_audited`。NVD 分类和补丁引用只能证明有值得核查的线索；**它们尚不能证明符合表中全部收录条件，也不能直接用作 VaryRoot 检出率分母**。尤其是 UAF 的单线程条件和越界访问的精确范围，必须逐条读修复前后源码。一个修复可能对应多个 CVE，反之亦然；根因去重同样尚未完成。每条 `review_required` 明确剩余步骤。没有进行利用或漏洞复现。

已有的判空原型保留在项目的 [`cJSON NULL 解引用试点`](../project/RootVary-codeql/experiments/cjson_null_deref/README.md)；其 [`seeds.json`](../project/RootVary-codeql/experiments/cjson_null_deref/seeds.json) 固定了两个修复簇的易受攻击和已修复版本、5 个代码位置、来源 API。另有 [`libssh 历史案例`](../project/RootVary-codeql/experiments/libssh_cve/README.md) 和 [`seeds.json`](../project/RootVary-codeql/experiments/libssh_cve/seeds.json) 可做独立对照。它们不计入这 100 条 NVD 候选，防止原型及历史修复混计。

资料来源：[NVD 漏洞 API](https://nvd.nist.gov/developers/vulnerabilities)、[CVE 官方记录库](https://github.com/CVEProject/cvelistV5/)、[CWE-476](https://cwe.mitre.org/data/definitions/476.html)、[CWE-125](https://cwe.mitre.org/data/definitions/125.html)、[CWE-787](https://cwe.mitre.org/data/definitions/787.html)、[CWE-416](https://cwe.mitre.org/data/definitions/416.html)。每条记录另有对应 CVE/NVD 页面与候选补丁链接。
