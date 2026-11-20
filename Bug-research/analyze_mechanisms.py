"""Auditable first-pass grouping of the 300 CVE descriptions.

The groups are hypotheses from NVD prose, not source-verified root causes.
Each CVE receives exactly one primary group. Re-run after corpus changes.
"""
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ordered from specific causal patterns to broad fallback. A regex match is
# evidence in the description, not proof that the fix has that causal structure.
RULES = {
    "null_pointer_dereference": [
        ("N1", "分配失败后仍访问", r"(?:allocat\w*|malloc|calloc|kzalloc|kmalloc|snd_ctl_new1|dma_alloc|airq_iv_create)[^.;]{0,90}(?:fail|returns? NULL|can return NULL)|(?:fail|NULL)[^.;]{0,70}(?:allocat\w*|malloc|calloc|kzalloc|kmalloc)"),
        ("N2", "错误返回约定用错", r"\bIS_ERR\s*\(|\bERR_PTR\s*\(|shadowed return|(?:failure|error)[^.;]{0,55}(?:ignored|not propagated|success)|ignores? [^.;]{0,55}failure|without setting the return code"),
        ("N3", "查找或获取结果未判空", r"(?:lookup|find|fetch|resolve|ioremap|platform_get_resource|dev_get_drvdata)[^.;]{0,90}(?:returns? NULL|can be NULL|without (?:a )?(?:NULL )?check|not check|unchecked)|(?:lookup|find|fetch|resolve)[^.;]{0,60}result[^.;]{0,30}(?:NULL|unchecked)"),
        ("N4", "可选字段、配置或状态缺席", r"(?:not (?:initialized|populated|configured|present)|(?:never|not) set|(?:may|can|could) be NULL|is NULL|no (?:certificate|table|driver data|device|key|slot)|IPv6 is disabled|CONFIG_INET=n)[^.;]{0,75}(?:pointer|field|member|state|data|dereferenc|because|when)?"),
        ("N5", "初始化、拆卸或清理次序", r"(?:before|after)[^.;]{0,75}(?:initializ|probe|unmount|remove|cleanup|release|mapping)|(?:unmount|unbind|teardown|cleanup|shutdown)[^.;]{0,75}(?:NULL|freed|dereferenc)"),
        ("N6", "判空位置或对象错误", r"(?:dereferenc|access)[^.;]{0,70}before[^.;]{0,50}check|(?:wrong|different|other)[^.;]{0,45}(?:pointer|object|check|guard)|(?:check|guard)[^.;]{0,45}(?:wrong|different|other)"),
        ("N7", "解析失败或畸形输入未传播", r"(?:parse|decode|init_get_bits)[^.;]{0,75}(?:failure|returns? NULL|fails)[^.;]{0,50}(?:ignored|unchecked|dereferenc)|(?:invalid|malformed|truncated)[^.;]{0,70}(?:returns? NULL|NULL pointer)"),
    ],
    "buffer_out_of_bounds": [
        ("B1", "容量计算与写入量不一致", r"undersiz\w*[^.;]{0,60}(?:buffer|allocat|output)|allocat\w*[^.;]{0,75}(?:but|even though|while)[^.;]{0,75}(?:emit|write|copy|full frame)|(?:fixed.size|smaller|too small)[^.;]{0,65}(?:buffer|window|array)[^.;]{0,55}(?:write|copy|overflow)"),
        ("B2", "偏移、长度与剩余范围未联动", r"(?:total packet length instead of remaining|without reducing the remaining length|against remaining|against the packet end|omits the table starting offset|offset \+ len|starting offset[^.;]{0,60}validat|cursor[^.;]{0,60}remaining|lengths? independently rather than against)"),
        ("B3", "索引或计数未受目标数组约束", r"(?:unchecked|unvalidated|invalid|oversized)[^.;]{0,50}(?:index|count|ID|offset|bitplane|array)|(?:index|count|ID|offset|bitplane)[^.;]{0,55}(?:unchecked|unvalidated|out.of.bounds|array|table)|(?:wrong|incorrect)[^.;]{0,40}(?:loop bound|count|index)"),
        ("B4", "整数溢出或有符号转换破坏边界检查", r"(?:integer overflow|signed bounds check|signed off_t|unsigned size_t|SIZE_MAX|wraparound|arithmetic overflow|offset \+ len[^.;]{0,50}overflow)"),
        ("B5", "字符串终止符或编码宽度漏算", r"(?:NUL.terminat|NUL byte|unterminated|incorrect string termination|unbounded strcpy|%s conversion|truncated multibyte|12.bit end.of.facsimile|4.bit indexed pixel)"),
        ("B6", "协议或文件字段直接决定访问范围", r"(?:attacker.controlled|peer.supplied|host.supplied|controller.declared|unvalidated|unchecked|trusts)[^.;]{0,70}(?:length|size|count|offset|dimension|field|index|value)|(?:length|size|count|offset|dimension)[^.;]{0,70}(?:attacker.controlled|peer.supplied|host.supplied|unchecked|unvalidated)"),
    ],
    "use_after_free": [
        ("U1", "重分配后沿用旧内部指针", r"(?:pskb_may_pull|reallocat\w*|realloc\s*\()[^.;]{0,125}(?:stale|cached|old|pointer|header|buffer|previous)|(?:stale|cached|old)[^.;]{0,85}(?:pointer|header)[^.;]{0,95}reallocat"),
        ("U2", "释放后未清除别名或缓存", r"(?:never clears?|not clear|leaves?[^.;]{0,25}unchanged|retain\w*|stale|dangling)[^.;]{0,75}(?:pointer|reference|cache|field|entry|buffer)|(?:pointer|reference)[^.;]{0,55}(?:unchanged|stale|dangling)"),
        ("U3", "引用计数或所有权转移错误", r"(?:refcount|reference count|put_device|of_node_put|drm_dev_put|kref|ownership contract|giveback_urb)[^.;]{0,100}(?:free|release|drop|prematur|after|before|zero|pin|hold|destroy|consum)|(?:free|release|drop)[^.;]{0,70}(?:refcount|reference count|owner)"),
        ("U4", "错误路径提前释放或重复清理", r"(?:error path|failure path|probe fail|allocation fail|on error|cleanup path|double free|double call)[^.;]{0,115}(?:free|release|cleanup|destroy|use|pointer)|(?:free|release|destroy)[^.;]{0,80}(?:error path|failure path|probe fail)"),
        ("U5", "异步回调或拆卸时序", r"(?:callback|workqueue|delayed work|IRQ handler|interrupt handler|async|timer|disconnect|teardown|unregister)[^.;]{0,115}(?:free|release|destroy|UAF|use.after.free|stop|access|stale)|(?:free|release|destroy)[^.;]{0,100}(?:callback|workqueue|delayed work|IRQ|interrupt|async|timer|disconnect|teardown|unregister)"),
        ("U6", "容器替换或遍历期间元素失效", r"(?:list|array|tree|map|cache|container|queue|entry|iterator|cursor)[^.;]{0,90}(?:replace|freed|remove|destroy|invalidate|stale|realloc)|(?:replace|free|remove)[^.;]{0,90}(?:list|array|tree|map|cache|container|queue|entry|iterator|cursor)"),
        ("U7", "同一函数内先释放后访问", r"(?:free|destroy|release|put|drop)[^.;]{0,75}(?:before|then|after|later)[^.;]{0,95}(?:access|read|use|dereferen|print|call)"),
    ],
}
FALLBACK = {"null_pointer_dereference": ("N0", "描述不足，需读补丁"), "buffer_out_of_bounds": ("B0", "描述不足，需读补丁"), "use_after_free": ("U0", "描述不足，需读补丁")}
OVERRIDE = {
    "CVE-2026-100082": ("N0", "以并发 UAF 为主，空指针为伴随结果"),
    "CVE-2026-64229": ("N0", "硬件 #GP，日志中的 NULL dereference 不是指针根因"),
    "CVE-2026-72316": ("N2", "NULL 与 ERR_PTR 返回约定不一致"),
    "CVE-2026-98134": ("N6", "验证器错误地推断另一指针非空"),
    "CVE-2026-107493": ("U3", "错误路径释放调用者原有的栈元素，所有权边界错误"),
    "CVE-2026-77358": ("U7", "TLS 会话先释放，随后 WebSocket close 帧仍使用它"),
}
PATCH_CHECKED = {"CVE-2026-125064", "CVE-2026-131855", "CVE-2026-107493", "CVE-2026-77358"}
SCOPE = {
    "CVE-2026-100082": "排除：并发 UAF 是主因",
    "CVE-2026-64229": "排除：硬件指令 #GP，不是 C/C++ 空指针访问",
    "CVE-2026-50126": "混合：空指针和越界路径需分离",
    "CVE-2026-106115": "排除：ImageSharp 为 .NET/C# 项目",
    "CVE-2026-106118": "排除：ImageSharp 为 .NET/C# 项目",
}
ASYNCHRONOUS = re.compile(r"\b(?:concurrent|concurrency|race|thread|async|IRQ|interrupt|timer|workqueue|delayed work|callback|worker|RCU)\b", re.I)


def classify(category, description):
    description = re.sub(r"\s+", " ", description)
    for code, name, pattern in RULES[category]:
        match = re.search(pattern, description, re.I)
        if match:
            return code, name, re.sub(r"\s+", " ", match.group(0))[:180]
    code, name = FALLBACK[category]
    return code, name, ""


def main():
    rows = []
    for category in RULES:
        files = sorted((ROOT / category).glob("CVE-*.json"))
        assert len(files) == 100, (category, len(files))
        for file in files:
            record = json.loads(file.read_text(encoding="utf-8"))
            code, name, phrase = classify(category, record["description"])
            scope = SCOPE.get(record["id"], "待源码核验")
            if category == "use_after_free" and ASYNCHRONOUS.search(record["description"]):
                scope = "有异步/并发线索：单线程准入待核验"
            if record["id"] in OVERRIDE:
                code, note = OVERRIDE[record["id"]]
                name = next((rule[1] for rule in RULES[category] if rule[0] == code), FALLBACK[category][1])
                phrase = note
            rows.append({"category": category, "id": record["id"], "mechanism": code, "mechanism_name": name, "description_anchor": phrase, "scope_note": scope, "source_review": "patch_checked" if record["id"] in PATCH_CHECKED else "not_done", "patch_url": record["patch_candidates"][0]})
    assert len(rows) == 300 and len({row["id"] for row in rows}) == 300
    with (ROOT / "mechanism_assignments.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader(); writer.writerows(rows)
    lines = ["# 三类 CVE 泛化机制：描述证据首轮归组", "", "本表覆盖目录中的全部 300 条候选记录，每条仅分配一个主机制。归组依据为本地 NVD 描述的匹配片段及少数人工修正，具体片段见 `mechanism_assignments.csv`。**仅 4 条核查了上游补丁，其他机制是待验证假设，不是已证实的源码级根因或 VaryRoot 测试结论。**", "", "分类时优先具体因果描述；仅有漏洞类别、产品和函数名的记录归入 `描述不足`。同一案例可能兼有多个机制，本表为统计而只取第一个可辨识的主机制。变量名变化只是表象；真正需要泛化的是来源契约、对象同一性、边界表达式和生命周期顺序。", "", "## 已核查的代表补丁", "", "| 类别 | CVE | 补丁显示的因果链 |", "| --- | --- | --- |", "| 空指针 | [CVE-2026-125064](https://github.com/FFmpeg/FFmpeg/commit/ec887b13a88afbaf44fb28c3045bda5d434da8dc) | `init_get_bits8` 失败返回未处理；修复在后续使用前传播错误 |", "| 越界 | [CVE-2026-131855](https://github.com/Ettercap/ettercap/commit/63d1a8498472cb37f76e12ac49e8c09531933e7b) | 指针推进后仍检查整包长度；修复改查 `end - ptr >= 16` |", "| UAF | [CVE-2026-107493](https://github.com/openssl/openssl/commit/0486dfadfec558e1808f59d35a8d79e541c4e7d7) | 错误路径释放调用者原有栈元素却将它们留在栈中；修复只移除本次新增元素 |", "| UAF | [CVE-2026-77358](https://github.com/yhirose/cpp-httplib/commit/2f986fd5e56e7c5f686d965174516360930f371d) | TLS 会话先释放，WebSocket close 帧仍通过保留的原始指针使用它；修复调整关闭次序 |", "", "## 资格问题", "", "- 空指针目录：CVE-2026-100082 的主因是并发 UAF；CVE-2026-64229 是禁用 PCID 后的硬件指令 #GP。两者应从空指针机制分析中排除。CVE-2026-50126 同时涉及空指针和越界，需拆分路径。", "- 越界目录：CVE-2026-106115、CVE-2026-106118 属于 ImageSharp（.NET/C#），不符合 C/C++ 范围。", "- UAF 目录：16 条描述含异步、线程、中断、定时器等线索；`scope_note` 已逐条标记。是否存在单线程触发路径必须读补丁和调用链后判断。", "", "## 可复用的判定关系", "", "| 类别 | 判定关系 | 可变化的表象 |", "| --- | --- | --- |", "| 空指针 | 实际被访问对象 `o` 在可达路径 `p` 上须满足 `o != NULL`；检查其他别名或采用错误返回约定都不能替代它 | 变量名、来源 API、字段层数、helper、错误码表示、条件分支 |", "| 越界 | 对同一缓冲区须证明 `0 ≤ offset` 且 `offset + width ≤ capacity`，计算须避免整数溢出并统一单位 | 文件格式、读写 API、索引/长度字段名、元素与字节单位、分配位置 |", "| UAF | 同一分配对象的 `free` 若先于 `use`，两事件之间无重新建立有效生命周期，则访问无效 | 指针别名、释放 API、引用计数、容器、调用层级、清理路径 |", ""]
    for category in RULES:
        group = [row for row in rows if row["category"] == category]
        buckets = defaultdict(list)
        for row in group:
            buckets[(row["mechanism"], row["mechanism_name"])].append(row["id"])
        lines += [f"## {category}（100 条）", "", "| 机制 | 条数 | 对应 CVE |", "| --- | ---: | --- |"]
        for (code, name), ids in sorted(buckets.items()):
            lines.append(f"| {code} {name} | {len(ids)} | {', '.join(ids)} |")
        lines += ["", f"描述可初步归组：{100-len(buckets.get(FALLBACK[category], []))}/100；描述不足：{len(buckets.get(FALLBACK[category], []))}/100。此处‘归组’不等于源码核验。", ""]
    (ROOT / "mechanism_report.md").write_text("\n".join(lines), encoding="utf-8")
    for category in RULES:
        print(category, {code: sum(row["mechanism"] == code and row["category"] == category for row in rows) for code in [*(rule[0] for rule in RULES[category]), FALLBACK[category][0]]})


if __name__ == "__main__":
    main()
