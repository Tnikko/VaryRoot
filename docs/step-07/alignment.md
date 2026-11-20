# R06 表达式坐标回归

在步骤 04 的两个已登记翻译单元上运行 CodeQL CLI 2.27.2 和 cpp-all 12.2.0。独立查询抽取数组表达式的位置、访问角色和投影到该位置的不同表达式数量。用 Ubuntu VM 的 Clang 18.1.3 重新生成 AST 与 O0/O2 调试位置。八个 AST 目标投影为七组后端坐标，六个目标可唯一定位。

| 源文件 | CodeQL 行及首末列（含末列） | 原始 UTF-8 字节区间 | 角色 | 对齐结果 |
| --- | --- | --- | --- | --- |
| accesses.cpp | 3，74–79 | [142,148) | read | read0 定义，唯一 |
| accesses.cpp | 6，21–26 | [213,219) | read | 同行第一个访问，唯一 |
| accesses.cpp | 6，30–35 | [222,228) | read | 同行第二个访问，唯一 |
| accesses.cpp | 7，27–32 | [256,262) | read | PAIR 参数的两次替换，两个目标均 ambiguous |
| accesses.cpp | 8，5–10 | [269,275) | write | 唯一 |
| accesses.cpp | 9，5–10 | [288,294) | read_write | 唯一 |
| reviewed.c | 5，21–33 | [128,141) | read | 同行中文注释后的访问，唯一 |

原始位置来自 [CodeQL 解码结果](alignment-sites.csv)。目标引用、宏替换位置和内联调用点来自 [Clang 索引](alignment-index.json)。O0 没有内联实例，O2 的两条实例记录指向不同调用点和同一源定义。定义粒度可以对齐一次。需要逐调用点计分时，后端必须提供相应上下文。

将 reviewed.c 换成 CRLF，在访问之前的注释中加入非 BMP 字符，并加入制表符。CodeQL 返回第 5 行第 23–35 列，对应字节 [137,150)。该版本按 Unicode 码点计列，制表符占一列。转换器按原始换行字节计算行起始偏移。[变体解码结果](alignment-variant.csv)

完整执行中，只有唯一对齐的 site 行才为该目标提供“零告警”事实。位置回归分别向同行两个已测位置加入 alert 与 gap，验证两个目标的输出独立。重复宏只要缺少区分展开实例的证据，即使告警集合为空，两个目标的实测输出也都为空值。

## 重放

在仓库根目录配置已安装的 CodeQL CLI 与锁定查询包，运行以下命令。脚本仅编译登记的两个翻译单元，打印临时数据库、BQRS 和解码 CSV 的保留目录。比较结果时按完整行排序，结果集没有行序约束。

```sh
export CODEQL="$HOME/varyroot/toolchains/codeql-2.27.2/codeql/codeql"
export CODEQL_PACKS="$HOME/varyroot/toolchains/codeql-2.27.2/packages"
bash tools/alignment07/measure.sh
bash tools/alignment07/measure.sh columns
PYTHONPATH=. python3 tools/alignment07/index_fixture.py > /tmp/alignment-index.json
diff -u docs/step-07/alignment-index.json /tmp/alignment-index.json
python3 -m unittest discover -s tests -p test_coordinates07.py -v
```

上述位置查询测量表达式清单。双版规约产生的实际告警和门禁由各自的运行记录给出。

## 调用表达式

在已登记的 C 调用夹具中，CodeQL 的 FunctionCall 行覆盖被调函数名，Clang 目标覆盖完整调用。以 npd05/before.c 为例，第 3 行第 12–24 列是 `read_required`，原始区间为 [88,101)。从同一份原始快照独立解析 `read_required(p)` 后，调用区间为 [88,104)。

转换规则 `registered_return_call_v1` 绑定十个已登记快照的摘要，并检查函数名首末边界。允许的三个拼写为 `read_required(p)`、`read_span(data, i, 4)` 和 `read_span(data, i, 8)`。转换记录保留原始行列、原始字节区间、解析所得区间及规则名。测试覆盖缺失首字节、重复调用、加入宏定义和目标区间被改动四种拒绝条件。数组表达式直接使用实测的完整区间。
