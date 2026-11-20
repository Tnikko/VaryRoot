# 逐位置双版回归

每行对应一个版本和目标。坐标列保留 BQRS 行及含末列范围，字节区间对应同一份原始快照。函数调用按冻结的表达式换算规则展开。空栏用破折号表示。

## NPD 正常修订

|快照摘要|BQRS 行、首末列 → 目标字节区间|版本|证据标签|规约预测|实现默认|后端缺口|实际输出|计分|去向|
|---|---|---|---|---|---|---|---|---|---|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Q0|positive|report|—|—|alert|TP|pass|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Qstar|positive|report|—|—|alert|TP|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Q0|positive|report|—|—|alert|TP|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Qstar|positive|report|—|—|alert|TP|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Q0|positive|quiet|—|—|no_alert|FN|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Qstar|positive|report|—|—|alert|TP|pass|

[完整目标引用](release/revise/archive/c1.json) · [对齐](release/revise/archive/c4.json) · [五列原始结果](release/revise/archive/c5.json) · [预算](release/revise/archive/budget.json)

## OOB 有据保留

|快照摘要|BQRS 行、首末列 → 目标字节区间|版本|证据标签|规约预测|实现默认|后端缺口|实际输出|计分|去向|
|---|---|---|---|---|---|---|---|---|---|
|`cf620cd1074e…`|4 行 12–20 → [83,104)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`cf620cd1074e…`|4 行 12–20 → [83,104)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`a888b74f1451…`|6 行 12–18 → [152,159)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`a888b74f1451…`|6 行 12–18 → [152,159)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`93b7f5b7e9f6…`|5 行 12–20 → [129,150)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`93b7f5b7e9f6…`|5 行 12–20 → [129,150)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`30b6b82bd06f…`|4 行 12–20 → [83,104)|Q0|positive|report|—|—|alert|TP|pass|
|`30b6b82bd06f…`|4 行 12–20 → [83,104)|Qstar|positive|report|—|—|alert|TP|pass|
|`bdd5c1325a9e…`|5 行 12–18 → [129,136)|Q0|positive|report|—|—|alert|TP|pass|
|`bdd5c1325a9e…`|5 行 12–18 → [129,136)|Qstar|positive|report|—|—|alert|TP|pass|
|`bf6e7db133b0…`|5 行 12–18 → [106,113)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`bf6e7db133b0…`|5 行 12–18 → [106,113)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`66b8fda465c6…`|4 行 12–18 → [83,90)|Q0|positive|report|—|—|alert|TP|pass|
|`66b8fda465c6…`|4 行 12–18 → [83,90)|Qstar|positive|report|—|—|alert|TP|pass|

[完整目标引用](release/keep/archive/c1.json) · [对齐](release/keep/archive/c4.json) · [五列原始结果](release/keep/archive/c5.json) · [预算](release/keep/archive/budget.json)

## OOB 后端缺口

|快照摘要|BQRS 行、首末列 → 目标字节区间|版本|证据标签|规约预测|实现默认|后端缺口|实际输出|计分|去向|
|---|---|---|---|---|---|---|---|---|---|
|`cf620cd1074e…`|4 行 12–20 → [83,104)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`cf620cd1074e…`|4 行 12–20 → [83,104)|Qstar|negative|quiet|—|external_body_missing|no_alert|TN|partial|
|`a888b74f1451…`|6 行 12–18 → [152,159)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`a888b74f1451…`|6 行 12–18 → [152,159)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`93b7f5b7e9f6…`|5 行 12–20 → [129,150)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`93b7f5b7e9f6…`|5 行 12–20 → [129,150)|Qstar|negative|quiet|—|external_body_missing|no_alert|TN|partial|
|`30b6b82bd06f…`|4 行 12–20 → [83,104)|Q0|positive|quiet|—|—|no_alert|FN|pass|
|`30b6b82bd06f…`|4 行 12–20 → [83,104)|Qstar|positive|report|—|external_body_missing|no_alert|FN|partial|
|`bdd5c1325a9e…`|5 行 12–18 → [129,136)|Q0|positive|report|—|—|alert|TP|pass|
|`bdd5c1325a9e…`|5 行 12–18 → [129,136)|Qstar|positive|report|—|—|alert|TP|pass|
|`bf6e7db133b0…`|5 行 12–18 → [106,113)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`bf6e7db133b0…`|5 行 12–18 → [106,113)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`66b8fda465c6…`|4 行 12–18 → [83,90)|Q0|positive|report|—|—|alert|TP|pass|
|`66b8fda465c6…`|4 行 12–18 → [83,90)|Qstar|positive|report|—|—|alert|TP|pass|

[完整目标引用](release/gap/archive/c1.json) · [对齐](release/gap/archive/c4.json) · [五列原始结果](release/gap/archive/c5.json) · [预算](release/gap/archive/budget.json)

## NPD 旧规约适用域未覆盖

|快照摘要|BQRS 行、首末列 → 目标字节区间|版本|证据标签|规约预测|实现默认|后端缺口|实际输出|计分|去向|
|---|---|---|---|---|---|---|---|---|---|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Q0|positive|report|—|—|alert|TP|pass|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Qstar|positive|report|—|—|alert|TP|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`a241fecc940f…`|4 行 12–24 → [111,127)|Q0|negative|uncovered|no_alert|—|no_alert|TN|pass|
|`a241fecc940f…`|4 行 12–24 → [111,127)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Q0|positive|report|—|—|alert|TP|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Qstar|positive|report|—|—|alert|TP|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Q0|positive|uncovered|no_alert|—|no_alert|FN|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Qstar|positive|report|—|—|alert|TP|pass|

[完整目标引用](release/uncovered/archive/c1.json) · [对齐](release/uncovered/archive/c4.json) · [五列原始结果](release/uncovered/archive/c5.json) · [预算](release/uncovered/archive/budget.json)

## C5 退回 B4 的故障注入

|快照摘要|BQRS 行、首末列 → 目标字节区间|版本|证据标签|规约预测|实现默认|后端缺口|实际输出|计分|去向|
|---|---|---|---|---|---|---|---|---|---|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Q0|positive|report|—|—|alert|TP|pass|
|`28b239cc9a6b…`|3 行 12–24 → [88,104)|Qstar|positive|report|—|—|alert|TP|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`a86ca48c1d62…`|4 行 12–24 → [110,126)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Q0|negative|quiet|—|—|no_alert|TN|pass|
|`adfcf4f0dd08…`|5 行 12–24 → [156,172)|Qstar|negative|quiet|—|—|no_alert|TN|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Q0|positive|report|—|—|alert|TP|pass|
|`60989fe114e2…`|4 行 12–24 → [134,150)|Qstar|positive|report|—|—|alert|TP|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Q0|positive|quiet|—|—|no_alert|FN|pass|
|`fc52d014da33…`|4 行 12–24 → [109,125)|Qstar|positive|quiet|—|—|no_alert|FN|B4|

[完整目标引用](b4-fault/archive/c1.json) · [对齐](b4-fault/archive/c4.json) · [五列原始结果](b4-fault/archive/c5.json) · [预算](b4-fault/archive/budget.json)

