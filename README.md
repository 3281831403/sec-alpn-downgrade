攻击者在中间把协议协商结果改成了旧版本，客户端毫不知情地用了弱配置继续通信：协商结果必须与客户端声明的偏好列表匹配；服务端不得选择未声明的协议；降级必须被显式检测并拒绝；协议版本与协商结果必须互相一致；协商结果为空时必须失败而不是回退默认；批量判定各连接独立。不变量：同一输入两次协商结果相同；协商结果永远在客户端声明集合内。

接口
----

parse_protocols 接受字符串或序列，按逗号拆分，去除两端空白和空项，保持原有顺序与大小写。

preferred 按客户端给出的顺序返回第一个与服务端列表共同拥有的协议，返回客户端使用的写法。协议名比较不区分大小写。

declared 判断协议是否在客户端声明集合内，比较不区分大小写。

detect_downgrade 根据策略中的最低版本判断所选协议是否构成降级。缺少降级规则时按不安全处理。

check_consistency 判断协议与版本号是否一致。h2 对应 2，h3 对应 3，http/1.1 对应 1.1。

negotiate 返回一个映射。成功时 ok 为真，并包含 protocol 与 version；失败时 ok 为假，并包含 error。不会在无共同协议或空输入时选择默认协议。

validate_policy 返回问题代码列表。合法策略必须声明 minimum_version，必须显式把 reject_downgrade 设为真，且不得允许空结果。

alpn_batch 对每个连接独立调用 negotiate，返回以连接 id 或序号为键的映射。

策略字段
--------

minimum_version：数字或数字字符串，表示允许的最低协议版本。

reject_downgrade：必须为真。缺失或为假都不构成可接受的降级规则。

allow_empty：缺失或为假；为真时策略不合法。

错误代码
--------

invalid_policy
missing_minimum_version
invalid_minimum_version
missing_downgrade_rule
downgrade_must_be_rejected
empty_result_allowed
empty_negotiation
no_common_protocol
undeclared_protocol
version_mismatch
downgrade_detected

版本约定
--------

h2 对应版本 2，h3 对应版本 3，http/1.1 对应版本 1.1。未知协议视为不一致，并在协商中失败。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

