# iam-policy-engine-go

一套**本地可运行**的授权判定引擎：用本地策略文档与请求上下文，模拟云平台
（风格类似 IAM Policy）在多策略来源叠加时的访问决策。目标是：

- 结论**确定**：策略顺序不同、语句重复，结论与解释完全一致；
- 失败**可解释**：每种拒绝都有机器可区分的 `ReasonCode`，并附命中规则；
- 默认安全：**默认拒绝**、显式拒绝不可覆盖、条件判定 fail-closed；
- 叠加层只能**收紧**不能放宽。

## 目录结构

```
pkg/policies/        策略领域模型
  types.go           Effect / Statement / Policy / Credentials / 条件值类型
  parse.go           JSON 策略文档解析与规范化（含 NotAction/NotResource、条件树）
  match.go           动作/资源的通配匹配（* 与 ?）
  condition.go       条件运算符语义、多值量词与可区分失败原因
  ip.go              IP/CIDR（IPv4 与 IPv6）包含关系判定
  statement.go       单条语句对请求的匹配（含排除形式）
pkg/engine/
  engine.go          判定流水线：凭证 -> 显式拒绝 -> 身份允许 -> 边界 -> 会话
  batch.go           批量判定：保序、并发、与单条判定结果一致
cmd/iamctl/          本地命令行验证入口
examples/            示例策略与请求
```

## 判定模型与优先级

引擎对每个请求自上而下依次检查，**第一条命中即定论**：

| 顺序 | 检查 | 结论 (`ReasonCode`) |
|---|---|---|
| 1 | 请求非法（action/resource 为空） | `invalid_request` |
| 2 | 凭证缺失 / 已过期 / 尚未生效 | `credentials_missing` / `credentials_expired` / `credentials_not_yet_valid` |
| 3 | **任意层**存在与请求匹配的 `Deny` | `explicit_deny` |
| 4 | 身份策略没有任何 `Allow` 命中：其中动作/资源在范围内但条件失败 | `condition_failed` |
| 4b | 身份策略没有任何 `Allow` 命中（其余情况） | `default_deny_no_matching_allow` |
| 5 | 权限边界存在但未 `Allow` 该请求（条件失败时同样为 `condition_failed`） | `permission_boundary_denied` |
| 6 | 会话策略存在但未 `Allow` 该请求（条件失败时同样为 `condition_failed`） | `session_policy_denied` |
| 7 | 以上均未命中 | `allowed` |

要点：

- **显式拒绝一旦命中，不得被任何允许覆盖**。检查顺序对身份、边界、会话三层
  完整扫描后再决定，因此 `Allow *` + `Deny s3:DeleteBucket` 永远拒绝删除。
- **无匹配默认拒绝**：身份层没有允许即拒绝；边界/会话策略单独存在不能授予
  任何权限（它们不是权限来源，只是收紧器）。
- **边界与会话只能收紧**：最终有效权限是
  `身份允许 ∩ 边界允许 ∩ 会话允许`，再减去任意层的显式拒绝。边界/会话层缺省
  （未提供）时表示"不额外限制"，不会被误判为拒绝。

## 策略来源

| 来源 | 作用 |
|---|---|
| `identity`（身份策略） | 基线权限来源；没有它的 Allow 即默认拒绝 |
| `boundary`（权限边界） | 可选收紧器；其 Allow 与身份 Allow 取交集 |
| `session`（会话策略） | 可选收紧器（如角色扮演时的会话标签/限制）；同样取交集，可显式拒绝 |

策略文档形如：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "read",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::bucket/*"],
      "Condition": { "StringEquals": { "env": ["prod"] } }
    }
  ]
}
```

`Statement` 可以是单个对象或数组；`Action`/`Resource` 可以是字符串或字符串数组。

## 匹配语义

### 动作与资源（通配、前缀、排除）

- `*` 匹配任意长度字符序列（可为空），`?` 匹配恰好一个字符；其余字符按
  字面量、区分大小写匹配。
- 通配可以跨 `/` 等分隔符（`a*b` 能匹配 `a/x/b`），因此编写排除规则时需要
  显式写出完整前缀（如 `arn:aws:s3:::secret/*`），不会自动按"段"理解。
- **排除形式** `NotAction` / `NotResource`：请求与所列模式**都不匹配**时才算
  命中该语句。即被排除模式实际覆盖的请求，绝不会从排除规则中漏过而被判允许。
  `Action` 与 `NotAction`（`Resource` 同理）必须且只能出现其一，解析期强制校验。

### 条件判定

条件结构为 `{ "运算符": { "键": [期望值...] } }`：

- 支持运算符：
  - 字符串：`StringEquals`、`StringNotEquals`、`StringEqualsIgnoreCase`、
    `StringLike`（右侧为通配模式）、`StringNotLike`
  - 数字：`NumericEquals` / `NotEquals` / `LessThan` / `LessThanEquals` /
    `GreaterThan` / `GreaterThanEquals`
  - 布尔：`Bool`
  - 时间：`DateEquals`、`DateBefore`、`DateAfter`（RFC3339 / `2006-01-02`）
  - 网络位置：`IpAddress` / `NotIpAddress`（见下文「IP 与 ARN 条件」）
  - 资源标识：`ArnLike` / `ArnNotLike`（按通配模式匹配 ARN）
  - 任意运算符可加 `IfExists` 后缀（如 `StringEqualsIfExists`）：键缺失时
    该条件视为成立而非失败。

#### 多值上下文与量词

上下文键可以携带一组值（`policies.ListV(...)`，或请求 JSON 中写数组）。运算符
名可显式加量词前缀声明归约方式：

- `ForAnyValue:`（如 `ForAnyValue:StringEquals`）：**至少一个**实际值与某个
  期望值比较成立，条件即成立；
- `ForAllValues:`（如 `ForAllValues:StringEquals`）：**每一个**实际值都要与
  某个期望值比较成立（不同值可命中期望值列表的不同成员）；
- **不写前缀时默认 `ForAnyValue`**。该默认行为与值的个数、顺序无关；单值键的
  结论与历史版本完全一致（既有策略无需修改）。

量词可与 `IfExists` 后缀组合（如 `ForAllValues:StringEqualsIfExists`）。

**取反运算符的整组集合语义**：`StringNotEquals`、`StringNotLike`、
`NumericNotEquals`、`NotIpAddress`、`ArnNotLike` 这类带取反意味的运算符，比较
的是**整组实际取值与排除集合**的关系——无论是否显式声明量词，只要实际取值中
有**任何一个**落在排除集合内，该条件就不成立；其它取值不在集合内也不能放行。
全部实际值都在排除集合之外时条件才成立。单值场景下结论与历史版本一致。

**边界情形的稳定结论**（均可通过 `ConditionReason` 区分）：

| 情形 | 结论 |
|---|---|
| 键缺失（无 `IfExists`） | 失败，`condition_key_missing`（取反运算符同样失败，fail-closed） |
| 键存在但值为空列表 + 正向运算符 | 失败，`condition_empty_value_set` |
| 键存在但值为空列表 + 取反运算符 | 成立（没有任何值落入排除集合，vacuously true） |
| 实际值/期望值对运算符域非法（如写错的 IP/网段） | 失败，`condition_invalid_value` |

#### IP 与 ARN 条件

- `IpAddress` / `NotIpAddress`：实际值为字面 IP（IPv4 或 IPv6），期望值可以是
  单个地址或 CIDR 网段（如 `10.0.0.0/8`、`2001:db8::/32`）；裸地址按主机前缀
  （`/32` / `/128`）处理。网段包含关系按前缀位严格计算，**网络地址与广播地址
  等边界地址属于网段内**，紧邻网段外的地址不会误判。带 zone 的 IPv6 地址
  （`fe80::1%eth0`）视为非法。写错的地址或网段（如 `10.0.0.0/33`、
  `999.1.2.3`）一律以 `condition_invalid_value` 失败，**不会**被悄悄当成
  不匹配或放行。
- `ArnLike` / `ArnNotLike`：按通配模式（`*` / `?`，与动作/资源匹配同一套
  语义）比较 ARN 字符串。
- 两类运算符都遵循上面的多值量词规则；取反形式遵循整组集合语义。

- **确定的失败规则（全部 fail-closed，导致语句不匹配、绝不允许）**，并以
  可区分的原因记录在 `Result.Conditions` 中：

| 情况 | `ConditionReason` |
|---|---|
| 上下文缺少该键（无 IfExists） | `condition_key_missing` |
| 实际值或期望值类型与运算符不符 | `condition_type_mismatch` |
| 运算符名称未知 | `condition_unknown_operator` |
| 键存在、类型正确但比较不成立 | `condition_did_not_match` |
| 键对应空值列表（正向运算符） | `condition_empty_value_set` |
| 值对运算符域非法（如非法 IP/CIDR） | `condition_invalid_value` |

- 解析期类型推断：JSON `true/false` → Bool，数字 → Number，可解析的时间字符串
  → Time，其余字符串 → String。因此数字比较请在 JSON 中写数字 `10` 而非 `"10"`。

### 凭证时效

请求携带 `Credentials`：

- `Creds == nil`：`credentials_missing`，拒绝；
- 当前时间晚于 `ExpiresAt`：`credentials_expired`，拒绝；
- 当前时间早于 `IssuedAt`：`credentials_not_yet_valid`，拒绝；
- 两者为零值表示不施加对应约束。`Request.Now`（或 `WithClock`）可固定时钟，
  使时效判定可复现。

## 确定性保证

- 引擎会扫描全部层的全部语句，**不依赖文档内顺序**决定 Allow/Deny 优先级；
- 命中规则与条件输出按规范化键**去重并排序**：重复语句只出现一次，交换策略
  顺序产生字节级一致的 `Result`（见 `TestOrderAndDuplicateDeterminism`）；
- 条件子句按运算符名、键名排序遍历，不受 Go map 迭代序影响。

## 批量与并发判定

`Engine.EvaluateBatch(reqs []Request) []Result` 面向巡检等批量场景：

- **保序**：`results[i]` 对应 `reqs[i]`，与提交顺序一致；
- **与单条判定一致**：每条结果与单独调用 `Evaluate` 完全相同（测试中用
  `reflect.DeepEqual` 逐条比对）；
- **并发安全**：`Engine` 构造后不可变，判定过程不持有任何共享可变状态（每条
  请求的命中/条件累积器相互独立），可安全地在多个 goroutine 间共享同一个
  引擎并混用 `Evaluate` / `EvaluateBatch`；批量内部以不超过 `GOMAXPROCS` 的
  有界 worker 池并行执行，规模增大时吞吐随核数扩展，且前一条请求的上下文
  绝不会影响后一条的结论；
- 空批次返回 `nil`。

## 兼容范围

本次扩展对既有行为的承诺：

- 单值上下文键在既有运算符下的结论**完全不变**（默认量词即历史行为）；
- 取反运算符在「单实际值 + 单期望值」下结论不变；「单实际值 + 多期望值」时
  旧行为是「与任一期望值不等即成立」，现按整组集合语义修正为「不等于所有
  期望值才成立」（即实际值落在排除集合内即不成立）——这是对旧行为中
  与排除语义相悖情形的修正，请检查依赖旧行为的策略；
- 新增运算符（`IpAddress` 等）此前会被判为 `condition_unknown_operator` 并
  fail-closed 拒绝，现在按真实语义判定；策略文档无需任何修改即可继续使用。

## 验证方法

运行全部单元测试（含竞态检测）：

```sh
go test ./... -race -count=1 -v
```

测试覆盖：显式拒绝覆盖 `Allow *`、默认拒绝、通配与 `Not*` 排除边界、条件缺失/
类型不匹配/未知运算符、权限边界收紧、会话策略收紧、凭证缺失/过期/未生效、
顺序与重复的幂等性，以及本次新增的：**多值量词**（`ForAllValues:` /
`ForAnyValue:` / 默认行为、取反整组集合语义、空集合与缺键边界）、**IP/ARN
条件**（IPv4/IPv6 网段边界、非法地址与网段、取反形式）、**批量与并发判定**
（保序、与单条判定逐条一致、`-race` 下并发混用不漂移、请求间上下文不串扰）。
每个用例都会在测试日志中打印**请求上下文、命中规则、条件判定与最终结论**
（使用 `-v` 查看）。

命令行端到端验证（Allow 退出码 0，Deny 退出码 1）：

```sh
go run ./cmd/iamctl \
  -identity examples/identity.json \
  -boundary examples/boundary.json \
  -request examples/request.json
```

请求 JSON 字段：`principal` / `action` / `resource` / `context`（任意 JSON 标量
或数组）/ `expiresAt` / `issuedAt` / `now`（RFC3339，用于复现凭证时效）。
