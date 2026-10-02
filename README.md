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
  operators.go       全部运算符规格（字符串/数字/布尔/时间/IP/ARN）
  ip.go              IPv4/IPv6 网段解析与包含判定（含边界地址）
  arn.go             ARN 通配匹配
  statement.go       单条语句对请求的匹配（含排除形式）
pkg/engine/
  engine.go          判定流水线：凭证 -> 显式拒绝 -> 身份允许 -> 边界 -> 会话
  batch.go           批量判定（保序、有界并发、与单条判定一致）
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

- 上下文值与期望值都可以是**多值列表**（双侧会先展平再比较）；
- 多值组合方式由**量词前缀**显式声明，缺省时也有与值个数/顺序无关的固定行为；
- 支持运算符：
  - 字符串：`StringEquals`、`StringNotEquals`、`StringEqualsIgnoreCase`、
    `StringLike`（右侧为通配模式）、`StringNotLike`
  - 数字：`NumericEquals` / `NotEquals` / `LessThan` / `LessThanEquals` /
    `GreaterThan` / `GreaterThanEquals`
  - 布尔：`Bool`
  - 时间：`DateEquals`、`DateBefore`、`DateAfter`（RFC3339 / `2006-01-02`）
  - 网络位置：`IpAddress`、`NotIpAddress`
  - 资源标识：`ArnLike` / `ArnEquals`、`ArnNotLike` / `ArnNotEquals`
  - 任意运算符可加 `IfExists` 后缀（如 `StringEqualsIfExists`）：键缺失时
    该条件视为成立而非失败。

#### 多值量词与取反的整组语义

对每个实际取值（actual）判定它是否命中任一期望值（expected），记为 m(g)：

| 写法 | 正向运算符（Equals/Like/IpAddress/ArnLike…） | 取反运算符（Not*） |
|---|---|---|
| 无前缀（默认，行为固定） | **存在**一个 actual 命中 expected | **所有** actual 都不命中 expected（两集合**完全不相交**） |
| `ForAllValues:` 前缀 | **所有** actual 都命中某个 expected | 同默认：actual 与排除集合完全不相交 |
| `ForAnyValue:` 前缀 | **至少一个** actual 命中 expected | **至少一个** actual 落在排除集合**之外** |

要点：

- 默认行为**不随取值个数或顺序变化**；单值场景的结论与旧版本完全一致。
- **取反条件比较的是整组实际取值与排除集合的关系**：只要有一个实际取值落入
  排除集合，整条条件即不成立，不能因为其他取值在集合外而放行
  （例如 `NotIpAddress` 下 `["10.1.2.3","192.0.2.1"]` 对 `10.0.0.0/8` 必失败）。
- 边界情况稳定且可区分：键不存在为 `condition_key_missing`；键存在但解析为
  **空值组**（空列表）为 `condition_empty_value_set`；`IfExists` 仅豁免前者。
- 非法字面量不会被悄悄当成“不匹配”：非法 IP / CIDR / ARN 一律记为
  `condition_invalid_value` 并附带指出问题字面量的说明。

#### 网络位置条件（IpAddress / NotIpAddress）

- 期望值支持单个地址（`10.1.2.3`、`2001:db8::1`，等价于 `/32`、`/128`）与
  带前缀的网段（`10.1.2.0/24`、`2001:db8::/32`），实际值为 IP 字面量。
- 网段包含判定为闭区间：**网络地址与定向广播地址都算在网段内**；恰好卡在
  边界两侧的地址不会误判（如 `10.1.2.0/24` 包含 `10.1.2.0` 与 `10.1.2.255`，
  但不包含 `10.1.1.255` 与 `10.1.3.0`）。
- IPv4 与 IPv6 族系不互通；IPv4 映射的 IPv6 地址（`::ffff:10.1.2.5`）按 IPv4
  参与匹配。
- 写错的实际地址与写错的期望网段都以 `condition_invalid_value` 失败，且
  `Detail` 能区分是“实际地址非法”还是“期望网段非法”。
- `NotIpAddress` 遵循上表的整组集合语义，也可叠加量词与 `IfExists`。

#### 资源标识条件（ArnLike / ArnNotLike）

- 按动作/资源同款通配规则整串匹配：`*` 任意序列、`?` 单字符、其余字面量、
  区分大小写，如 `arn:aws:s3:::bucket/*`。
- `ArnEquals` 是 `ArnLike` 的别名，`ArnNotEquals` 是 `ArnNotLike` 的别名。
- `ArnNotLike` 与其他取反运算符一样按整组集合判定；空 ARN 属非法值。

- **确定的失败规则（全部 fail-closed，导致语句不匹配、绝不允许）**，并以
  可区分的原因记录在 `Result.Conditions` 中：

| 情况 | `ConditionReason` |
|---|---|
| 上下文缺少该键（无 IfExists） | `condition_key_missing` |
| 键存在但为空值组，或策略未给期望值 | `condition_empty_value_set` |
| 实际值或期望值类型与运算符不符 | `condition_type_mismatch` |
| IP / CIDR / ARN 字面量非法 | `condition_invalid_value` |
| 运算符名称未知 | `condition_unknown_operator` |
| 键存在、类型正确但比较不成立 | `condition_did_not_match` |

- 解析期类型推断：JSON `true/false` → Bool，数字 → Number，可解析的时间字符串
  → Time，其余字符串 → String。因此数字比较请在 JSON 中写数字 `10` 而非 `"10"`；
  IP/ARN 条件值写成字符串。

### 凭证时效

请求携带 `Credentials`：

- `Creds == nil`：`credentials_missing`，拒绝；
- 当前时间晚于 `ExpiresAt`：`credentials_expired`，拒绝；
- 当前时间早于 `IssuedAt`：`credentials_not_yet_valid`，拒绝；
- 两者为零值表示不施加对应约束。`Request.Now`（或 `WithClock`）可固定时钟，
  使时效判定可复现。

## 批量判定与并发使用

- `Engine.EvaluateBatch([]Request) []BatchResult`：一次提交成百上千条请求，
  返回结果**严格按提交顺序排列**（并附 `Index` 便于重排后回溯）。
- 每条批量结果与单独调用 `Evaluate` 的输出**逐字段一致**（决策、原因、命中、
  条件解释都相同）；请求之间完全隔离，前一条的上下文不会影响后一条。
- 同一 `*Engine` 可被任意多个 goroutine 并发共享：策略数据只读，每个请求的
  中间变量独立分配，结果写入各自预分配的槽位，无共享可变状态
  （以 `go test -race` 验证）。
- 批量内部用有界 worker 池（上限 `GOMAXPROCS`），批次很大时不会产生无界
  goroutine；性能见 `BenchmarkEvaluateBatch1000`。

## 确定性保证

- 引擎会扫描全部层的全部语句，**不依赖文档内顺序**决定 Allow/Deny 优先级；
- 命中规则与条件输出按规范化键**去重并排序**：重复语句只出现一次，交换策略
  顺序产生字节级一致的 `Result`（见 `TestOrderAndDuplicateDeterminism`）；
- 条件子句按运算符名、键名排序遍历，不受 Go map 迭代序影响；多值比较固定按
  “实际值 × 期望值”的展平顺序扫描，结构性错误（非法字面量、类型不符）不会
  因为另一个值恰好匹配而被短路吞掉。

## 与既有规则的兼容范围

- 单值条件、字符串/数字/布尔/时间运算符、`IfExists`、`NotAction/NotResource`、
  三层策略叠加、凭证时效等**既有行为保持不变**；原有用例全部保留并通过。
- 唯一的行为细化：取反运算符在**多值**上下文下，旧实现按“存在一对不等即
  成立”会错误放行，现按整组集合语义判为不成立；单值场景结论不变。
- 新失败原因 `condition_empty_value_set` / `condition_invalid_value` 只在新增
  边界场景（空值组、非法 IP/ARN）出现；`IpAddress`/`Arn*` 从“未知运算符”
  变为受支持运算符。

## 验证方法

运行全部单元测试（含竞态检测）：

```sh
go test ./... -race -count=1 -v
```

测试覆盖：显式拒绝覆盖 `Allow *`、默认拒绝、通配与 `Not*` 排除边界、条件缺失/
空值组/类型不匹配/非法值/未知运算符、多值量词真值表（默认、`ForAllValues:`、
`ForAnyValue:`，含取反整组语义与顺序稳定性）、IPv4/IPv6 网段边界与主机地址、
IP/ARN 条件的取反形式、权限边界收紧、会话策略收紧、凭证缺失/过期/未生效、
顺序与重复的幂等性、**批量判定保序且与单条一致、并发无数据竞争、上下文隔离**。
每个用例都会在测试日志中打印**请求上下文、命中规则、条件判定与最终结论**
（使用 `-v` 查看）。

批量性能基准：

```sh
go test ./pkg/engine/ -bench BenchmarkEvaluateBatch1000
```

命令行端到端验证（Allow 退出码 0，Deny 退出码 1）：

```sh
go run ./cmd/iamctl \
  -identity examples/identity.json \
  -boundary examples/boundary.json \
  -request examples/request.json
```

请求 JSON 字段：`principal` / `action` / `resource` / `context`（任意 JSON 标量
或数组）/ `expiresAt` / `issuedAt` / `now`（RFC3339，用于复现凭证时效）。
