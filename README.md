# IAM Policy Engine (Go)

一个**本地可运行**的授权判定引擎：用本地 JSON 策略文档与请求上下文，模拟云平台
（IAM 风格）的访问决策。目标是让不同策略来源、不同上下文组合下的判定结论
**确定、可解释、可复现**。

无任何第三方依赖，标准库实现。

## 快速开始

```bash
go run ./cmd/demo          # 运行内置的 5 个判定场景，打印上下文/命中规则/结论
go test ./... -v           # 运行全部单测（日志含请求上下文、命中规则与最终结论）
go vet ./...               # 静态检查
```

## 代码结构

| 路径 | 职责 |
| --- | --- |
| `pkg/policy/policy.go` | JSON 策略解析、结构校验、文档模型 |
| `pkg/policy/match.go` | Action/Resource 模式匹配（通配、前缀、Not 排除） |
| `pkg/policy/condition.go` | 条件运算符、类型检查、可区分的条件错误 |
| `pkg/policy/context.go` | 请求上下文与强类型条件键值 |
| `pkg/engine/engine.go` | 多来源合并、判定流水线、凭证时效 |
| `pkg/engine/decision.go` | 判定结论与拒绝原因枚举 |
| `pkg/engine/explain.go` | 确定性的判定说明（测试日志使用） |
| `cmd/demo` | 本地演示程序 |

## 判定模型与优先级

对一个请求 `(principal, action, resource, condition keys)`，引擎严格按以下
**固定顺序**判定，前一步拒绝就立即返回，后面的任何 Allow 都无法翻案：

1. **上下文完整性**：context 为 nil、Action 或 Resource 为空
   → `Deny / ContextMissing`。
2. **凭证时效**：临时凭证 `Now >= ExpiresAt`
   → `Deny / CredentialsExpired`。`Now` 缺省时取当前 UTC 时间。
3. **身份策略显式拒绝（Explicit Deny）**：任一身份策略的 Deny 语句命中
   → `Deny / ExplicitDeny`。**显式拒绝优先于一切 Allow。**
4. **身份策略允许（Allow）**：必须至少有一个 Allow 语句命中；
   没有任何语句适用 → `Deny / DefaultDeny.NoMatch`（**默认拒绝，不放行**）。
5. **权限边界（Permission Boundary）**：存在边界时，边界必须**独立地**给出
   Allow；边界内的 Deny → `PermissionBoundary.ExplicitDeny`，
   无 Allow → `PermissionBoundary.DefaultDeny`。边界只能收紧。
6. **会话策略（Session Policy）**：同理，会话策略必须独立 Allow；
   拒绝原因分别为 `SessionPolicy.ExplicitDeny` /
   `SessionPolicy.DefaultDeny`。会话策略只能收紧，**无法放宽**身份权限。

以上全部通过才是 `Allow`。每种拒绝都有**可区分的 `DenyReason`**：

| DenyReason | 触发条件 |
| --- | --- |
| `ExplicitDeny` | 身份策略 Deny 命中 |
| `DefaultDeny.NoMatch` | 身份层无任何 Allow 命中（默认拒绝） |
| `PermissionBoundary.ExplicitDeny` | 边界 Deny 命中 |
| `PermissionBoundary.DefaultDeny` | 边界内无 Allow |
| `SessionPolicy.ExplicitDeny` | 会话策略 Deny 命中 |
| `SessionPolicy.DefaultDeny` | 会话策略内无 Allow |
| `CredentialsExpired` | 凭证已过 `ExpiresAt` |
| `ContextMissing` | 上下文/动作/资源缺失 |
| `ConditionError` | 条件无法正常判定（见下，fail-closed） |

## 策略来源与合并

- **身份策略（identity）**：挂在身份（用户/角色）上的常规策略。
- **权限边界（boundary）**：身份权限的上限，独立判定，只收紧。
- **会话策略（session）**：角色扮演/临时会话时下发的策略，独立判定，只收紧。

语句命中规则（同一来源内，Deny 压过 Allow）：

- Action 与 Resource **同时**匹配（含 NotAction/NotResource 语义），且
  该语句上的**所有**条件都为 true，语句才生效；任一条件 false，
  该语句既不 Allow 也不 Deny。

### 确定性保证

- 文档在引擎内按 **ID 排序**后扫描；解析时条件按 `运算符 → 键` 排序。
- 同层重复（同 ID 且内容相同）的文档会被去重；同 ID 但内容不同会直接
  panic，阻止“顺序决定结果”的歧义配置进入系统。
- 因此：**策略传入顺序不同、规则重复，结论与命中规则集合完全一致**。

## 匹配语义

- 通配符 `*`：匹配任意（含空）字符序列；末尾 `*` 即前缀匹配；
  无 `*` 即精确匹配；`?` 等其它字符按字面量处理，不做特殊解释。
- **Action**：大小写不敏感（如 `S3:getobject` 等价于 `s3:GetObject`）。
- **Resource**：大小写敏感。
- `Action` / `NotAction`、`Resource` / `NotResource` **互斥**（解析期校验）。
- `NotAction` / `NotResource` 是排除集：只有**没有任何排除模式命中**时，
  语句才在该维度上适用。因此排除形式不会把被排除的请求误判为 Allow。

## 条件语义

支持的运算符：

| 家族 | 运算符 |
| --- | --- |
| 字符串 | `StringEquals` / `StringNotEquals` / `StringEqualsIgnoreCase` / `StringNotEqualsIgnoreCase` / `StringLike` / `StringNotLike` |
| 数值 | `NumericEquals` / `NumericNotEquals` / `NumericLessThan(Equals)` / `NumericGreaterThan(Equals)` |
| 布尔 | `Bool` |
| 时间 | `DateGreaterThan(Equals)` / `DateLessThan(Equals)`（epoch 秒） |
| 网络 | `IpAddress` / `NotIpAddress`（CIDR） |
| 存在性 | `Null` |

求值规则：

- 单值键：与条件值列表做 **ANY**（任一等值/比较成立即 true）；
  `Not*` 运算符为取反形式。
- 多值字符串键（`Value.Strs`）：每个键值都必须命中某个条件值（ALL）。
- **类型必须匹配**：数值/日期运算符要求 `Number`/`Date`，字符串族与
  IP 要求 `String`，`Bool` 要求 `Bool`。
- 所有异常一律 **fail-closed**（作为拒绝处理），且原因可区分：
  - `UnknownOperator`：运算符不被支持；
  - `MissingKey`：条件键在上下文中不存在（`Null` 是唯一例外，用于探测存在性）；
  - `TypeMismatch`：键的声明类型与运算符家族不符；
  - `InvalidValue`：比较值无法解析（坏数字 / CIDR / 布尔 / epoch）。

## 策略 JSON 示例

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadShared",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::shared/*",
      "Condition": { "IpAddress": { "aws:SourceIp": ["10.0.0.0/8"] } }
    },
    {
      "Sid": "NoSecrets",
      "Effect": "Deny",
      "NotAction": ["s3:Delete*"],
      "NotResource": ["arn:aws:s3:::secret/*"]
    }
  ]
}
```

`Statement`、`Action`、`Resource` 均可写单值或数组。

## 作为库使用

```go
doc, _ := policy.Parse([]byte(policyJSON))
doc.ID = "my-policy"
eng := engine.New(
    []*policy.Document{doc},          // identity
    nil,                              // permission boundary
    nil,                              // session policy
)
ev := eng.Evaluate(&policy.RequestContext{
    PrincipalARN: "arn:aws:iam::111111:user/alice",
    AccountID:    "111111",
    Action:       "s3:GetObject",
    Resource:     "arn:aws:s3:::shared/a",
    Keys: map[string]policy.Value{
        "aws:SourceIp": {Type: policy.TypeString, Str: "10.0.0.5"},
    },
}, &engine.Credentials{ExpiresAt: expiry})

fmt.Println(ev.Decision, ev.DenyReason)
fmt.Println(engine.Explain(ctx, ev))
```

## 验证方法

- `go test ./... -v`：单测日志对每个关键场景打印**请求上下文（含条件键）、
  命中规则（来源/策略/语句/效果）与最终结论及拒绝原因**。
- 覆盖场景：显式拒绝覆盖允许（含顺序翻转）、无匹配默认拒绝、通配/前缀/
  NotAction/NotResource 排除边界、条件类型不匹配 / 缺失键 / 未知运算符 /
  非法值、权限边界与会话策略收紧（且会话策略不能放宽）、凭证失效、
  上下文缺失，以及顺序/重复输入下的结论确定性。
