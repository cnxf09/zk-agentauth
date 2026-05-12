# 安全目标测试

本文说明如何用 `scripts/security_goals_cli.sh` 对方案的 6 个安全目标做工程级测试。这些测试不是形式化安全证明，而是覆盖当前实现中最关键的攻击路径，适合本地验证、演示视频和 PR 回归检查。

执行命令：

```bash
scripts/security_goals_cli.sh
```

预期输出为 CSV 风格：

```text
result,goal,test
PASS,baseline,valid_agent_presentation_generated
PASS,baseline,valid_agent_presentation_accepted
PASS,unforgeability,tampered_delegation_signature_cannot_present
PASS,unforgeability,wrong_agent_secret_cannot_present
PASS,delegation_transparency,verifier_reports_authorized_agent_checks
PASS,policy_constraint,agent_cannot_present_unallowed_claim
PASS,revocability,revoked_delegation_cannot_present
PASS,credential_binding,delegation_cannot_move_to_another_credential
PASS,delegator_anonymity,presentation_omits_hidden_witness_material
```

## 覆盖目标

| 安全目标 | 测试方式 | 预期 |
|---|---|---|
| 不可伪造性 | 篡改委托签名、替换 Agent 私钥 | 无法生成被接受的 presentation |
| 委托透明 | 检查 verifier 输出中的委托签名、策略、撤销状态结果 | Verifier 能确认是合法授权的 Agent 在操作 |
| 委托人匿名 / 不可关联 | 扫描 presentation，确认不包含设备公钥和签名明文等 witness/debug 材料 | presentation 不直接暴露稳定设备标识 |
| 策略约束 | Verifier 请求 Alice 未授权的 claim | Agent 无法生成有效 presentation |
| 可撤销性 | Alice 生成 `revoked=true` 的委托状态 | Agent 无法继续出示 |
| 凭证绑定性 | 将凭证 A 的委托材料挪到凭证 B | 跨凭证挪用失败 |

## 1. 不可伪造性

目标：

```text
没有合法委托链就不能产生被接受的证明。
```

测试项：

- `tampered_delegation_signature_cannot_present`
- `wrong_agent_secret_cannot_present`

测试方式：

- 在合法 delegation 中篡改 `delegation_sig.txt`。
- 在合法 delegation 中篡改 `agent_sk.txt`，模拟非被授权 Agent 尝试操作。

预期：

```text
Agent present 失败，无法生成可验证 presentation。
```

## 2. 委托透明

目标：

```text
验证者能确认“这是一个被合法授权的 Agent 在操作”。
```

测试项：

- `verifier_reports_authorized_agent_checks`

测试方式：

对合法 presentation 执行 verifier，并检查输出是否包含：

```text
Delegation sig: PASS
Policy claims: PASS
Delegation revocation: PASS
Overall: ACCEPT
```

说明：Verifier 不只是看到一个普通 mDoc ZK proof，还能看到该 proof 绑定了委托签名、策略和撤销状态。

## 3. 委托人匿名 / 不可关联

目标：

```text
验证者无法得知委托人身份，无法关联不同会话。
```

测试项：

- `presentation_omits_hidden_witness_material`

测试方式：

使用同一 Alice 凭证生成两次不同 delegation 和 presentation，然后扫描 presentation 目录，确认其中不包含这些稳定或敏感材料：

```text
device_pkx
device_pky
delegation_sig
agent_sig
delegation_msg
```

说明：

早期 demo 中 `delegation_token.json` 同时包含 Verifier 需要的公开输入和本地 witness/debug 材料。当前实现已改为发送 `public_delegation.json`，只包含 Verifier 需要的公开委托输入；设备公钥、委托签名、Agent 签名和 delegation message 不随 proof 发给 Verifier。

边界：

这项测试证明当前打包层不再直接暴露稳定设备公钥。它不是完整的形式化匿名性证明；如果后续新增公开字段，还需要继续检查是否引入新的稳定标识。

## 4. 策略约束

目标：

```text
Agent 只能在授权策略范围内产生有效证明。
```

测试项：

- `agent_cannot_present_unallowed_claim`

测试方式：

Alice 只授权：

```text
age_over_18
height
```

但 Verifier 请求：

```text
family_name
```

预期：

```text
Agent present 失败。
```

## 5. 可撤销性

目标：

```text
委托人可随时终止 Agent 的授权。
```

测试项：

- `revoked_delegation_cannot_present`

测试方式：

Alice 生成 delegation 时写出：

```text
revoked = true
```

预期：

```text
Agent present 失败。
```

说明：当前实现验证的是“委托授权撤销”，即 Alice 撤销她对 Agent 的授权，不是 Issuer 撤销 Alice 的 mDoc 凭证。

## 6. 凭证绑定性

目标：

```text
一个委托必须且只能绑定到签署它的那份凭证，不可跨凭证挪用。
```

测试项：

- `delegation_cannot_move_to_another_credential`

测试方式：

先用凭证 A 生成合法 delegation，然后把 delegation 目录里的 holder 材料替换为凭证 B：

```text
device_response.cbor
device_sk.txt
device_pkx.txt
device_pky.txt
```

预期：

```text
Agent present 失败。
```

## 隐私增强方向

当前版本已经将公开输入与 witness/debug 材料拆分，presentation 不再发送设备公钥、委托签名、Agent 签名和 delegation message。

后续如果进一步追求最小披露，可以继续：

- 将 policy 明文进一步压缩为必要公开值，例如 claim hash、策略过期时间和 agent id hash。
- 检查 Web feed、日志和错误信息，避免引入新的稳定标识。
- 对同一 Alice 多次 presentation 的公开字段做更系统的可关联性分析。
