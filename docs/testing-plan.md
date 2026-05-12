# 性能测试与基础安全测试

本文说明仓库内置的 CLI 性能测试与基础安全负例测试。CLI 链路不包含浏览器、Flask 服务和网络抖动，结果更稳定、可重复；Web 端测试可在此基础上补充端到端系统延迟。

## 性能测试指标

使用 `scripts/perf_cli.sh` 采集以下指标：

- `issue`：Issuer 颁发 mDoc 凭证耗时。
- `delegate`：Alice 生成委托签名和委托撤销状态耗时。
- `request`：Verifier 生成 reader request 与打包 delegated circuit 耗时。
- `present`：Agent 生成 ZK proof 耗时，这是主要的 Prover 成本。
- `verify`：Verifier 验证 ZK proof、策略和撤销状态耗时。
- `proof_bytes`：最终 Ligero proof 文件大小。
- `presentation_bytes`：完整 presentation 目录大小。

执行示例：

```bash
RUNS=5 scripts/perf_cli.sh | tee /tmp/zkaa_perf.csv
```

上面的命令是完整端到端测试，每一轮都会重新执行：

```text
issue -> delegate -> request -> present -> verify
```

其中 `request` 会重新生成并压缩 delegated circuit，通常是最耗时的阶段。如果只是想重复测 Prover/Verifier 成本，可以复用同一套 setup：

```bash
REUSE_SETUP=1 RUNS=5 scripts/perf_cli.sh | tee /tmp/zkaa_perf_reuse.csv
```

`REUSE_SETUP=1` 时只会先执行一次：

```text
issue -> delegate -> request
```

然后重复执行 5 次：

```text
present -> verify
```

这样更适合快速观察 proof 生成时间、验证时间和 proof 大小；但它不代表完整端到端延迟，因为 request/circuit 生成成本只被计算了一次。

记录性能数据时，建议至少覆盖这些场景：

- 单个 claim：`age_over_18`。
- 两个谓词组合：`age_over_18:EQ:true` 和 `height:GE:170`。
- 冷启动测试：删除 `/tmp/zkaa_perf_cli` 后重新执行。
- 热启动测试：复用已经编译好的二进制文件执行。

## 安全性测试

使用 `scripts/security_cli.sh` 检查高价值负例：

- 合法 baseline proof 应被接受。
- 已撤销委托应被拒绝。
- 已过期策略应被拒绝。
- 不满足谓词的请求应被拒绝。
- 篡改 `proof.bin` 应被拒绝。
- 篡改 policy 公共输入应被拒绝。
- 篡改委托撤销公开状态应被拒绝。

执行示例：

```bash
scripts/security_cli.sh
```

预期输出类似 CSV：

```text
result,test
PASS,baseline_present
PASS,baseline_verify
PASS,revoked_delegation_rejected
PASS,expired_policy_rejected
PASS,unsatisfied_predicate_rejected
PASS,tampered_proof_rejected
PASS,tampered_policy_rejected
PASS,tampered_revocation_status_rejected
```

## Web 端扩展测试

CLI 测试稳定后，再围绕 `web/` 增加 HTTP 级测试：

- 测量钱包侧从 `/api/agent/dispatch` 到任务状态 `done` 的总耗时。
- 测量 TripGo 在 `/api/agent/order` 内部调用 verifier 的耗时。
- 用旧 presentation 搭配新的 reader request 重放，等 nonce/session 绑定完善后应被拒绝。
- 在提交给 TripGo 前篡改 multipart 输入，确认最终 `Overall` 不会被接受。

当前 README 已说明：演示环境使用明文 HTTP，`X-Request-Id` 还没有签名保护。因此重放测试和传输安全测试属于生产化加固项，不视为当前本地 demo 的失败。
