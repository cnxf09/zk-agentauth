# ZK-AgentAuth

基于零知识证明的 AI Agent 委托认证系统。Alice 把 mDoc 凭证里的部分声明授权给 AI Agent，Agent 携 P-256 委托签名 + Ligero v2 ZK 证明跨服务调用商家完成下单；商家可验证授权与属性正确性，但无法回溯 Alice 真实身份，也无法跨会话关联。

## 仓库结构

```
zk-agentauth/
├── README.md                ← 本文件
├── LICENSE                  ← Apache 2.0（来源 longfellow-zk）
├── lib/                     ← C++ 零知识证明库 + delegation_demo CLI
│   ├── CMakeLists.txt
│   ├── algebra/ arrays/ cbor/ circuits/ ec/ gf2k/ ligero/ merkle/
│   │   proto/ random/ sumcheck/ util/ zk/
│   ├── testing/             ← 测试脚手架
│   └── examples/
│       ├── mdoc_anoncred/   ← mDoc 颁发/持有/出示原型（被 delegation_demo 复用）
│       └── delegation_demo/ ← 本项目核心：issuer / alice / agent / verifier 四个 CLI
└── web/                     ← 双服务 Web 演示
    ├── README.md            ← 子项目使用说明
    ├── Makefile · start.sh · requirements.txt
    ├── wallet_server/       ← Flask :8002（Issuer + Alice + Agent + Client UI）
    ├── tripgo_server/       ← Flask :8003（验证方 / 商家 + Service UI）
    └── data/                ← 运行时数据（mDoc / 订单 / 任务工作目录）
```

## 上游来源 / 致谢

本项目的 C++ 零知识证明库（`lib/`）派生自 Google 开源的 [Longfellow ZK](https://github.com/google/longfellow-zk)（Apache 2.0）。我们在其 `examples/mdoc_anoncred/` 之上新增了 `examples/delegation_demo/`，把以下安全性要求整合进了 ZK 电路：

- **约束 7 · 委托签名**：在签名电路中验证 Alice 设备私钥 `sk_d` 对委托消息（`pk_agent ‖ allowed_claims ‖ expires ‖ policy_context_hash`）的 ECDSA 签名。
- **约束 8 · 策略披露**：在哈希电路中检查请求方索取的 claim 在 Alice 的 `policy.allowed_claims` 之内。
- **约束 9 · 策略未过期**：电路约束 `now < policy.expires`。
- **约束 10 · Agent 会话签名**：在签名电路中验证 Agent 临时密钥 `sk_agent` 对本次 session transcript / docType 摘要的 ECDSA 签名。
- **约束 11 · 委托未撤销**：电路约束委托撤销状态由 `sk_d` 签发、`revoked == false` 且未过期；这是「Alice 撤销她对 Agent 的委托」语义，不是 Issuer 撤销凭证。
- **通用谓词**：电路与应用层共同支持 `DISCLOSE / EQ / IN_SET / GE / LE`，按 AND 组合。

更多电路细节见 `lib/examples/delegation_demo/` 的源码与上游 Longfellow ZK 的 README。

## 快速跑通

### 通用前置 · 编译 C++ 二进制

```bash
# 系统依赖
brew install cmake openssl ninja      # macOS
# sudo apt install cmake libssl-dev libzstd-dev    # Debian/Ubuntu

# 编译（只需一次，约 1-2 分钟）
cd web && make build
# 等价：cd zk-agentauth && cmake -S lib -B build && cmake --build build --target delegation_demo_*
```

编译完成后 `build/examples/delegation_demo/` 下会得到四个 CLI：
`delegation_demo_issuer / delegation_demo_alice / delegation_demo_agent / delegation_demo_verifier`。

接下来有 **两种** 演示方式，可任选其一或两种都跑：

### 方式 A · Web 双服务演示（推荐，可视化）

```bash
m
make deps          # python3 -m venv .venv && pip install -r requirements.txt
make demo          # ./start.sh，自动打开浏览器
```

| 端口 | URL | 角色 |
|------|-----|------|
| 8002 | http://localhost:8002 | Alice 的钱包（Client UI） |
| 8003 | http://localhost:8003 | TripGo 商户站（Service UI） |

详细演示步骤、API 速查、篡改/撤销负向用例都在 [`web/README.md`](web/README.md)。

### 方式 B · 命令行演示（直接调四个 CLI）

整个流程是 5 步：Issuer 颁发 mDoc → Alice 签发委托 → 验证方挑战 → Agent 出示 → 验证方验证。**已在新 tree 上实测通过 6 项全 PASS**。

```bash
# 工作目录（每次重跑前 rm -rf）
WORK=/tmp/zkaa_cli
BIN=$(pwd)/build/examples/delegation_demo
rm -rf $WORK

# ① Issuer 颁发 mDoc 凭证（example 3 自带 4 个 claim：age_over_18 / family_name / birth_date / height=175）
$BIN/delegation_demo_issuer issue \
  --example 3 \
  --out $WORK/issue

# ② Alice 把 age_over_18 委托给 bookstore-agent，有效期到 2027 年
$BIN/delegation_demo_alice delegate \
  --holder $WORK/issue/holder \
  --claim age_over_18 \
  --expires 2027-01-01T00:00:00Z \
  --agent-id bookstore-agent \
  --out $WORK/delegation

# ③ 验证方颁发 reader request（指定它要看哪些 claim）
$BIN/delegation_demo_verifier request \
  --issuer-public $WORK/issue/issuer_public \
  --claim age_over_18 \
  --out $WORK/request

# ④ Agent 用委托 + 凭证生成 ZK 证明（约 5 秒，proof.bin 约 350 KB）
$BIN/delegation_demo_agent present \
  --delegation $WORK/delegation \
  --issuer-public $WORK/issue/issuer_public \
  --request $WORK/request \
  --out $WORK/presentation

# ⑤ 验证方验证
$BIN/delegation_demo_verifier verify \
  --issuer-public $WORK/issue/issuer_public \
  --request $WORK/request \
  --presentation $WORK/presentation
```

预期输出：

```text
ZK proof: PASS
Delegation sig: PASS
Policy claims: PASS
Policy predicates: PASS
Policy expiry: PASS
Delegation revocation: PASS
Overall: ACCEPT
```

#### 通用谓词（CLI 支持 `DISCLOSE / EQ / IN_SET / GE / LE`，按 AND 组合）

```bash
# 同时要求 age_over_18 == true 且 height >= 170
$BIN/delegation_demo_alice delegate \
  --holder $WORK/issue/holder \
  --predicate age_over_18:EQ:true \
  --predicate height:GE:170 \
  --expires 2027-01-01T00:00:00Z \
  --agent-id bookstore-agent \
  --out $WORK/delegation

$BIN/delegation_demo_verifier request \
  --issuer-public $WORK/issue/issuer_public \
  --predicate age_over_18:EQ:true \
  --predicate height:GE:170 \
  --out $WORK/request
# present / verify 同上
```

#### 负向测试

| 想验证什么 | 怎么做 | 预期 |
|---|---|---|
| 委托被撤销 | `delegate` 加 `--revoked` | `present failed: delegation revocation check failed: delegation is revoked` |
| 谓词不满足 | example 3 中 `height=175`，用 `--predicate height:GE:180` | `present failed: policy predicate check failed: height numeric predicate failed` |
| 委托过期 | `--expires 2024-01-01T00:00:00Z` | `Policy expiry: FAIL` |
| 篡改 ZK 证明 | 改 `$WORK/presentation/proof.bin` 任意一字节 | `ZK proof: FAIL` |

> 当前 demo 的 ZK 规格只支持 1 或 2 个 claim，所以 `--predicate` 最多组合两个。要支持更多条件，需要给电路加对应 `num_attributes` 的规格。

## 不再依赖的部分

整理后已从仓库移除（与本产品无关）：

- 上游 `examples/anoncred/` —— 原始论文 *Anonymous Credentials from ECDSA* 的实现（与 mdoc/delegation 流程独立）
- `circuits/tests/{anoncred,base64,jwt,ripemd,sha3,mdoc}` —— 实验性测试，未在生产 target 中
- `web_demo/` / `docs/` / `reference/` / `run/` —— 上游附带的网页 demo / 论文素材
- 所有 build 目录与 IDE 工程文件 —— 由 `make build` 重新生成

## 协议参考

- 整体设计：见同级 `proposal.pdf`（项目策划书）与 `main.tex`（会议论文初稿）
- 撤销透明性：见 `RevocationTransparency_cn.pdf`
- 上游电路文档：[Longfellow ZK README](https://github.com/google/longfellow-zk)

## License

Apache License 2.0（继承自 Longfellow ZK）。详见 [`LICENSE`](LICENSE)。
