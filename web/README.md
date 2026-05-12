# Web 端 · ZK-AgentAuth 双服务原型

Wallet（Alice 钱包，:8002）+ TripGo（验证方/商家，:8003）两个 Flask 服务，外加单文件 React Client UI 与 Service UI。

跨服务流程：Alice 把 mDoc 凭证的部分声明委托给 AI Agent，Agent 携 P-256 委托签名 + ~350 KB Ligero v2 ZK 证明跨服务调用 TripGo 完成下单；TripGo 验证后无法回溯 Alice 真实身份。

## 架构

```
┌──────────────────────────┐  HTTP / SSE   ┌──────────────────────────┐
│  Wallet Server :8002     │ ────────────► │  TripGo Server :8003     │
│  (Issuer + Alice + Agent)│               │  (Verifier)              │
│  · sk_I, sk_a, sk_d      │               │  · 仅 issuer_public/     │
│  · 自动颁发 mDoc          │               │  · 真人下单 / Agent 下单 │
│  · 派 Agent 完成跨服务调用 │               │  · 实时 Feed (SSE 广播)  │
└──────────────────────────┘               └──────────────────────────┘
       ▲                                           ▲
       │ 浏览器                                     │ 浏览器
       │ Client UI (Alice 的钱包)                   │ Service UI (TripGo 商户站)
```

服务边界严格隔离：浏览器中 Client UI 只与 :8002 通信，Service UI 只与 :8003 通信，跨服务流量只在两个 backend 之间。

## 快速启动

### 0 · 编译 C++ ZK 二进制

```bash
make build        # 等价 cmake -S ../lib -B ../build && cmake --build ../build --target delegation_demo_*
```

`make build` 默认用兄弟目录 `../lib` 作源码、把构建产物放到 `../build/`。要换位置可覆盖 `LIB_SRC=` 与 `BUILD=`。

### 1 · Python 依赖

```bash
make deps         # 等价 python3 -m venv .venv && pip install -r requirements.txt
```

### 2 · 一键启动

```bash
make demo         # 等价 ./start.sh
```

启动后：
- Wallet Server 自动检测并颁发 mDoc 凭证（首次约 1 秒）
- 浏览器自动打开两个标签页（macOS / Linux）

| 端口 | URL | 角色 |
|------|-----|------|
| 8002 | http://localhost:8002 | Alice 的钱包（Client UI） |
| 8003 | http://localhost:8003 | TripGo 商户站（Service UI） |

`Ctrl+C` 停止。`make clean` 清理运行时数据（mDoc / 任务 / 订单）。

## 演示流程

### A · 真人下单（旁路 ZK，作为对比）

1. http://localhost:8003 → 「真人入口」
2. 通过 reCAPTCHA 风格的人机验证
3. 浏览酒店 → 选房 → 填写姓名/手机 → 确认预订
4. TripGo 落单到 `data/tripgo/orders.json`，channel=`human`

### B · Agent 委托下单（核心：真 ZK 全链路）

1. http://localhost:8002 → 「Agent」→「购书助手」 → 输入「帮我订外滩璞丽酒店」 → 发送
2. 弹出 ProvingOverlay → 实时观察 5 阶段时间线 + Prover 实时日志：
   - ① delegating · 生成 P-256 委托签名 + delegation_revocation_status.json
   - ② fetching_request · 跨服务 POST :8003/api/agent/request 取挑战
   - ③ proving · 生成 Ligero v2 ZK 证明（~5 秒），proof.bin 实际尺寸（~350 KB）回填
   - ④ posting · multipart 投递 :8003/api/agent/order
   - ⑤ done · 校验全 PASS，订单入库
3. **同时** 切到 :8003 的 Live Monitor，看到刚才的 Agent 流量实时进入：JSON 解析、四步验证动画、订单卡片
4. 钱包侧得到一张 VERIFIED 印章 + 订单详情卡

### C · 修改委托权限（不触发购物）

1. AgentChat 头部点「修改权限」 → DelegationWizard
2. 4 步配完后点「签发委托」 → 只本地保存策略，**不会派单**
3. 顶部 chip 行多出新委托，可点击切换为下次派单生效的策略
4. 取消勾选某属性（如 `age_over_18`），再去对话框预订 18+ 酒店 → TripGo 端 Business Rule 检查 FAIL → 订单 REJECT

## 篡改演示（验证安全性）

```bash
# 替换 Wallet/Agent 本地委托签名字节，证明无效委托无法生成有效 proof
python3 -c "
from pathlib import Path
for f in Path('data/wallet/tasks').glob('*/delegation/delegation_sig.txt'):
    s = f.read_text()
    f.write_text(s[:5] + ('a' if s[5]!='a' else 'b') + s[6:])
    print('tampered:', f); break
"
# 对被篡改的 delegation 重新 present 会失败；presentation zip 不再发送 delegation_sig 明文。
```

## API 速查

### Wallet Server (8002)

| Method | Path | 说明 |
|--------|------|------|
| GET  | `/` | Client UI |
| GET  | `/api/wallet/status` | 凭证状态 + 持有 claims |
| POST | `/api/wallet/reissue` | 强制重发 mDoc |
| GET  | `/api/catalog` | 代理 :8003/api/catalog |
| POST | `/api/agent/dispatch` | 派 Agent，body: `{hotel_id, claims, expires, agent_id}` → `{task_id}` |
| GET  | `/api/agent/task/<id>/stream` | SSE：阶段进度（事件名为阶段名） |
| GET  | `/api/agent/task/<id>` | 任务最终态 |
| GET  | `/api/agent/history` | 最近任务列表 |

### TripGo Server (8003)

| Method | Path | 说明 |
|--------|------|------|
| GET  | `/` | Service UI |
| GET  | `/api/catalog` | 6 家酒店 |
| POST | `/api/order/human` | 真人下单（无 ZK） |
| POST | `/api/agent/request` | 内部：颁发 reader request（zip） |
| POST | `/api/agent/order` | 接收 Agent 投递 (multipart) → 调 verifier → SSE 广播 |
| GET  | `/api/agent/feed` | SSE：Live Monitor 流量推送 |
| GET  | `/api/agent/feed/history` | feed 历史（in-memory，重启清零） |
| GET  | `/api/orders/<id>` | 订单详情 |

## 目录布局

```
web/
├── README.md
├── Makefile · start.sh · requirements.txt
├── wallet_server/
│   ├── app.py             # Flask routes + bootstrap
│   ├── bins.py            # subprocess 包装四个 C++ 二进制
│   ├── agent_runner.py    # 五阶段任务 + SSE
│   └── static/index.html  # Client UI（单文件 React）
├── tripgo_server/
│   ├── app.py             # Flask routes
│   ├── verifier.py        # subprocess 包装 verifier
│   ├── feed.py            # SSE 广播通道
│   └── static/index.html  # Service UI（单文件 React）
└── data/
    ├── shared/issuer_public/   # 公钥目录（启动时自动写入）
    ├── wallet/
    │   ├── holder/             # mDoc + sk_d（启动时自动写入）
    │   └── tasks/<task_id>/    # 每次 Agent 派单的工作目录
    └── tripgo/
        ├── catalog.json        # 静态酒店列表（已纳入仓库）
        ├── orders.json         # 已确认订单（运行时生成）
        └── tasks/<id>/         # 每次验证的工作目录
```

## TripGo 校验项（与电路约束对照）

| Verifier 输出行 | 含义 | 在 ZK 电路里？ |
|---|---|---|
| `ZK proof` | Ligero v2 见证-证明数学正确 | 是 |
| `Delegation sig` | 设备 sk_d 对委托消息的 ECDSA 签名 | 是（约束 7） |
| `Policy claims` | 披露的 claim 在 policy.allowed_claims 里 | 是（约束 8） |
| `Policy predicates` | 通用谓词（DISCLOSE/EQ/IN_SET/GE/LE）通过 | 是 |
| `Policy expiry` | now < policy.expires | 是（约束 9） |
| `Delegation revocation` | 委托未撤销且撤销状态签名有效 | 是（约束 11） |
| `Business Rule` | 商家业务层（如 18+ 酒店要求 age_over_18 在披露集中） | 否（应用层） |
| `Overall` | 全部 ACCEPT 才入库 | — |

## 安全 / 演示局限

- `sk_I` 与 `sk_a` 共置于 :8002：演示简化。生产环境 Issuer 应是独立可信第三方。
- HTTP 明文，未做 TLS。`X-Request-Id` 头无签名保护——:8002↔:8003 之间若有中间人可重放。生产需 mTLS + nonce 绑定。
- 委托私钥下发：Alice 把 `agent_sk` 通过 ZK 证明绑定，本演示中 `agent_sk` 文件留在 task 目录方便观察；现实场景应由 Agent 远端生成、私钥永不离机。
- feed 历史 in-memory，重启清零。生产应换 Redis/SSE proxy。
- 撤销服务（链上 Merkle 树）当前为本地 JSON 文件 + 设备签名校验，未真正部署到链。
