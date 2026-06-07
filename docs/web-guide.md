# Web 端 · ZK-AgentAuth 双服务原型

Wallet（Alice 钱包，:8002）+ TripGo（验证方/商家，:8003）两个 Flask 服务，外加单文件 React Client UI 与 Service UI。

跨服务流程：Alice 把 mDoc 凭证的部分声明委托给 AI Agent，Agent 携 SM2/SM3 委托材料 + Ligero v2 ZK 证明跨服务调用 TripGo 完成下单；TripGo 验证后无法回溯 Alice 真实身份。

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
   - ① delegating · 生成 SM2/SM3 委托材料与委托撤销状态
   - ② fetching_request · 跨服务 POST :8003/oid4vp/request 取 OID4VP 展示请求
   - ③ proving · 生成 Ligero v2 ZK 证明（~5 秒），proof.bin 实际尺寸（~350 KB）回填
   - ④ posting · direct_post 投递 :8003/oid4vp/response
   - ⑤ done · 校验全 PASS，订单入库
3. **同时** 切到 :8003 的 Live Monitor，看到刚才的 Agent 流量实时进入：JSON 解析、四步验证动画、订单卡片
4. 钱包侧得到一张 VERIFIED 印章 + 订单详情卡

### C · 修改委托权限（不触发购物）

1. AgentChat 头部点「修改权限」 → DelegationWizard
2. 4 步配完后点「签发委托」 → 只本地保存策略，**不会派单**
3. 顶部 chip 行多出新委托，可点击切换为下次派单生效的策略
4. 取消勾选某属性（如 `age_over_18`），再去对话框预订 18+ 酒店 → TripGo 端 Business Rule 检查 FAIL → 订单 REJECT

## 接入其他 AI Agent（MCP 服务）

把本项目的「匿名委托下单」能力作为一个 **MCP 服务(stdio)** 暴露,任何支持 MCP 的 Agent
宿主(Claude Desktop / Hermes / openclaw / …)加一段配置即可复用,宿主侧零代码改动。MCP
server 是对运行中的 `wallet_server`(:8002)的薄代理,自身不做密码学。详见
[`mcp-server.md`](mcp-server.md)。

**前置**:先 `make demo` 起 wallet + tripgo 并保持运行(下单要 TripGo 在线)。

### 配置方法 A · 标准 `mcpServers` JSON（Claude Desktop 等）

写进宿主的 MCP 配置(如 `claude_desktop_config.json`);把路径换成你的仓库绝对路径:

```json
{
  "mcpServers": {
    "zkaa-wallet": {
      "command": "/ABS/PATH/zk-agentauth/web/.venv/bin/python",
      "args": ["/ABS/PATH/zk-agentauth/web/mcp_server/server.py"],
      "env": { "WALLET_BASE": "http://localhost:8002" }
    }
  }
}
```

### 配置方法 B · Hermes（YAML,字段是 `mcp_servers`）

写进 `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  zkaa-wallet:
    command: /ABS/PATH/zk-agentauth/web/.venv/bin/python
    args:
    - /ABS/PATH/zk-agentauth/web/mcp_server/server.py
    env:
      WALLET_BASE: http://localhost:8002
    timeout: 600
```

重启宿主后,工具列表出现 `list_agents / list_hotels / wallet_status / book_hotel /
booking_status / presentation_log`。对宿主说「用出行助手帮我订外滩璞丽酒店」即走真实
零知识证明下单。

> 配置片段也可在管理台「MCP 接入」页一键复制(路径已自动填好)。
> 调试:`make mcp-dev` 打开 MCP Inspector 交互式调用各工具。
> TripGo 上云:只在 wallet 侧设 `TRIPGO_BASE=https://你的域名`,宿主配置不用改。

### 本地权限/凭证管理台

外部 Agent 宿主无法管理委托权限与凭证,因此提供一个本地管理台(与 demo 同端口,无新进程):

打开 **http://localhost:8002/manage**,可:
- **档案**:增删改多个 Agent,为每个 Agent 勾选可披露的属性(`allowed_claims`)。
  这是唯一的授权点——MCP 的 `book_hotel` 只能按所选 Agent 的授权出示,无法越权。
- **凭证**:查看 mDoc 持有的属性,重发凭证。
- **委托管理**:撤销委托(consume-on-use)。
- **日志**:真实出示历史(含外部 Agent 经 MCP 触发的)。
- **MCP 接入**:复制上面的配置片段、查看工具清单与在线自检。

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
| GET  | `/.well-known/openid-configuration` | OIDC discovery，暴露 issuer、authorization/token endpoint、JWKS 地址和支持能力 |
| GET  | `/jwks.json` | OIDC RS256 签名公钥 JWKS |
| GET/POST | `/userinfo` | Bearer access token 用户信息端点，要求 `openid` scope |
| GET  | `/schemas/agent-delegation.schema.json` | `authorization_details` 的 Agent 委托 JSON Schema |
| GET  | `/profiles/vp-token/zkaa-ligero-v1` | `zkaa+ligero` VP Token profile markdown |
| GET/POST | `/oauth/authorize` | OIDC/OAuth 风格授权页，校验 client/redirect_uri/state/PKCE/CSRF，解析 `authorization_details` 并生成 authorization code |
| POST | `/oauth/token` | authorization_code 交换，校验 PKCE，code 5 分钟过期且一次性使用，写入 access token store，返回 `access_token`、RS256 `id_token`、`authorization_details`、`agent_policy` |
| GET  | `/api/catalog` | 代理 :8003/api/catalog |
| POST | `/api/agent/dispatch` | 派 Agent，body 可直接给 `{hotel_id, claims, expires, agent_id}`，也可用 `authorization_details` 承载委托策略 |
| GET  | `/api/agent/task/<id>/stream` | SSE：阶段进度（事件名为阶段名） |
| GET  | `/api/agent/task/<id>` | 任务最终态 |
| GET  | `/api/agent/history` | 最近任务列表 |

`authorization_details` 示例：

```json
[
  {
    "type": "https://zk-agentauth.local/authorization/agent-delegation",
    "agent_id": "tripgo-agent",
    "allowed_claims": ["age_over_18"],
    "predicates": ["age_over_18:GE:18"],
    "expires": "2027-01-01T00:00:00Z",
    "verifier": "tripgo",
    "allowed_scopes": ["hotel.book"]
  }
]
```

OAuth demo 注册了一个客户端白名单：

```text
client_id: tripgo-web
redirect_uri:
  - http://localhost:8003/oauth/callback
  - http://127.0.0.1:8003/oauth/callback
PKCE: required, S256 only
state: required
authorization code: 5 minutes, one-time use
access token: stored server-side, 10 minutes, Bearer token scope checked by /userinfo
id_token: RS256 signed, public key at /jwks.json
authorization_details type: https://zk-agentauth.local/authorization/agent-delegation
authorization_details schema: http://localhost:8002/schemas/agent-delegation.schema.json
```

生成带 PKCE 的授权页 URL：

```bash
python3 - <<'PY'
import base64, hashlib, json, secrets, urllib.parse

code_verifier = secrets.token_urlsafe(48)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode("ascii")).digest()
).rstrip(b"=").decode("ascii")
authorization_details = [{
    "type": "https://zk-agentauth.local/authorization/agent-delegation",
    "agent_id": "tripgo-agent",
    "allowed_claims": ["age_over_18"],
    "predicates": ["age_over_18:GE:18"],
    "expires": "2027-01-01T00:00:00Z",
    "verifier": "tripgo",
    "allowed_scopes": ["hotel.book"],
}]
params = {
    "response_type": "code",
    "client_id": "tripgo-web",
    "redirect_uri": "http://localhost:8003/oauth/callback",
    "scope": "openid agent.delegate",
    "state": secrets.token_urlsafe(16),
    "nonce": secrets.token_urlsafe(16),
    "authorization_details": json.dumps(authorization_details, separators=(",", ":")),
    "code_challenge": code_challenge,
    "code_challenge_method": "S256",
}
print("open:", "http://localhost:8002/oauth/authorize?" + urllib.parse.urlencode(params))
print("save code_verifier:", code_verifier)
PY
```

授权页批准后会跳转到 `redirect_uri?code=...&state=...`。用上一步保存的 `code_verifier` 换 token：

```bash
curl --noproxy '*' -X POST http://localhost:8002/oauth/token \
  -d grant_type=authorization_code \
  -d client_id=tripgo-web \
  -d redirect_uri=http://localhost:8003/oauth/callback \
  -d code='PASTE_CODE_HERE' \
  -d code_verifier='PASTE_CODE_VERIFIER_HERE'
```

再用返回的 `access_token` 调 `/userinfo`：

```bash
curl --noproxy '*' http://localhost:8002/userinfo \
  -H 'Authorization: Bearer PASTE_ACCESS_TOKEN_HERE'
```

`/api/agent/dispatch` 若收到同一份 `authorization_details`，会从中提取 `allowed_claims`、`predicates`、`expires`、`agent_id` 作为 Agent 委托策略，并继续走 `/oid4vp/request` → `/oid4vp/response`。

OIDC discovery:

```bash
curl --noproxy '*' http://localhost:8002/.well-known/openid-configuration
curl --noproxy '*' http://localhost:8002/jwks.json
curl --noproxy '*' http://localhost:8002/schemas/agent-delegation.schema.json
curl --noproxy '*' http://localhost:8002/profiles/vp-token/zkaa-ligero-v1
```

### TripGo Server (8003)

| Method | Path | 说明 |
|--------|------|------|
| GET  | `/` | Service UI |
| GET  | `/api/catalog` | 6 家酒店 |
| POST | `/api/order/human` | 真人下单（无 ZK） |
| POST | `/api/agent/request` | 内部：颁发 reader request（zip） |
| POST | `/api/agent/order` | 接收 Agent 投递 (multipart) → 调 verifier → SSE 广播 |
| GET  | `/.well-known/oid4vp-verifier` | TripGo OID4VP verifier metadata，暴露 JWKS、direct_post endpoint 与 `zkaa+ligero` 支持能力 |
| GET  | `/oid4vp/jwks.json` | TripGo verifier request object RS256 签名公钥 |
| GET  | `/profiles/vp-token/zkaa-ligero-v1` | `zkaa+ligero` VP Token profile markdown |
| GET/POST | `/oid4vp/request` | OID4VP 风格请求对象，返回 `{request_id,state,request,request_object_jwt,reader_request_zip_b64}` |
| POST | `/oid4vp/response` | OID4VP `direct_post` 风格响应，body 内含 `vp_token.presentation_zip_b64` |
| GET  | `/api/agent/feed` | SSE：Live Monitor 流量推送 |
| GET  | `/api/agent/feed/history` | feed 历史（in-memory，重启清零） |
| GET  | `/api/orders/<id>` | 订单详情 |

`/oid4vp/request` 复用 `delegation_demo_verifier request` 生成 SM2/SM3 delegated profile 的 `reader_request.cbor` / `session_transcript.cbor`，外层补上 `client_id`、`response_mode=direct_post`、`state`、`presentation_definition`、`client_metadata_uri` 等字段，并生成 RS256 JWS `request_object_jwt`。请求体也可传 `authorization_details`；TripGo 会从其中派生 `claims/predicates` 并写入 request object 与 metadata。`reader_request_zip_b64` 是当前原型给 prover 复用目录格式的扩展。

`zkaa+ligero` VP Token profile：

```text
profile: https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1
local spec: web/profiles/vp-token/zkaa-ligero-v1.md
local HTTP: http://localhost:8003/profiles/vp-token/zkaa-ligero-v1
format: zkaa+ligero
container: base64url/base64 encoded ZIP in vp_token.presentation_zip_b64
required files:
  - proof.bin
  - public_delegation.json
  - delegation_revocation_status.json
optional disclosed-claim files:
  - disclosed_claims_count.txt
  - disclosed_alias_<i>.txt
  - disclosed_namespace_<i>.txt
  - disclosed_id_<i>.txt
  - disclosed_cbor_value_<i>.bin
binding:
  - proof is verified against the original reader_request.cbor
  - nonce/state are recovered from the OID4VP request stored by TripGo
  - presentation_definition.input_descriptors[0].id maps to $.vp_token
replay protection:
  - each OID4VP request metadata starts with consumed=false
  - /oid4vp/response marks the matching state/request_id as consumed after verification
  - repeating the same state/request_id returns HTTP 409 replay_detected
```

`/oid4vp/response` 接收示例：

```json
{
  "state": "request-state",
  "vp_token": {
    "format": "zkaa+ligero",
    "profile": "https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1",
    "presentation_zip_b64": "...",
    "claims": ["age_over_18"],
    "order_request": {
      "hotel_id": 1,
      "checkin": "2026-05-29",
      "checkout": "2026-05-31",
      "agent_id": "tripgo-agent"
    }
  },
  "presentation_submission": {
    "id": "ps-demo",
    "definition_id": "tripgo-zkaa-agentauth",
    "descriptor_map": [
      {
        "id": "zkaa-ligero-presentation",
        "format": "zkaa+ligero",
        "path": "$.vp_token",
        "path_nested": {
          "format": "application/zip;base64",
          "path": "$.vp_token.presentation_zip_b64",
          "proof_files": {
            "proof": "proof.bin",
            "public_delegation": "public_delegation.json",
            "revocation_status": "delegation_revocation_status.json"
          }
        }
      }
    ]
  }
}
```

服务端会按 `state` 找回原 reader request，解包 presentation 后继续调用同一个 verifier。

TripGo verifier metadata:

```bash
curl --noproxy '*' http://localhost:8003/.well-known/oid4vp-verifier
curl --noproxy '*' http://localhost:8003/oid4vp/jwks.json
curl --noproxy '*' http://localhost:8003/profiles/vp-token/zkaa-ligero-v1
```

`request_object_jwt` 的 payload 是 `/oid4vp/request` 中的 request object 加上 `iss/aud/iat/exp`，签名 key 由 `/oid4vp/jwks.json` 发布。

## 本地 HTTPS

默认仍用 HTTP，方便浏览器和 curl 调试。要用本地自签 HTTPS：

```bash
USE_HTTPS=1 OPEN_BROWSER=0 ./start.sh
```

这会让 Wallet 和 TripGo 使用 Werkzeug `adhoc` 自签证书，并自动设置：

```text
OIDC_ISSUER=https://localhost:8002
TRIPGO_ISSUER=https://localhost:8003
TRIPGO_BASE=https://localhost:8003
ZKAA_TLS_VERIFY=0
```

浏览器访问时会看到自签证书警告，curl 需加 `-k`。如果你用 Nginx/Caddy/Traefik 做反向代理，可显式设置 `OIDC_ISSUER`、`TRIPGO_ISSUER`、`TRIPGO_BASE` 指向代理后的 HTTPS origin。

## 目录布局

```
web/
├── README.md
├── Makefile · start.sh · requirements.txt
├── mcp_server/
│   ├── server.py          # MCP 服务（stdio，薄代理到 wallet:8002）
│   └── README.md          # MCP 工具清单与接入说明
├── wallet_server/
│   ├── app.py             # Flask routes + bootstrap（含 /manage、/api/mcp/info）
│   ├── bins.py            # subprocess 包装四个 C++ 二进制
│   ├── agent_runner.py    # 五阶段任务 + SSE + 持久化日志
│   └── static/
│       ├── index.html     # Client UI（单文件 React,带聊天的 web demo）
│       └── manage.html    # 本地权限/凭证管理台（/manage）
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
| `Delegation sig` | 设备 sk_d 对委托消息的 SM2/SM3 签名 | 是（约束 7） |
| `Policy claims` | 披露的 claim 在 policy.allowed_claims 里 | 是（约束 8） |
| `Policy predicates` | 通用谓词（DISCLOSE/EQ/IN_SET/GE/LE）通过 | 是 |
| `Policy expiry` | now < policy.expires | 是（约束 9） |
| `Delegation revocation` | 委托未撤销且撤销状态签名有效 | 是（约束 11） |
| `Business Rule` | 商家业务层（如 18+ 酒店要求 age_over_18 在披露集中） | 否（应用层） |
| `Overall` | 全部 ACCEPT 才入库 | — |

## 安全 / 演示局限

- `sk_I` 与 `sk_a` 共置于 :8002：演示简化。生产环境 Issuer 应是独立可信第三方。
- 本地可用 `USE_HTTPS=1` 启动自签 HTTPS；生产仍应使用正式 CA 证书、反向代理或 mTLS。
- OID4VP request object 已做 RS256 JWS 签名并暴露 TripGo verifier metadata/JWKS；Wallet 端当前仍是演示级消费，尚未实现完整信任锚配置和 request object 强校验。
- 委托私钥下发：Alice 把 `agent_sk` 通过 ZK 证明绑定，本演示中 `agent_sk` 文件留在 task 目录方便观察；现实场景应由 Agent 远端生成、私钥永不离机。
- feed 历史 in-memory，重启清零。生产应换 Redis/SSE proxy。
- 撤销服务（链上 Merkle 树）当前为本地 JSON 文件 + 设备签名校验，未真正部署到链。
