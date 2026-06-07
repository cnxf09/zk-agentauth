# ZK-AgentAuth

基于零知识证明的 AI Agent 委托认证系统。Alice 把 mDoc 凭证里的部分声明授权给 AI Agent,
Agent 携 SM2/SM3 委托材料与 Ligero v2 ZK 证明跨服务调用商家完成下单;商家可验证授权与
属性正确性,但**无法回溯 Alice 真实身份,也无法跨会话关联**。

系统两层:**C++ ZK 核心**(`lib/`,派生自 Google Longfellow ZK,编译成 issuer / alice /
agent / verifier 四个 CLI)+ **Python 编排层**(`web/`,Flask 双服务 + MCP 服务)。可三种
方式使用:可视化 Web 演示、接入任意支持 MCP 的 AI Agent、或直接调命令行。

当前国密 profile 为 `zk-agentauth-sm-delegation-v1`:委托、Agent 会话和委托撤销签名使用
标准 SM2,SM2 的 `ZA/e` 以及委托策略相关摘要使用 SM3。mDoc issuer 签名、原始 baseline
路径、circuit id 等非委托签名路径仍保留 P-256/SHA-256 兼容逻辑。

## 构建

```bash
# 系统依赖
brew install cmake openssl ninja                  # macOS
# sudo apt install cmake libssl-dev libzstd-dev    # Debian/Ubuntu

cd web
make build      # 编译 C++ 二进制(只需一次,约 1-2 分钟,默认 -O3)
make deps       # 创建 venv 并安装 Python 依赖
```

## 使用

### 1 · Web 双服务演示(可视化)

```bash
cd web && make demo      # 起 wallet:8002 + tripgo:8003,自动颁发 mDoc 并打开浏览器
```

| URL | 角色 |
|-----|------|
| http://localhost:8002 | Alice 钱包 / Agent 对话(Client UI) |
| http://localhost:8002/manage | 本地权限/凭证管理台 |
| http://localhost:8003 | TripGo 商户站(Service UI) |

在 8002 选一个 Agent 对话(先在「模型」面板填入任意 OpenAI/Anthropic 兼容的 API Key),
说「帮我订外滩璞丽酒店」即走真实 ZK 全链路下单。`make clean` 清运行时数据。

### 2 · 接入其他 AI Agent(MCP 服务)

把匿名委托能力作为 **MCP 服务(stdio)** 暴露,Claude Desktop / Hermes / openclaw 等加一段
配置即可复用。MCP server 是对运行中的 `wallet_server`(:8002)的薄代理。

**前置**:先 `cd web && make demo` 起后端并保持运行(下单需 TripGo 在线)。

标准 `mcpServers` JSON(Claude Desktop 等,路径换成你的仓库绝对路径):

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

Hermes(YAML,写进 `~/.hermes/config.yaml`,字段名是 `mcp_servers`):

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

重启宿主后出现工具 `list_agents / list_hotels / wallet_status / book_hotel /
booking_status / presentation_log`,对宿主说「用出行助手帮我订外滩璞丽酒店」即可。

- **权限只在管理台 http://localhost:8002/manage 配置**:为每个 Agent 勾选可披露的属性
  (`allowed_claims`);`book_hotel` 只能按所选 Agent 的授权出示,无法越权(ZK 电路强制)。
  管理台还可查看凭证、撤销委托、查看真实出示日志、一键复制上面的配置片段。
- 调试:`cd web && make mcp-dev` 打开 MCP Inspector 交互式调用各工具。
- TripGo 上云:只在 wallet 侧设 `TRIPGO_BASE=https://你的域名`,宿主配置不变。

### 3 · 命令行(直接调四个 CLI)

Issuer 颁发 → Alice 委托 → Verifier 挑战 → Agent 出示 → Verifier 验证:

```bash
WORK=/tmp/zkaa_cli; BIN=$(pwd)/build/examples/delegation_demo; rm -rf $WORK
$BIN/delegation_demo_issuer issue --example 3 --out $WORK/issue
$BIN/delegation_demo_alice delegate --holder $WORK/issue/holder --claim age_over_18 \
  --expires 2027-01-01T00:00:00Z --agent-id bookstore-agent --out $WORK/delegation
$BIN/delegation_demo_verifier request --sm --issuer-public $WORK/issue/issuer_public \
  --claim age_over_18 --out $WORK/request
$BIN/delegation_demo_agent present --delegation $WORK/delegation \
  --issuer-public $WORK/issue/issuer_public --request $WORK/request --out $WORK/presentation
$BIN/delegation_demo_verifier verify --issuer-public $WORK/issue/issuer_public \
  --request $WORK/request --presentation $WORK/presentation
```

预期 6 项检查全 PASS、`Overall: ACCEPT`。example 3 自带 4 个 claim(age_over_18 /
family_name / birth_date / height);谓词支持 `DISCLOSE / EQ / IN_SET / GE / LE`,
当前 ZK 规格单次最多组合 2 个 claim。不加 `request --sm` 时仍可运行原 P-256/SHA-256
baseline profile,用于兼容和回归对照。

## 致谢

C++ 零知识证明库(`lib/`)派生自 Google 开源的
[Longfellow ZK](https://github.com/google/longfellow-zk)(Apache 2.0)。本项目在其
`examples/mdoc_anoncred/` 之上新增 `examples/delegation_demo/`,把委托签名、策略披露、
未过期、Agent 会话签名、委托未撤销等语义编入 ZK 电路,并新增 SM2/SM3 delegated profile。

许可证:Apache License 2.0(继承自 Longfellow ZK),详见 [`LICENSE`](LICENSE)。
