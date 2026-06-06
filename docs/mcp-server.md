# ZK-AgentAuth MCP Server

把本项目的「匿名委托下单」能力作为一个 **MCP 服务(stdio)** 暴露,让任何支持 MCP 的
Agent 宿主(Claude Desktop / Hermes / openclaw / …)以「加一条 server 配置」的极小代价
复用——宿主侧零代码改动。

这是对运行中的 `wallet_server`(默认 `:8002`)的**薄代理**:它自身不做任何密码学,只调用
钱包已有的 HTTP 端点。权限(每个 Agent 能披露哪些属性)在钱包的「档案」里预先配置,
`book_hotel` 永远不会披露超出所选 Agent `allowed_claims` 的属性——由 ZK 电路强制。

## 暴露的工具

| 工具 | 说明 |
|------|------|
| `list_agents()` | 列出所有委托 Agent(档案)及其授权披露的属性 |
| `list_hotels()` | 列出 TripGo 可预订酒店(id/名称/价格/是否 18+) |
| `wallet_status()` | 是否持有 mDoc 凭证及可证明属性 |
| `book_hotel(agent, hotel, checkin?, checkout?)` | 以某 Agent 身份匿名 ZK 证明预订;阻塞到出证+验证完成 |
| `booking_status(task_id)` | 查询某次预订任务状态 |
| `presentation_log(limit?)` | 读取真实出示历史 |

`book_hotel` 的 `agent` 可传档案名称或 id;`hotel` 可传名称关键字或 id。披露的属性固定
取自该 Agent 的 `allowed_claims`,调用方无法指定额外属性(不会越权)。

## 前置

先启动钱包与商家(它们提供真实的 ZK 颁发/证明/验证):

```bash
cd web
make build   # 仅首次,编译 C++ 二进制
make deps    # 安装 Python 依赖(含 mcp)
make demo    # 起 wallet :8002 + tripgo :8003
```

MCP server 自身一般由宿主拉起;本地调试可:

```bash
make mcp        # 直接以 stdio 跑(给宿主用)
make mcp-dev    # 打开 MCP Inspector,交互式调用各工具
```

## 接入宿主(Claude Desktop 示例)

写入 `claude_desktop_config.json`(把路径换成你的仓库绝对路径,管理台的「MCP 接入」页可一键复制):

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

重启宿主后,即可对它说「用出行助手帮我订外滩璞丽酒店」,走真实零知识证明下单。

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `WALLET_BASE` | `http://localhost:8002` | 运行中的钱包地址 |
| `ZKAA_TLS_VERIFY` | `1` | 出站是否校验 TLS |
| `ZKAA_MCP_BOOK_TIMEOUT` | `120` | `book_hotel` 等待出证的秒数 |

> TripGo 商家若部署到远端,只需在 **wallet 侧**设 `TRIPGO_BASE=https://你的域名`,MCP 配置不变。

## 配套管理台

外部 Agent 宿主无法管理委托权限/凭证,因此本项目提供一个本地管理台:
打开 **http://localhost:8002/manage** 即可增删改 Agent 档案、配置 `allowed_claims`、
撤销委托、查看凭证与出示日志,并复制上面的接入配置。
