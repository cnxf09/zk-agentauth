"""ZK-AgentAuth MCP server (stdio).

Exposes the project's anonymous-delegation hotel-booking flow as MCP tools so any
MCP host (Claude Desktop / Hermes / openclaw) can reuse it with a single stdio
server config — no code change on the host side.

This is a *thin proxy* over the running wallet_server (default :8002): it does no
cryptography itself, it just calls the existing HTTP endpoints. The wallet must be
running (cd web && make demo). Permission management (which claims each Agent may
disclose) lives in the wallet's profiles; `book_hotel` can never disclose anything
outside the chosen Agent's `allowed_claims` — that is enforced by the ZK circuit.

Run standalone for debugging:  python mcp_server/server.py
Usually the host launches it; see the repo root README.md for the config snippet.
"""
from __future__ import annotations

import os
import time
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP

# Base URL of the running wallet_server. Override with WALLET_BASE if needed.
WALLET_BASE = os.environ.get("WALLET_BASE", "http://localhost:8002").rstrip("/")
# trust_env=False bypasses a local Clash/V2Ray proxy for loopback calls, matching
# agent_runner.py. TLS verify follows ZKAA_TLS_VERIFY (default on).
_TLS_VERIFY = os.environ.get("ZKAA_TLS_VERIFY", "1") != "0"
# book_hotel blocks until the proof + verification finishes. A ZK proof is ~5-10s
# plus a verifier round-trip; 120s covers cold-cache / slow runs.
_BOOK_TIMEOUT = int(os.environ.get("ZKAA_MCP_BOOK_TIMEOUT", "120"))

_S = requests.Session()
_S.trust_env = False

mcp = FastMCP("zkaa-wallet")


class WalletError(RuntimeError):
    pass


def _get(path: str, **kw) -> Any:
    try:
        r = _S.get(f"{WALLET_BASE}{path}", timeout=kw.pop("timeout", 15), verify=_TLS_VERIFY)
    except requests.RequestException as e:
        raise WalletError(
            f"无法连接钱包 {WALLET_BASE}{path}:{e}。请先在 web/ 下运行 `make demo` 启动 wallet+tripgo。"
        )
    if r.status_code >= 400:
        raise WalletError(f"钱包返回 {r.status_code}: {r.text[:200]}")
    return r.json()


def _post(path: str, body: dict, timeout: int = 30) -> Any:
    try:
        r = _S.post(f"{WALLET_BASE}{path}", json=body, timeout=timeout, verify=_TLS_VERIFY)
    except requests.RequestException as e:
        raise WalletError(
            f"无法连接钱包 {WALLET_BASE}{path}:{e}。请先在 web/ 下运行 `make demo` 启动 wallet+tripgo。"
        )
    if r.status_code >= 400:
        raise WalletError(f"钱包返回 {r.status_code}: {r.text[:200]}")
    return r.json()


def _resolve_agent(agent: str) -> dict:
    """Resolve an Agent profile by id or (case-insensitive) name."""
    profiles = _get("/api/profiles")
    a = (agent or "").strip()
    for p in profiles:
        if p.get("id") == a:
            return p
    al = a.lower()
    for p in profiles:
        if str(p.get("name", "")).lower() == al:
            return p
    for p in profiles:
        if al and al in str(p.get("name", "")).lower():
            return p
    names = ", ".join(f"{p.get('name')}（{p.get('id')}）" for p in profiles) or "（无）"
    raise WalletError(f"找不到 Agent「{agent}」。可用 Agent:{names}。")


def _resolve_hotel(hotel: str | int) -> dict:
    """Resolve a hotel by catalog id or name keyword."""
    catalog = _get("/api/catalog")
    catalog = catalog if isinstance(catalog, list) else catalog.get("hotels", [])
    # by id (int or numeric string)
    try:
        hid = int(hotel)
        for h in catalog:
            if int(h.get("id")) == hid:
                return h
    except (TypeError, ValueError):
        pass
    q = str(hotel).strip().lower()
    for h in catalog:
        if q and q in str(h.get("name", "")).lower():
            return h
    names = ", ".join(f"{h.get('name')}（id={h.get('id')}）" for h in catalog) or "（无）"
    raise WalletError(f"找不到酒店「{hotel}」。可订酒店:{names}。")


@mcp.tool()
def list_agents() -> list[dict]:
    """列出本地钱包里配置的所有委托 Agent(档案)及其被授权披露的属性。

    每个 Agent 只能证明它 allowed_claims 里的属性;这是在管理台预先授权的,
    book_hotel 不能超出此范围。
    """
    return [
        {
            "id": p.get("id"),
            "name": p.get("name"),
            "agent_id": p.get("agent_id"),
            "allowed_claims": p.get("allowed_claims", []),
            "desc": p.get("desc", ""),
        }
        for p in _get("/api/profiles")
    ]


@mcp.tool()
def list_hotels() -> list[dict]:
    """列出 TripGo 商家可预订的酒店目录(含 id、名称、价格、是否 18+)。"""
    catalog = _get("/api/catalog")
    catalog = catalog if isinstance(catalog, list) else catalog.get("hotels", [])
    return [
        {"id": h.get("id"), "name": h.get("name"), "price": h.get("price"),
         "adult_only": bool(h.get("age"))}
        for h in catalog
    ]


@mcp.tool()
def wallet_status() -> dict:
    """查询钱包状态:是否已持有 mDoc 凭证,以及可证明的属性列表。"""
    d = _get("/api/wallet/status")
    return {
        "has_credential": bool(d.get("claims")),
        "claims": d.get("claims", []),
        "supported_claims": d.get("supported_claims", []),
    }


@mcp.tool()
def book_hotel(agent: str, hotel: str, checkin: str = "", checkout: str = "") -> dict:
    """以指定委托 Agent 的身份,通过零知识证明匿名预订一家酒店。

    商家只会得知该 Agent 被授权披露的属性(allowed_claims),无法回溯用户真实身份。
    披露的属性固定取自该 Agent 的档案,调用方无法指定额外属性(不会越权)。

    参数:
        agent: Agent 的名称或 id(见 list_agents)。
        hotel: 酒店名称关键字或 id(见 list_hotels)。
        checkin/checkout: 可选,YYYY-MM-DD;留空用默认入住日期。

    返回 ZK 证明 + 验证结果:accepted、6 项验证检查、订单详情(若通过)。
    18+ 酒店但该 Agent 未授权 age_over_18 时会被商家拒绝(accepted=false)。
    """
    prof = _resolve_agent(agent)
    h = _resolve_hotel(hotel)
    claims = list(prof.get("allowed_claims") or [])[:2]  # ZK spec discloses ≤2
    if not claims:
        return {"accepted": False,
                "error": f"Agent「{prof.get('name')}」没有任何被授权的属性,无法出示证明。"}

    body = {
        "hotel_id": h["id"],
        "claims": claims,
        "agent_id": prof.get("agent_id"),
        "expires": prof.get("expires"),
        "predicates": prof.get("predicates") or [],
    }
    if checkin:
        body["checkin"] = checkin
    if checkout:
        body["checkout"] = checkout

    dispatched = _post("/api/agent/dispatch", body)
    task_id = dispatched.get("task_id")
    if not task_id:
        raise WalletError(f"派单失败:{dispatched}")

    # Poll until terminal (done/failed).
    deadline = time.time() + _BOOK_TIMEOUT
    summary = None
    while time.time() < deadline:
        summary = _get(f"/api/agent/task/{task_id}")
        if summary.get("status") in ("done", "failed"):
            break
        time.sleep(2)
    else:
        return {"accepted": False, "task_id": task_id,
                "error": f"等待证明超时({_BOOK_TIMEOUT}s);可用 booking_status 继续查询。"}

    if summary.get("status") == "failed":
        err = next((e["data"].get("error") for e in summary.get("events", [])
                    if e.get("phase") == "failed" and isinstance(e.get("data"), dict)), None)
        return {"accepted": False, "task_id": task_id,
                "error": err or "证明/投递失败(常见原因:TripGo 商家未在线)。"}

    result = summary.get("result") or {}
    order = result.get("order") or {}
    return {
        "accepted": bool(result.get("accepted")),
        "overall": (result.get("checks") or {}).get("overall"),
        "checks": {k: v for k, v in (result.get("checks") or {}).items() if k != "raw"},
        "agent": prof.get("name"),
        "disclosed_claims": claims,
        "task_id": task_id,
        "order": {
            "order_id": order.get("order_id"),
            "hotel_name": order.get("hotel_name"),
            "amount": order.get("amount"),
            "claims_proven": order.get("claims_proven"),
            "proof_size_bytes": order.get("proof_size"),
        } if order else None,
    }


@mcp.tool()
def booking_status(task_id: str) -> dict:
    """查询某次预订任务的状态(用于 book_hotel 超时后手动轮询或排查)。"""
    s = _get(f"/api/agent/task/{task_id}")
    result = s.get("result") or {}
    return {
        "task_id": task_id,
        "status": s.get("status"),
        "accepted": result.get("accepted"),
        "overall": (result.get("checks") or {}).get("overall"),
        "order_id": (result.get("order") or {}).get("order_id"),
    }


@mcp.tool()
def presentation_log(limit: int = 20) -> list[dict]:
    """读取真实的零知识证明出示历史(最新在前),含 Agent、披露属性、验证结果、订单。"""
    entries = _get("/api/agent/log")
    out = []
    for e in entries[: max(1, min(limit, 100))]:
        out.append({
            "ts": e.get("ts"),
            "agent_id": e.get("agent_id"),
            "claims": e.get("claims"),
            "hotel_name": e.get("hotel_name"),
            "accepted": e.get("accepted"),
            "overall": e.get("overall"),
            "order_id": e.get("order_id"),
            "proof_size_bytes": e.get("proof_size"),
        })
    return out


if __name__ == "__main__":
    mcp.run()  # stdio transport
