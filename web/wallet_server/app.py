"""Wallet Server (Alice + Agent + Issuer) — port 8002.

Holds: sk_I, sk_a, sk_d, sk_agent. Auto-issues mDoc on first run.
Serves Client UI at /, exposes /api/wallet/* and /api/agent/*.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import json as _json
import requests
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, jsonify, redirect, request, send_from_directory, Response, stream_with_context
from queue import Empty

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bins  # noqa: E402
import agent_runner  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
HOLDER_DIR = DATA / "wallet" / "holder"
DELEGATION_DIR = DATA / "wallet" / "delegation"
TASKS_DIR = DATA / "wallet" / "tasks"
OAUTH_GRANTS_DIR = DATA / "wallet" / "oauth_grants"
OAUTH_TOKENS_DIR = DATA / "wallet" / "oauth_tokens"
OIDC_SIGNING_KEY_PATH = DATA / "wallet" / "oidc_signing_key.pem"
REVOCATION_STATE_PATH = DATA / "wallet" / "revocation_state.json"
LLM_CONFIG_PATH = DATA / "wallet" / "llm_config.json"
PROFILES_PATH = DATA / "wallet" / "profiles.json"
ISSUER_PUBLIC_DIR = DATA / "shared" / "issuer_public"
STATIC_DIR = Path(__file__).resolve().parent / "static"
SCHEMAS_DIR = ROOT / "schemas"
PROFILES_DIR = ROOT / "profiles"

PORT = int(os.environ.get("WALLET_PORT", "8002"))
USE_HTTPS = os.environ.get("USE_HTTPS") == "1"
DEFAULT_SCHEME = "https" if USE_HTTPS else "http"
TRIPGO_BASE = os.environ.get("TRIPGO_BASE", f"{DEFAULT_SCHEME}://localhost:8003")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", f"{DEFAULT_SCHEME}://localhost:{PORT}")
OIDC_KEY_ID = os.environ.get("OIDC_KEY_ID", "wallet-demo-rs256-1")
# LLM proxy config. Env vars are defaults; the "模型" panel can override them at
# runtime by writing data/wallet/llm_config.json (file wins over env).
LLM_ENV_DEFAULTS = {
    "provider": os.environ.get("LLM_PROVIDER", "openai"),
    "api_base": os.environ.get("LLM_API_BASE", "https://api.openai.com/v1"),
    "model": os.environ.get("LLM_MODEL", "gpt-4o-mini"),
    "api_key": os.environ.get("LLM_API_KEY", ""),
}
AGENT_DELEGATION_AUTHZ_TYPE = "https://zk-agentauth.local/authorization/agent-delegation"
AGENT_DELEGATION_AUTHZ_TYPE_ALIASES = {
    AGENT_DELEGATION_AUTHZ_TYPE,
    "agent_delegation",
    "zkaa_agent_delegation",
    "agent_policy",
}
OAUTH_AUTH_REQUEST_TTL_SECONDS = 300
OAUTH_CODE_TTL_SECONDS = 300
OAUTH_ACCESS_TOKEN_TTL_SECONDS = 600
OIDC_ID_TOKEN_TTL_SECONDS = 600
OAUTH_CLIENTS = {
    "tripgo-web": {
        "redirect_uris": {
            "http://localhost:8003/oauth/callback",
            "http://127.0.0.1:8003/oauth/callback",
            "https://localhost:8003/oauth/callback",
            "https://127.0.0.1:8003/oauth/callback",
        },
        "require_pkce": True,
        "pkce_methods": {"S256"},
    },
}

_bootstrap_lock = threading.Lock()


def _default_stay_dates() -> tuple[str, str]:
    today = datetime.now(timezone.utc).date()
    return (
        (today + timedelta(days=1)).isoformat(),
        (today + timedelta(days=3)).isoformat(),
    )


def _holder_present() -> bool:
    return HOLDER_DIR.exists() and (HOLDER_DIR / "device_response.cbor").exists()


def _issuer_public_present() -> bool:
    return ISSUER_PUBLIC_DIR.exists() and (ISSUER_PUBLIC_DIR / "issuer_pkx.txt").exists()


def bootstrap_if_needed():
    """If no mDoc on disk, run issuer once and place artifacts."""
    with _bootstrap_lock:
        if _holder_present() and _issuer_public_present():
            return
        print("[bootstrap] no mDoc found — running Issuer", flush=True)
        with tempfile.TemporaryDirectory(prefix="zkaa_issue_") as tmp:
            tmp_path = Path(tmp)
            bins.issuer_issue(tmp_path, example=3,
                              on_line=lambda l: print(f"  [issuer] {l}", flush=True))
            # move outputs into place
            HOLDER_DIR.parent.mkdir(parents=True, exist_ok=True)
            ISSUER_PUBLIC_DIR.parent.mkdir(parents=True, exist_ok=True)
            if HOLDER_DIR.exists():
                shutil.rmtree(HOLDER_DIR)
            if ISSUER_PUBLIC_DIR.exists():
                shutil.rmtree(ISSUER_PUBLIC_DIR)
            shutil.copytree(tmp_path / "holder", HOLDER_DIR)
            shutil.copytree(tmp_path / "issuer_public", ISSUER_PUBLIC_DIR)
        print(f"[bootstrap] mDoc → {HOLDER_DIR}", flush=True)
        print(f"[bootstrap] issuer_public → {ISSUER_PUBLIC_DIR}", flush=True)


def _read_supported_claims() -> list[str]:
    if not _issuer_public_present():
        return []
    n_file = ISSUER_PUBLIC_DIR / "supported_claims_count.txt"
    if not n_file.exists():
        return []
    n = int(n_file.read_text().strip())
    return [(ISSUER_PUBLIC_DIR / f"supported_claim_{i}.txt").read_text().strip()
            for i in range(n)]


def _read_holder_claims() -> list[str]:
    if not _holder_present():
        return []
    n_file = HOLDER_DIR / "claims_count.txt"
    if not n_file.exists():
        return []
    n = int(n_file.read_text().strip())
    return [(HOLDER_DIR / f"claim_alias_{i}.txt").read_text().strip()
            for i in range(n)]


def _load_authorization_details(value) -> list[dict]:
    if not value:
        return []
    if isinstance(value, str):
        value = json.loads(value)
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("authorization_details must be a JSON object or array")
    details = []
    for item in value:
        if not isinstance(item, dict):
            continue
        normalized = dict(item)
        if normalized.get("type") in AGENT_DELEGATION_AUTHZ_TYPE_ALIASES:
            normalized["type"] = AGENT_DELEGATION_AUTHZ_TYPE
            if "allowed_claims" not in normalized and "claims" in normalized:
                normalized["allowed_claims"] = normalized["claims"]
            _validate_agent_delegation_authorization_detail(normalized)
        details.append(normalized)
    return details


def _agent_delegation_schema() -> dict:
    return json.loads((SCHEMAS_DIR / "agent-delegation.schema.json").read_text())


def _validate_agent_delegation_authorization_detail(detail: dict):
    try:
        Draft202012Validator(
            _agent_delegation_schema(),
            format_checker=FormatChecker(),
        ).validate(detail)
        _validate_agent_delegation_formats(detail)
    except ValidationError as e:
        path = ".".join(str(p) for p in e.absolute_path)
        where = f" at {path}" if path else ""
        raise ValueError(f"authorization_details[agent-delegation] schema violation{where}: {e.message}") from e


def _validate_agent_delegation_formats(detail: dict):
    if detail.get("expires"):
        try:
            datetime.fromisoformat(str(detail["expires"]).replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError("authorization_details[agent-delegation] schema violation at expires: must be RFC3339 date-time") from e
    for key in ("checkin", "checkout"):
        if detail.get(key):
            try:
                datetime.strptime(str(detail[key]), "%Y-%m-%d")
            except ValueError as e:
                raise ValueError(f"authorization_details[agent-delegation] schema violation at {key}: must be YYYY-MM-DD") from e


def _agent_policy_from_authorization_details(value, client_id: str = "") -> tuple[list[dict], dict]:
    details = _load_authorization_details(value)
    if not details:
        return [], {}
    detail = next(
        (
            d for d in details
            if d.get("type") in AGENT_DELEGATION_AUTHZ_TYPE_ALIASES
        ),
        details[0],
    )
    nested = detail.get("policy") or {}
    claims = (
        nested.get("allowed_claims")
        or detail.get("allowed_claims")
        or detail.get("claims")
        or []
    )
    predicates = nested.get("predicates") or detail.get("predicates") or []
    policy = {
        "type": AGENT_DELEGATION_AUTHZ_TYPE,
        "agent_id": nested.get("agent_id") or detail.get("agent_id") or "tripgo-agent",
        "allowed_claims": claims if isinstance(claims, list) else [claims],
        "predicates": predicates if isinstance(predicates, list) else [predicates],
        "expires": nested.get("expires") or detail.get("expires") or "2027-01-01T00:00:00Z",
        "verifier": nested.get("verifier") or detail.get("verifier") or client_id,
        "scopes": nested.get("allowed_scopes") or detail.get("allowed_scopes") or detail.get("actions") or [],
    }
    for optional in ("max_amount", "currency", "hotel_id", "checkin", "checkout"):
        if optional in nested:
            policy[optional] = nested[optional]
        elif optional in detail:
            policy[optional] = detail[optional]
    return details, policy


def _redirect_with_params(uri: str, params: dict):
    sep = "&" if "?" in uri else "?"
    return redirect(uri + sep + urlencode({k: v for k, v in params.items() if v is not None}))


def _oauth_error(error: str, description: str = "", status: int = 400):
    body = {"error": error}
    if description:
        body["error_description"] = description
    return jsonify(body), status


def _outbound_tls_verify() -> bool:
    return os.environ.get("ZKAA_TLS_VERIFY", "1") != "0"


def _oauth_timestamp(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _parse_oauth_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_expired(value: str) -> bool:
    try:
        return datetime.now(timezone.utc) >= _parse_oauth_timestamp(value)
    except Exception:
        return True


def _is_safe_oauth_handle(value: str) -> bool:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return bool(value) and all(c in allowed for c in value)


def _oauth_file(prefix: str, handle: str) -> Path | None:
    if not _is_safe_oauth_handle(handle):
        return None
    return OAUTH_GRANTS_DIR / f"{prefix}{handle}.json"


def _token_file(access_token: str) -> Path:
    token_hash = hashlib.sha256(access_token.encode("ascii")).hexdigest()
    return OAUTH_TOKENS_DIR / f"{token_hash}.json"


def _save_access_token(access_token: str, grant: dict):
    OAUTH_TOKENS_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "active": True,
        "client_id": grant.get("client_id"),
        "scope": grant.get("scope", "openid"),
        "sub": _oidc_subject(),
        "authorization_details": grant.get("authorization_details", []),
        "agent_policy": grant.get("agent_policy", {}),
        "issued_at": _oauth_timestamp(),
        "expires_at": _oauth_timestamp(OAUTH_ACCESS_TOKEN_TTL_SECONDS),
        "grant_code": grant.get("code"),
    }
    _token_file(access_token).write_text(json.dumps(record, ensure_ascii=False, indent=2))


def _load_access_token(access_token: str) -> dict | None:
    if not access_token:
        return None
    try:
        path = _token_file(access_token)
    except UnicodeEncodeError:
        return None
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text())
    except Exception:
        return None
    if not record.get("active") or _is_expired(record.get("expires_at", "")):
        return None
    return record


def _require_bearer_scope(required_scope: str) -> tuple[dict | None, Response | tuple]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, _oauth_error("invalid_token", "Bearer access token required", 401)
    token = auth.removeprefix("Bearer ").strip()
    record = _load_access_token(token)
    if record is None:
        return None, _oauth_error("invalid_token", "access token is invalid or expired", 401)
    scopes = set(str(record.get("scope", "")).split())
    if required_scope not in scopes:
        return None, _oauth_error("insufficient_scope", f"scope {required_scope} required", 403)
    return record, None


def _client_config(client_id: str) -> dict | None:
    return OAUTH_CLIENTS.get(client_id)


def _redirect_uri_allowed(client_id: str, redirect_uri: str) -> bool:
    cfg = _client_config(client_id)
    return bool(cfg and redirect_uri in cfg.get("redirect_uris", set()))


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if not code_verifier or not code_challenge:
        return False
    if not 43 <= len(code_verifier) <= 128:
        return False
    if method == "S256":
        try:
            verifier_bytes = code_verifier.encode("ascii")
        except UnicodeEncodeError:
            return False
        digest = hashlib.sha256(verifier_bytes).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    elif method == "plain":
        expected = code_verifier
    else:
        return False
    return hmac.compare_digest(expected, code_challenge)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))


def _load_oidc_private_key():
    OIDC_SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if OIDC_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            OIDC_SIGNING_KEY_PATH.read_bytes(),
            password=None,
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    OIDC_SIGNING_KEY_PATH.write_bytes(pem)
    OIDC_SIGNING_KEY_PATH.chmod(0o600)
    return private_key


def _oidc_public_jwk() -> dict:
    public_numbers = _load_oidc_private_key().public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": OIDC_KEY_ID,
        "alg": "RS256",
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }


def _jwt_rs256(claims: dict) -> str:
    header = {"typ": "JWT", "alg": "RS256", "kid": OIDC_KEY_ID}
    signing_input = ".".join([
        _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")),
    ]).encode("ascii")
    signature = _load_oidc_private_key().sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signing_input.decode("ascii") + "." + _b64url(signature)


def _unix_time(value: datetime | None = None) -> int:
    return int((value or datetime.now(timezone.utc)).timestamp())


def _oidc_subject() -> str:
    if (HOLDER_DIR / "device_pkx.txt").exists():
        device_pkx = (HOLDER_DIR / "device_pkx.txt").read_text().strip()
        return _b64url(hashlib.sha256(device_pkx.encode("utf-8")).digest())
    return "wallet-demo-user"


def _id_token_for_grant(grant: dict) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": OIDC_ISSUER,
        "sub": _oidc_subject(),
        "aud": grant.get("client_id", ""),
        "iat": _unix_time(now),
        "exp": _unix_time(now + timedelta(seconds=OIDC_ID_TOKEN_TTL_SECONDS)),
    }
    if grant.get("created_at"):
        try:
            claims["auth_time"] = _unix_time(_parse_oauth_timestamp(grant["created_at"]))
        except Exception:
            pass
    if grant.get("nonce"):
        claims["nonce"] = grant["nonce"]
    return _jwt_rs256(claims)


def _render_authorization_page(
    params: dict,
    details: list[dict],
    policy: dict,
    auth_request_id: str,
    csrf_token: str,
) -> str:
    client_id = escape(params.get("client_id") or "unknown-client")
    redirect_uri = escape(params.get("redirect_uri") or "")
    state = escape(params.get("state") or "")
    nonce = escape(params.get("nonce") or "")
    scope = escape(params.get("scope") or "openid")
    claims = policy.get("allowed_claims") or []
    predicates = policy.get("predicates") or []
    auth_details_json = json.dumps(details, ensure_ascii=False, indent=2)
    policy_json = json.dumps(policy, ensure_ascii=False, indent=2)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Agent Delegation</title>
  <style>
    body {{ margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; background:#f7f3ec; color:#25231f; }}
    main {{ max-width:760px; margin:48px auto; padding:0 20px; }}
    section {{ background:#fffaf2; border:1px solid #ded2bd; border-radius:8px; padding:24px; box-shadow:0 16px 48px rgba(66,52,27,.12); }}
    h1 {{ margin:0 0 8px; font-size:24px; }}
    .meta {{ color:#6d6252; margin-bottom:20px; }}
    dl {{ display:grid; grid-template-columns:150px 1fr; gap:10px 16px; margin:20px 0; }}
    dt {{ color:#7a6b58; }}
    dd {{ margin:0; }}
    .pill {{ display:inline-block; padding:4px 8px; border:1px solid #c9bca6; border-radius:999px; margin:0 6px 6px 0; background:#fff; }}
    pre {{ overflow:auto; background:#221f1b; color:#f6ead9; padding:14px; border-radius:6px; font-size:12px; }}
    .actions {{ display:flex; gap:12px; margin-top:22px; }}
    button {{ border:0; border-radius:6px; padding:10px 14px; cursor:pointer; font-weight:650; }}
    .approve {{ background:#1d6f5f; color:white; }}
    .deny {{ background:#eadfce; color:#3b3124; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>授权 Agent 委托</h1>
      <div class="meta">OAuth/OIDC authorization request from <strong>{client_id}</strong></div>
      <dl>
        <dt>response_type</dt><dd>{escape(params.get("response_type") or "code")}</dd>
        <dt>scope</dt><dd>{scope}</dd>
        <dt>redirect_uri</dt><dd>{redirect_uri}</dd>
        <dt>state</dt><dd>{state or "未提供"}</dd>
        <dt>nonce</dt><dd>{nonce or "未提供"}</dd>
        <dt>agent_id</dt><dd>{escape(policy.get("agent_id") or "tripgo-agent")}</dd>
        <dt>expires</dt><dd>{escape(policy.get("expires") or "")}</dd>
        <dt>claims</dt><dd>{"".join(f'<span class="pill">{escape(str(c))}</span>' for c in claims) or "无"}</dd>
        <dt>predicates</dt><dd>{"".join(f'<span class="pill">{escape(str(p))}</span>' for p in predicates) or "无"}</dd>
      </dl>
      <pre>{escape(auth_details_json)}</pre>
      <pre>{escape(policy_json)}</pre>
      <form method="post" action="/oauth/authorize" class="actions">
        <input type="hidden" name="auth_request_id" value="{escape(auth_request_id)}">
        <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
        <button class="approve" type="submit" name="decision" value="approve">授权并生成 code</button>
        <button class="deny" type="submit" name="decision" value="deny">拒绝</button>
      </form>
    </section>
  </main>
</body>
</html>"""


app = Flask(__name__, static_folder=None)


# ---- static UI ----
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:fname>")
def static_files(fname):
    return send_from_directory(STATIC_DIR, fname)


@app.route("/schemas/<path:fname>")
def schema_files(fname):
    return send_from_directory(SCHEMAS_DIR, fname)


@app.route("/profiles/<path:fname>")
def profile_files(fname):
    return send_from_directory(PROFILES_DIR, fname)


@app.route("/profiles/vp-token/zkaa-ligero-v1")
def zkaa_ligero_profile():
    return send_from_directory(PROFILES_DIR / "vp-token", "zkaa-ligero-v1.md",
                               mimetype="text/markdown")


# ---- API ----
@app.route("/api/wallet/status")
def wallet_status():
    if not _holder_present():
        return jsonify({"has_mdoc": False, "claims": []})
    return jsonify({
        "has_mdoc": True,
        "claims": _read_holder_claims(),
        "supported_claims": _read_supported_claims(),
        "device_pkx": (HOLDER_DIR / "device_pkx.txt").read_text().strip()[:32] + "...",
    })


@app.route("/api/wallet/reissue", methods=["POST"])
def wallet_reissue():
    if HOLDER_DIR.exists():
        shutil.rmtree(HOLDER_DIR)
    if ISSUER_PUBLIC_DIR.exists():
        shutil.rmtree(ISSUER_PUBLIC_DIR)
    bootstrap_if_needed()
    return jsonify({"ok": True, "claims": _read_holder_claims()})


@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify({
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{OIDC_ISSUER}/oauth/authorize",
        "token_endpoint": f"{OIDC_ISSUER}/oauth/token",
        "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
        "jwks_uri": f"{OIDC_ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["openid", "agent.delegate"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_details_types_supported": [
            AGENT_DELEGATION_AUTHZ_TYPE,
        ],
        "authorization_details_schema_uri": f"{OIDC_ISSUER}/schemas/agent-delegation.schema.json",
    })


@app.route("/jwks.json")
def jwks():
    return jsonify({"keys": [_oidc_public_jwk()]})


@app.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    token_record, error = _require_bearer_scope("openid")
    if error is not None:
        return error
    return jsonify({
        "sub": token_record.get("sub"),
        "wallet": {
            "has_mdoc": _holder_present(),
            "claims": _read_holder_claims(),
        },
        "authorization_details": token_record.get("authorization_details", []),
        "agent_policy": token_record.get("agent_policy", {}),
    })


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    if request.method == "POST":
        form = request.form
        auth_request_id = form.get("auth_request_id", "")
        pending_path = _oauth_file("pending-", auth_request_id)
        if pending_path is None or not pending_path.exists():
            return Response("invalid or expired authorization request", status=400)
        pending = json.loads(pending_path.read_text())
        redirect_uri = pending.get("redirect_uri", "")
        state = pending.get("state")
        if _is_expired(pending.get("expires_at", "")):
            pending_path.unlink(missing_ok=True)
            return _redirect_with_params(redirect_uri, {
                "error": "invalid_request",
                "error_description": "authorization request expired",
                "state": state,
            })
        if not hmac.compare_digest(form.get("csrf_token", ""), pending.get("csrf_token", "")):
            return Response("invalid csrf_token", status=400)
        if form.get("decision") != "approve":
            pending_path.unlink(missing_ok=True)
            return _redirect_with_params(redirect_uri, {
                "error": "access_denied",
                "state": state,
            })
        code = secrets.token_urlsafe(24)
        OAUTH_GRANTS_DIR.mkdir(parents=True, exist_ok=True)
        grant = {
            "code": code,
            "client_id": pending.get("client_id", ""),
            "redirect_uri": redirect_uri,
            "scope": pending.get("scope", "openid"),
            "state": state,
            "nonce": pending.get("nonce"),
            "authorization_details": pending.get("authorization_details", []),
            "agent_policy": pending.get("agent_policy", {}),
            "code_challenge": pending.get("code_challenge"),
            "code_challenge_method": pending.get("code_challenge_method"),
            "created_at": _oauth_timestamp(),
            "expires_at": _oauth_timestamp(OAUTH_CODE_TTL_SECONDS),
            "used": False,
        }
        (OAUTH_GRANTS_DIR / f"{code}.json").write_text(
            json.dumps(grant, ensure_ascii=False, indent=2)
        )
        pending_path.unlink(missing_ok=True)
        return _redirect_with_params(redirect_uri, {"code": code, "state": state})

    params = dict(request.args)
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    if params.get("response_type", "code") != "code":
        return Response("unsupported response_type", status=400)
    if not client_id or not redirect_uri:
        return Response("missing client_id or redirect_uri", status=400)
    if not _redirect_uri_allowed(client_id, redirect_uri):
        return Response("invalid client_id or redirect_uri", status=400)
    if not params.get("state"):
        return _redirect_with_params(redirect_uri, {
            "error": "invalid_request",
            "error_description": "state required",
        })
    cfg = _client_config(client_id) or {}
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "plain")
    if cfg.get("require_pkce"):
        methods = cfg.get("pkce_methods", {"S256"})
        if not code_challenge or code_challenge_method not in methods:
            return _redirect_with_params(redirect_uri, {
                "error": "invalid_request",
                "error_description": "PKCE S256 code_challenge required",
                "state": params.get("state"),
            })
    try:
        details, policy = _agent_policy_from_authorization_details(
            params.get("authorization_details"), client_id
        )
    except (json.JSONDecodeError, ValueError) as e:
        return _redirect_with_params(redirect_uri, {
            "error": "invalid_request",
            "error_description": f"invalid authorization_details: {e}",
            "state": params.get("state"),
        })
    if not policy.get("allowed_claims"):
        return _redirect_with_params(redirect_uri, {
            "error": "invalid_request",
            "error_description": "authorization_details must include allowed_claims or claims",
            "state": params.get("state"),
        })
    OAUTH_GRANTS_DIR.mkdir(parents=True, exist_ok=True)
    auth_request_id = secrets.token_urlsafe(16)
    csrf_token = secrets.token_urlsafe(32)
    pending = {
        "auth_request_id": auth_request_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": params.get("scope", "openid"),
        "state": params.get("state"),
        "nonce": params.get("nonce"),
        "authorization_details": details,
        "agent_policy": policy,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "csrf_token": csrf_token,
        "created_at": _oauth_timestamp(),
        "expires_at": _oauth_timestamp(OAUTH_AUTH_REQUEST_TTL_SECONDS),
    }
    pending_path = _oauth_file("pending-", auth_request_id)
    assert pending_path is not None
    pending_path.write_text(json.dumps(pending, ensure_ascii=False, indent=2))
    return Response(
        _render_authorization_page(params, details, policy, auth_request_id, csrf_token),
        mimetype="text/html",
    )


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    if request.form.get("grant_type") != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400
    code = request.form.get("code", "")
    grant_path = _oauth_file("", code)
    if grant_path is None or not grant_path.exists():
        return jsonify({"error": "invalid_grant"}), 400
    grant = json.loads(grant_path.read_text())
    if grant.get("used"):
        return jsonify({"error": "invalid_grant", "error_description": "authorization code already used"}), 400
    if _is_expired(grant.get("expires_at", "")):
        grant["used"] = True
        grant["used_at"] = _oauth_timestamp()
        grant["error"] = "expired"
        grant_path.write_text(json.dumps(grant, ensure_ascii=False, indent=2))
        return jsonify({"error": "invalid_grant", "error_description": "authorization code expired"}), 400
    if not request.form.get("client_id") or request.form.get("client_id") != grant.get("client_id"):
        return jsonify({"error": "invalid_client"}), 400
    if not request.form.get("redirect_uri") or request.form.get("redirect_uri") != grant.get("redirect_uri"):
        return jsonify({"error": "invalid_grant"}), 400
    if grant.get("code_challenge"):
        if not _verify_pkce(
            request.form.get("code_verifier", ""),
            grant.get("code_challenge", ""),
            grant.get("code_challenge_method", "plain"),
        ):
            return jsonify({"error": "invalid_grant", "error_description": "PKCE verification failed"}), 400
    token = secrets.token_urlsafe(32)
    grant["used"] = True
    grant["used_at"] = _oauth_timestamp()
    grant["access_token"] = token
    grant["token_issued_at"] = _oauth_timestamp()
    grant["access_token_expires_at"] = _oauth_timestamp(OAUTH_ACCESS_TOKEN_TTL_SECONDS)
    grant_path.write_text(json.dumps(grant, ensure_ascii=False, indent=2))
    _save_access_token(token, grant)
    response = {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "scope": grant.get("scope", "openid"),
        "authorization_details": grant.get("authorization_details", []),
        "agent_policy": grant.get("agent_policy", {}),
    }
    if "openid" in str(grant.get("scope", "")).split():
        response["id_token"] = _id_token_for_grant(grant)
    return jsonify(response)


# ── Revocation state ──────────────────────────────────────────────────
# In the real protocol Alice would write the revoked rh into an on-chain
# Merkle tree (RL). The demo backend doesn't run a chain; instead, when the
# user "revokes" a delegation from the wallet UI, we flag the wallet so the
# *next* Agent dispatch is built with --revoked. The verifier then fails the
# "Delegation revocation" check and the order is rejected. This is enough to
# demonstrate the end-to-end revocation effect against the real C++ verifier.
def _load_revocation_state() -> dict:
    if not REVOCATION_STATE_PATH.exists():
        return {"pending": False, "rh": None, "revoked_at": None}
    try:
        return json.loads(REVOCATION_STATE_PATH.read_text())
    except Exception:
        return {"pending": False, "rh": None, "revoked_at": None}


def _save_revocation_state(state: dict):
    REVOCATION_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    REVOCATION_STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2))


@app.route("/api/wallet/revoke", methods=["POST"])
def wallet_revoke():
    body = request.get_json(force=True, silent=True) or {}
    rh = (body.get("rh") or "").strip()
    from datetime import datetime, timezone
    state = {"pending": True, "rh": rh or None,
             "revoked_at": datetime.now(timezone.utc).isoformat()}
    _save_revocation_state(state)
    return jsonify({"ok": True, "state": state,
                    "note": "next agent dispatch will be marked --revoked"})


@app.route("/api/wallet/revoke/status")
def wallet_revoke_status():
    return jsonify(_load_revocation_state())


@app.route("/api/wallet/revoke/clear", methods=["POST"])
def wallet_revoke_clear():
    _save_revocation_state({"pending": False, "rh": None, "revoked_at": None})
    return jsonify({"ok": True})


def _fetch_catalog() -> list:
    """Return TripGo's hotel catalog as a list (used by /api/catalog and the
    LLM system prompt). trust_env=False bypasses a local Clash/V2Ray proxy."""
    s = requests.Session(); s.trust_env = False
    r = s.get(f"{TRIPGO_BASE}/api/catalog", timeout=10, verify=_outbound_tls_verify())
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("hotels", [])


@app.route("/api/catalog")
def catalog_proxy():
    try:
        s = requests.Session(); s.trust_env = False
        r = s.get(f"{TRIPGO_BASE}/api/catalog", timeout=10,
                  verify=_outbound_tls_verify())
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except requests.RequestException as e:
        return jsonify({"error": f"TripGo unreachable: {e}"}), 502


# ── LLM config + chat proxy ─────────────────────────────────────────────────

def _load_llm_config() -> dict:
    """Effective LLM config: env defaults overlaid by data/wallet/llm_config.json."""
    cfg = dict(LLM_ENV_DEFAULTS)
    if LLM_CONFIG_PATH.exists():
        try:
            saved = json.loads(LLM_CONFIG_PATH.read_text())
            for k in ("provider", "api_base", "model", "api_key"):
                if saved.get(k):
                    cfg[k] = saved[k]
        except Exception:
            pass
    return cfg


def _save_llm_config(patch: dict):
    cfg = {}
    if LLM_CONFIG_PATH.exists():
        try:
            cfg = json.loads(LLM_CONFIG_PATH.read_text())
        except Exception:
            cfg = {}
    for k in ("provider", "api_base", "model"):
        if patch.get(k) is not None:
            cfg[k] = patch[k]
    # Only overwrite the key when a new non-empty value is supplied.
    if patch.get("api_key"):
        cfg["api_key"] = patch["api_key"]
    LLM_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LLM_CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))


@app.route("/api/llm/config", methods=["GET", "POST"])
def llm_config():
    if request.method == "POST":
        body = request.get_json(force=True, silent=True) or {}
        _save_llm_config(body)
    cfg = _load_llm_config()
    # Never echo the key back; expose only whether one is configured.
    return jsonify({
        "provider": cfg["provider"],
        "api_base": cfg["api_base"],
        "model": cfg["model"],
        "has_key": bool(cfg["api_key"]),
    })


# ── Agent profiles (档案): each profile is a named Agent with its own set of
# claims it is allowed to disclose. allowed_claims is enforced end-to-end: it
# becomes the delegation policy passed to alice_delegate, so the ZK circuit's
# "Policy claims" check rejects any disclosure outside the list. ────────────

# Seeded on first run so the demo is immediately usable and illustrates the
# core property (different agents → different permissions).
_DEFAULT_PROFILES = [
    {"id": "agent-travel", "name": "出行助手", "agent_id": "travel-agent",
     "allowed_claims": ["age_over_18"], "predicates": [],
     "expires": "2027-01-01T00:00:00Z",
     "desc": "只能证明你已年满 18 岁,用于预订 18+ 酒店。"},
    {"id": "agent-kyc", "name": "实名助手", "agent_id": "kyc-agent",
     "allowed_claims": ["family_name"], "predicates": [],
     "expires": "2027-01-01T00:00:00Z",
     "desc": "只能证明你的姓氏,无法得知你的年龄。"},
]


def _load_profiles() -> list:
    if not PROFILES_PATH.exists():
        _save_profiles(_DEFAULT_PROFILES)
        return list(_DEFAULT_PROFILES)
    try:
        data = json.loads(PROFILES_PATH.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_profiles(profiles: list):
    PROFILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROFILES_PATH.write_text(json.dumps(profiles, ensure_ascii=False, indent=2))


def _profile_by_id(pid: str) -> dict | None:
    return next((p for p in _load_profiles() if p.get("id") == pid), None)


@app.route("/api/profiles", methods=["GET", "POST"])
def profiles():
    if request.method == "POST":
        body = request.get_json(force=True, silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400
        # Validate against the holder's claim aliases (the short names that
        # alice_delegate --claim expects), not the long supported_claims labels.
        holder_claims = _read_holder_claims()
        allowed = [c for c in (body.get("allowed_claims") or []) if c in holder_claims]
        items = _load_profiles()
        pid = body.get("id")
        prof = {
            "id": pid or ("agent-" + secrets.token_hex(4)),
            "name": name,
            "agent_id": (body.get("agent_id") or "").strip() or
                        ("agent-" + secrets.token_hex(3)),
            "allowed_claims": allowed,
            "predicates": body.get("predicates") or [],
            "expires": body.get("expires") or "2027-01-01T00:00:00Z",
            "desc": (body.get("desc") or "").strip(),
        }
        if pid and any(p["id"] == pid for p in items):
            items = [prof if p["id"] == pid else p for p in items]
        else:
            items.append(prof)
        _save_profiles(items)
        return jsonify(prof)
    return jsonify(_load_profiles())


@app.route("/api/profiles/<pid>", methods=["DELETE"])
def delete_profile(pid):
    items = [p for p in _load_profiles() if p.get("id") != pid]
    _save_profiles(items)
    return jsonify({"ok": True})


# Tool the model can call to trigger a real ZK delegated booking.
_BOOK_HOTEL_TOOL = {
    "name": "book_hotel",
    "description": (
        "Book a hotel on behalf of the user via the anonymous ZK delegation flow. "
        "Use this whenever the user asks to book/reserve a hotel. The booking runs "
        "a zero-knowledge proof so the merchant learns only the disclosed claims, "
        "never the user's real identity."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "hotel_query": {
                "type": "string",
                "description": "Hotel name or keyword the user mentioned, e.g. '外滩璞丽'.",
            },
            "claims": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Claims to disclose/prove, e.g. ['age_over_18']. Defaults to age_over_18.",
            },
        },
        "required": ["hotel_query"],
    },
}


def _match_hotel(query: str, catalog: list) -> dict | None:
    if not query:
        return None
    q = str(query).strip().lower()
    for h in catalog:
        name = str(h.get("name", "")).lower()
        if q in name or name in q:
            return h
    # Looser fallback: any shared non-trivial substring.
    for h in catalog:
        name = str(h.get("name", "")).lower()
        if any(tok and tok in name for tok in q.split()):
            return h
    return None


def _llm_system_prompt(catalog: list, holder_claims: list[str], profile: dict | None) -> str:
    lines = [f"- id={h.get('id')} {h.get('name')} ¥{h.get('price')}"
             + (" [18+]" if h.get("age") else "") for h in catalog]
    allowed = (profile or {}).get("allowed_claims") or []
    agent_name = (profile or {}).get("name") or "隐私 Agent"
    return (
        f"你是名为「{agent_name}」的 ZK-AgentAuth 隐私 Agent。你代表用户与商家交互,"
        "但通过零知识证明,商家只能得知被授权披露的属性,无法回溯用户真实身份。\n"
        f"用户钱包持有的属性: {', '.join(holder_claims) or '(无)'}。\n"
        f"⚠️ 本 Agent 仅被授权披露这些属性: {', '.join(allowed) or '(无)'}。"
        "你绝不能尝试披露授权之外的属性;若用户要求披露未授权属性,礼貌拒绝并说明本 Agent 的权限范围。\n"
        "可预订的酒店目录:\n" + "\n".join(lines) + "\n"
        "当用户想订酒店时,调用 book_hotel 工具(传 hotel_query 和需要披露的 claims,claims 必须是上面授权列表的子集)。"
        "若酒店标注 [18+] 但本 Agent 未被授权 age_over_18,则无法预订,需如实告知用户。其他问题正常用中文回答。"
    )


def _call_openai(cfg, messages, tools):
    s = requests.Session(); s.trust_env = False
    body = {"model": cfg["model"], "messages": messages}
    if tools:
        body["tools"] = [{"type": "function", "function": t} for t in tools]
    r = s.post(f"{cfg['api_base'].rstrip('/')}/chat/completions",
               headers={"Authorization": f"Bearer {cfg['api_key']}",
                        "Content-Type": "application/json"},
               json=body, timeout=120, verify=_outbound_tls_verify())
    r.raise_for_status()
    choice = r.json()["choices"][0]["message"]
    text = choice.get("content") or ""
    tool_calls = []
    for tc in (choice.get("tool_calls") or []):
        fn = tc.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except Exception:
            args = {}
        tool_calls.append({"name": fn.get("name"), "args": args})
    return text, tool_calls


def _call_anthropic(cfg, messages, tools):
    s = requests.Session(); s.trust_env = False
    system = ""
    conv = []
    for m in messages:
        if m["role"] == "system":
            system += m["content"] + "\n"
        else:
            conv.append({"role": m["role"], "content": m["content"]})
    body = {"model": cfg["model"], "max_tokens": 1024, "messages": conv}
    if system:
        body["system"] = system
    if tools:
        body["tools"] = [{"name": t["name"], "description": t["description"],
                          "input_schema": t["parameters"]} for t in tools]
    r = s.post(f"{cfg['api_base'].rstrip('/')}/messages",
               headers={"x-api-key": cfg["api_key"],
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"},
               json=body, timeout=120, verify=_outbound_tls_verify())
    r.raise_for_status()
    text, tool_calls = "", []
    for block in r.json().get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
        elif block.get("type") == "tool_use":
            tool_calls.append({"name": block.get("name"), "args": block.get("input") or {}})
    return text, tool_calls


@app.route("/api/chat", methods=["POST"])
def chat():
    cfg = _load_llm_config()
    if not cfg["api_key"]:
        return jsonify({"error": "LLM 未配置,请在「模型」面板填写 API Key"}), 400
    body = request.get_json(force=True, silent=True) or {}
    user_messages = body.get("messages") or []
    if body.get("model"):
        cfg = {**cfg, "model": body["model"]}

    # The conversation is bound to an Agent profile (档案). Its allowed_claims
    # are enforced below, not merely suggested to the model.
    profile = _profile_by_id(body.get("agent") or "") if body.get("agent") else None
    allowed = (profile or {}).get("allowed_claims") or []

    try:
        catalog = _fetch_catalog()
    except requests.RequestException:
        catalog = []
    holder_claims = _read_holder_claims()
    messages = [{"role": "system", "content": _llm_system_prompt(catalog, holder_claims, profile)}]
    messages += [{"role": m["role"], "content": m["content"]} for m in user_messages
                 if m.get("role") in ("user", "assistant") and m.get("content")]

    try:
        if cfg["provider"] == "anthropic":
            text, tool_calls = _call_anthropic(cfg, messages, [_BOOK_HOTEL_TOOL])
        else:
            text, tool_calls = _call_openai(cfg, messages, [_BOOK_HOTEL_TOOL])
    except requests.RequestException as e:
        return jsonify({"error": f"LLM 调用失败: {e}"}), 502

    tool_invocation = None
    for call in tool_calls:
        if call["name"] != "book_hotel":
            continue
        hotel = _match_hotel(call["args"].get("hotel_query", ""), catalog)
        if not hotel:
            text = (text + "\n\n" if text else "") + \
                f"抱歉,没找到「{call['args'].get('hotel_query','')}」对应的酒店。"
            break
        requested = call["args"].get("claims") or (allowed[:1] if allowed else ["age_over_18"])
        # Hard enforcement: the Agent may only disclose claims in its policy.
        if profile is not None:
            forbidden = [c for c in requested if c not in allowed]
            if forbidden:
                text = (text + "\n\n" if text else "") + (
                    f"⚠️ 本 Agent「{profile.get('name')}」无权证明 {', '.join(forbidden)},"
                    f"它只被授权披露: {', '.join(allowed) or '(无)'}。已拒绝本次下单。")
                break
            claims = [c for c in requested if c in allowed]
            if not claims:
                text = (text + "\n\n" if text else "") + \
                    f"⚠️ 本 Agent「{profile.get('name')}」没有可披露的授权属性,无法完成预订。"
                break
        else:
            claims = requested
        # ZK spec currently supports at most 2 disclosed claims per proof.
        claims = claims[:2]
        if not _holder_present():
            return jsonify({"error": "no mDoc on wallet — call /api/wallet/reissue first"}), 400
        dispatch_body = {"hotel_id": hotel["id"], "claims": claims}
        if profile is not None:
            dispatch_body["agent_id"] = profile.get("agent_id")
            dispatch_body["expires"] = profile.get("expires")
            if profile.get("predicates"):
                dispatch_body["predicates"] = profile["predicates"]
        try:
            params = _build_dispatch_params(dispatch_body)
        except (json.JSONDecodeError, ValueError) as e:
            return jsonify({"error": str(e)}), 400
        task = _dispatch_task(params)
        tool_invocation = {"task_id": task.id, "hotel_name": hotel.get("name"),
                           "hotel_id": hotel["id"], "claims": claims,
                           "agent": (profile or {}).get("name")}
        if not text:
            text = (f"好的,正在以「{(profile or {}).get('name','隐私 Agent')}」身份通过零知识证明"
                    f"为你预订「{hotel.get('name')}」,仅披露 {', '.join(claims)},商家不会得知你的真实身份。")
        break

    return jsonify({"reply": text, "tool_invocation": tool_invocation})


def _build_dispatch_params(body: dict) -> dict:
    """Assemble agent_runner.dispatch params from a request body.

    Shared by /api/agent/dispatch (manual) and /api/chat (LLM tool call) so the
    pending-revocation consume-on-use semantics and policy defaults stay in one
    place. Raises ValueError on invalid authorization_details / missing hotel_id.
    """
    authorization_details, agent_policy = _agent_policy_from_authorization_details(
        body.get("authorization_details"), body.get("client_id", "")
    )
    # Pending revocation (set by the wallet UI's "撤销委托" button) takes
    # precedence over the dispatch body's revoked flag. Consume-on-use: read
    # the flag, clear it, then mark THIS dispatch as revoked so the verifier
    # returns "Delegation revocation: FAIL" and the order is rejected.
    rev_state = _load_revocation_state()
    revoked_pending = bool(rev_state.get("pending"))
    if revoked_pending:
        _save_revocation_state({"pending": False, "rh": None, "revoked_at": None})

    default_checkin, default_checkout = _default_stay_dates()
    params = {
        "hotel_id": int(body.get("hotel_id") or agent_policy.get("hotel_id") or 0),
        "checkin": body.get("checkin") or agent_policy.get("checkin") or default_checkin,
        "checkout": body.get("checkout") or agent_policy.get("checkout") or default_checkout,
        "claims": body.get("claims") or agent_policy.get("allowed_claims") or ["age_over_18"],
        # Optional generic predicates, each as "claim:OP:value"
        # (DISCLOSE / EQ / IN_SET / GE / LE). Empty → only basic claim disclosure.
        "predicates": body.get("predicates") or agent_policy.get("predicates") or [],
        "expires": body.get("expires") or agent_policy.get("expires") or "2027-01-01T00:00:00Z",
        "agent_id": body.get("agent_id") or agent_policy.get("agent_id") or "tripgo-agent",
        "authorization_details": authorization_details,
        "agent_policy": agent_policy,
        # When true, Alice writes a pre-revoked delegation_revocation_status.json;
        # used for negative-path demos of the "Delegation revocation" check.
        "revoked": revoked_pending or bool(body.get("revoked")),
    }
    if not params["hotel_id"]:
        raise ValueError("hotel_id required")
    return params


def _dispatch_task(params: dict):
    return agent_runner.dispatch(
        params=params,
        holder_dir=HOLDER_DIR,
        issuer_public_dir=ISSUER_PUBLIC_DIR,
        tasks_dir=TASKS_DIR,
        tripgo_base=TRIPGO_BASE,
    )


@app.route("/api/agent/dispatch", methods=["POST"])
def agent_dispatch():
    body = request.get_json(force=True, silent=True) or {}
    if not _holder_present():
        return jsonify({"error": "no mDoc on wallet — call /api/wallet/reissue first"}), 400
    try:
        params = _build_dispatch_params(body)
    except (json.JSONDecodeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    task = _dispatch_task(params)
    return jsonify({"task_id": task.id})


@app.route("/api/agent/task/<tid>")
def agent_task(tid):
    task = agent_runner.get_task(tid)
    if not task:
        return jsonify({"error": "not found"}), 404
    return jsonify({**task.to_summary(), "events": task.events})


@app.route("/api/agent/task/<tid>/stream")
def agent_task_stream(tid):
    task = agent_runner.get_task(tid)
    if not task:
        return jsonify({"error": "not found"}), 404
    q = task.subscribe()

    @stream_with_context
    def gen():
        try:
            yield ": stream open\n\n"
            while True:
                try:
                    ev = q.get(timeout=30)
                except Empty:
                    yield ": ping\n\n"
                    continue
                if ev is None:
                    break
                yield f"event: {ev['phase']}\ndata: {_json.dumps(ev, ensure_ascii=False)}\n\n"
                if ev["phase"] in ("done", "failed"):
                    break
        finally:
            task.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/agent/history")
def agent_history():
    return jsonify(agent_runner.list_tasks(50))


@app.route("/api/agent/log")
def agent_log():
    # Persisted, real ZK presentation log (survives restart). Enriched with the
    # Agent's display name from profiles when available.
    name_by_agent_id = {p.get("agent_id"): p.get("name") for p in _load_profiles()}
    entries = agent_runner.read_log(TASKS_DIR, 100)
    for e in entries:
        e["agent_name"] = name_by_agent_id.get(e.get("agent_id")) or e.get("agent_id")
    return jsonify(entries)


def main():
    DATA.mkdir(exist_ok=True)
    TASKS_DIR.mkdir(parents=True, exist_ok=True)
    bootstrap_if_needed()
    ssl_context = "adhoc" if USE_HTTPS else None
    print(f"[wallet] listening on {DEFAULT_SCHEME}://localhost:{PORT}", flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False,
            ssl_context=ssl_context)


if __name__ == "__main__":
    main()
