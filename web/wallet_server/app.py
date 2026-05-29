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


@app.route("/api/catalog")
def catalog_proxy():
    try:
        # trust_env=False bypasses HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars
        # (e.g., a local Clash proxy on 7890) for localhost cross-service calls.
        s = requests.Session(); s.trust_env = False
        r = s.get(f"{TRIPGO_BASE}/api/catalog", timeout=10,
                  verify=_outbound_tls_verify())
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except requests.RequestException as e:
        return jsonify({"error": f"TripGo unreachable: {e}"}), 502


@app.route("/api/agent/dispatch", methods=["POST"])
def agent_dispatch():
    body = request.get_json(force=True, silent=True) or {}
    if not _holder_present():
        return jsonify({"error": "no mDoc on wallet — call /api/wallet/reissue first"}), 400
    try:
        authorization_details, agent_policy = _agent_policy_from_authorization_details(
            body.get("authorization_details"), body.get("client_id", "")
        )
    except (json.JSONDecodeError, ValueError) as e:
        return jsonify({"error": f"invalid authorization_details: {e}"}), 400
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
        return jsonify({"error": "hotel_id required"}), 400
    task = agent_runner.dispatch(
        params=params,
        holder_dir=HOLDER_DIR,
        issuer_public_dir=ISSUER_PUBLIC_DIR,
        tasks_dir=TASKS_DIR,
        tripgo_base=TRIPGO_BASE,
    )
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
