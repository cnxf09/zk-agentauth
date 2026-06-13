"""TripGo Server (Verifier) — port 8003.

Holds: issuer_public/ (public keys only).
Serves Service UI at /, exposes /api/catalog, /api/order/human, /api/agent/order.
"""
from __future__ import annotations
import base64
import json
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context
from queue import Empty
import io
import zipfile
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verifier  # noqa: E402
from feed import FEED  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CATALOG_PATH = DATA / "tripgo" / "catalog.json"
ORDERS_PATH = DATA / "tripgo" / "orders.json"
ISSUER_PUBLIC_DIR = DATA / "shared" / "issuer_public"
TASKS_DIR = DATA / "tripgo" / "tasks"
STATIC_DIR = Path(__file__).resolve().parent / "static"
SCHEMAS_DIR = ROOT / "schemas"
PROFILES_DIR = ROOT / "profiles"
VERIFIER_SIGNING_KEY_PATH = DATA / "tripgo" / "oid4vp_verifier_signing_key.pem"

PORT = int(os.environ.get("TRIPGO_PORT", "8003"))
USE_HTTPS = os.environ.get("USE_HTTPS") == "1"
DEFAULT_SCHEME = "https" if USE_HTTPS else "http"
VERIFIER_ISSUER = os.environ.get("TRIPGO_ISSUER", f"{DEFAULT_SCHEME}://localhost:{PORT}")
VERIFIER_KEY_ID = os.environ.get("TRIPGO_OID4VP_KEY_ID", "tripgo-verifier-rs256-1")
AGENT_DELEGATION_AUTHZ_TYPE = "https://zk-agentauth.local/authorization/agent-delegation"
ZKAA_LIGERO_PROFILE = "https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1"
AGENT_DELEGATION_AUTHZ_TYPE_ALIASES = {
    AGENT_DELEGATION_AUTHZ_TYPE,
    "agent_delegation",
    "zkaa_agent_delegation",
    "agent_policy",
}


def _load_orders() -> list:
    if not ORDERS_PATH.exists():
        return []
    try:
        return json.loads(ORDERS_PATH.read_text())
    except Exception:
        return []


def _save_order(order: dict):
    orders = _load_orders()
    orders.append(order)
    ORDERS_PATH.write_text(json.dumps(orders, ensure_ascii=False, indent=2))


def _load_catalog() -> list:
    return json.loads(CATALOG_PATH.read_text())


def _new_order_id(prefix: str) -> str:
    return f"TG-{prefix}-{uuid.uuid4().hex[:6].upper()}"


def _default_stay_dates() -> tuple[str, str]:
    today = datetime.now().astimezone().date()
    return (
        today.isoformat(),
        (today + timedelta(days=1)).isoformat(),
    )


def _stay_nights(checkin: str, checkout: str) -> int:
    try:
        start = datetime.strptime(checkin, "%Y-%m-%d").date()
        end = datetime.strptime(checkout, "%Y-%m-%d").date()
    except ValueError:
        return 1
    return max((end - start).days, 1)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))


def _load_verifier_private_key():
    VERIFIER_SIGNING_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if VERIFIER_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            VERIFIER_SIGNING_KEY_PATH.read_bytes(),
            password=None,
        )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    VERIFIER_SIGNING_KEY_PATH.write_bytes(pem)
    VERIFIER_SIGNING_KEY_PATH.chmod(0o600)
    return private_key


def _verifier_public_jwk() -> dict:
    public_numbers = _load_verifier_private_key().public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": VERIFIER_KEY_ID,
        "alg": "RS256",
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }


def _jwt_rs256(claims: dict) -> str:
    header = {"typ": "oauth-authz-req+jwt", "alg": "RS256", "kid": VERIFIER_KEY_ID}
    signing_input = ".".join([
        _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")),
    ]).encode("ascii")
    signature = _load_verifier_private_key().sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signing_input.decode("ascii") + "." + _b64url(signature)


def _unix_time(value: datetime | None = None) -> int:
    return int((value or datetime.now(timezone.utc)).timestamp())


def _signed_oid4vp_request(request_object: dict) -> str:
    now = datetime.now(timezone.utc)
    signed_claims = dict(request_object)
    signed_claims.update({
        "iss": VERIFIER_ISSUER,
        "aud": "https://self-issued.me/v2/openid-vc",
        "iat": _unix_time(now),
        "exp": _unix_time(now + timedelta(minutes=5)),
    })
    return _jwt_rs256(signed_claims)


def _json_body() -> dict:
    return request.get_json(force=True, silent=True) or {}


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


def _agent_policy_from_authorization_details(value) -> tuple[list[dict], dict]:
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
    return details, {
        "agent_id": nested.get("agent_id") or detail.get("agent_id"),
        "allowed_claims": claims if isinstance(claims, list) else [claims],
        "predicates": predicates if isinstance(predicates, list) else [predicates],
        "expires": nested.get("expires") or detail.get("expires"),
        "verifier": nested.get("verifier") or detail.get("verifier"),
    }


def _safe_extract_zip(zip_bytes: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"unsafe zip member: {info.filename}")
        z.extractall(dest)


def _zip_dir_bytes(src: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src.iterdir()):
            if f.is_file():
                z.write(f, f.name)
    return buf.getvalue()


def _build_presentation_definition(claims: list[str]) -> dict:
    return {
        "id": "tripgo-zkaa-agentauth",
        "name": "TripGo ZK-AgentAuth presentation definition",
        "purpose": "Prove delegated authority and selected claims with a ZK-AgentAuth Ligero presentation.",
        "input_descriptors": [
            {
                "id": "zkaa-ligero-presentation",
                "name": "ZK-AgentAuth delegated presentation",
                "purpose": "Submit one zkaa+ligero VP token bound to this OID4VP request nonce and state.",
                "format": {
                    "zkaa+ligero": {
                        "alg": ["SM2/SM3+Ligero"],
                        "profile": ZKAA_LIGERO_PROFILE,
                        "encoding": "application/zip;base64",
                        "proof_type": "LigeroV2",
                        "proof_files": [
                            "proof.bin",
                            "public_delegation.json",
                            "delegation_revocation_status.json"
                        ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "id": f"claim-{claim}",
                            "path": [
                                f"$.vp_token.claims[?(@ == '{claim}')]",
                                f"$.vp_token.claims.{claim}",
                            ],
                            "purpose": f"TripGo requires proof of {claim}",
                        }
                        for claim in claims
                    ]
                },
            }
        ],
    }


def _create_reader_request(
    claims: list[str],
    predicates: list[str] | None = None,
    state: str | None = None,
    authorization_details: list[dict] | None = None,
) -> tuple[str, str, Path, dict, bytes]:
    if not ISSUER_PUBLIC_DIR.exists():
        raise RuntimeError("issuer_public not provisioned")
    predicates = predicates or []
    request_id = uuid.uuid4().hex[:10]
    state = state or request_id
    req_dir = TASKS_DIR / request_id / "request"
    verifier.request(
        issuer_public=ISSUER_PUBLIC_DIR,
        claims=claims,
        out_dir=req_dir,
        predicates=predicates,
    )
    oid4vp_request = json.loads((req_dir / "openid4vp_request.json").read_text())
    oid4vp_request.update({
        "client_id": VERIFIER_ISSUER,
        "client_id_scheme": "redirect_uri",
        "response_mode": "direct_post",
        "response_uri": f"{VERIFIER_ISSUER}/oid4vp/response",
        "state": state,
        "presentation_definition": _build_presentation_definition(claims),
        "authorization_details": authorization_details or [],
        "zkaa_request_id": request_id,
        "client_metadata_uri": f"{VERIFIER_ISSUER}/.well-known/oid4vp-verifier",
    })
    oid4vp_request["request_object_jwt"] = _signed_oid4vp_request(oid4vp_request)
    metadata = {
        "request_id": request_id,
        "state": state,
        "claims": claims,
        "predicates": predicates,
        "authorization_details": authorization_details or [],
        "request_object_jwt": oid4vp_request["request_object_jwt"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "consumed": False,
    }
    (TASKS_DIR / request_id).mkdir(parents=True, exist_ok=True)
    (TASKS_DIR / request_id / "oid4vp_request.json").write_text(
        json.dumps(oid4vp_request, ensure_ascii=False, indent=2)
    )
    (TASKS_DIR / request_id / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2)
    )
    return request_id, state, req_dir, oid4vp_request, _zip_dir_bytes(req_dir)


def _resolve_request_dir(state_or_request_id: str) -> Path | None:
    if not state_or_request_id:
        return None
    direct = TASKS_DIR / state_or_request_id / "request"
    if direct.exists():
        return direct
    for meta_path in TASKS_DIR.glob("*/metadata.json"):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        if meta.get("state") == state_or_request_id or meta.get("request_id") == state_or_request_id:
            req_dir = meta_path.parent / "request"
            return req_dir if req_dir.exists() else None
    return None


def _resolve_request_metadata(state_or_request_id: str) -> tuple[Path, dict] | tuple[None, None]:
    if not state_or_request_id:
        return None, None
    direct = TASKS_DIR / state_or_request_id / "metadata.json"
    if direct.exists():
        try:
            return direct, json.loads(direct.read_text())
        except Exception:
            return direct, {}
    for meta_path in TASKS_DIR.glob("*/metadata.json"):
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        if meta.get("state") == state_or_request_id or meta.get("request_id") == state_or_request_id:
            return meta_path, meta
    return None, None


def _mark_oid4vp_consumed(meta_path: Path, meta: dict, order_id: str, result: dict | None = None):
    meta["consumed"] = True
    meta["consumed_at"] = datetime.now(timezone.utc).isoformat()
    meta["consumed_order_id"] = order_id
    if result is not None:
        meta["consumed_result"] = {
            "accepted": bool(result.get("accepted")),
            "overall": (result.get("checks") or {}).get("overall"),
        }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2))


def _read_claims_from_request_dir(request_dir: Path) -> list[str]:
    request_json = request_dir / "openid4vp_request.json"
    if not request_json.exists():
        return ["age_over_18"]
    try:
        data = json.loads(request_json.read_text())
        return [c["alias"] for c in data.get("claims", []) if c.get("alias")] or ["age_over_18"]
    except Exception:
        return ["age_over_18"]


def _validate_presentation_submission(body: dict) -> str | None:
    submission = body.get("presentation_submission") or {}
    if not isinstance(submission, dict):
        return "presentation_submission must be an object"
    if submission.get("definition_id") != "tripgo-zkaa-agentauth":
        return "presentation_submission.definition_id must be tripgo-zkaa-agentauth"
    descriptor_map = submission.get("descriptor_map")
    if not isinstance(descriptor_map, list) or not descriptor_map:
        return "presentation_submission.descriptor_map must be a non-empty array"
    descriptor = next(
        (
            item for item in descriptor_map
            if isinstance(item, dict)
            and item.get("id") == "zkaa-ligero-presentation"
        ),
        None,
    )
    if descriptor is None:
        return "descriptor_map missing zkaa-ligero-presentation"
    if descriptor.get("format") != "zkaa+ligero":
        return "descriptor_map format must be zkaa+ligero"
    if descriptor.get("path") != "$.vp_token":
        return "descriptor_map path must be $.vp_token"
    nested = descriptor.get("path_nested") or {}
    if not isinstance(nested, dict):
        return "descriptor_map.path_nested must be an object"
    if nested.get("path") != "$.vp_token.presentation_zip_b64":
        return "descriptor_map.path_nested.path must point to vp_token.presentation_zip_b64"
    return None


app = Flask(__name__, static_folder=None)


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:fname>")
def static_files(fname):
    return send_from_directory(STATIC_DIR, fname)


@app.route("/profiles/<path:fname>")
def profile_files(fname):
    return send_from_directory(PROFILES_DIR, fname)


@app.route("/profiles/vp-token/zkaa-ligero-v1")
def zkaa_ligero_profile():
    return send_from_directory(PROFILES_DIR / "vp-token", "zkaa-ligero-v1.md",
                               mimetype="text/markdown")


@app.route("/.well-known/oid4vp-verifier")
def oid4vp_verifier_metadata():
    return jsonify({
        "issuer": VERIFIER_ISSUER,
        "client_id": VERIFIER_ISSUER,
        "jwks_uri": f"{VERIFIER_ISSUER}/oid4vp/jwks.json",
        "request_object_signing_alg_values_supported": ["RS256"],
        "authorization_signed_response_alg_values_supported": ["RS256"],
        "response_modes_supported": ["direct_post"],
        "vp_formats_supported": {
            "zkaa+ligero": {
                "profile": ZKAA_LIGERO_PROFILE,
                "encoding": "application/zip;base64",
                "proof_type": "LigeroV2",
                "proof_files": [
                    "proof.bin",
                    "public_delegation.json",
                    "delegation_revocation_status.json",
                ],
            }
        },
        "presentation_definition_supported": True,
        "presentation_definition_uri": f"{VERIFIER_ISSUER}/oid4vp/request",
        "direct_post_endpoint": f"{VERIFIER_ISSUER}/oid4vp/response",
    })


@app.route("/oid4vp/jwks.json")
def oid4vp_jwks():
    return jsonify({"keys": [_verifier_public_jwk()]})


@app.route("/api/catalog")
def catalog():
    return jsonify(_load_catalog())


@app.route("/api/orders/<order_id>")
def order_detail(order_id):
    for o in _load_orders():
        if o.get("order_id") == order_id:
            return jsonify(o)
    return jsonify({"error": "not found"}), 404


@app.route("/api/order/human", methods=["POST"])
def order_human():
    body = request.get_json(force=True, silent=True) or {}
    default_checkin, default_checkout = _default_stay_dates()
    hotel_id = body.get("hotel_id")
    catalog = _load_catalog()
    hotel = next((h for h in catalog if h["id"] == hotel_id), None)
    if not hotel:
        return jsonify({"error": "hotel not found"}), 404
    order = {
        "order_id": _new_order_id("H"),
        "channel": "human",
        "hotel_id": hotel_id,
        "hotel_name": hotel["name"],
        "checkin": body.get("checkin") or default_checkin,
        "checkout": body.get("checkout") or default_checkout,
        "contact_name": body.get("contact_name", ""),
        "phone": body.get("phone", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "ACCEPT",
    }
    order["amount"] = hotel["price"] * _stay_nights(order["checkin"], order["checkout"])
    _save_order(order)
    return jsonify(order)


@app.route("/api/agent/request", methods=["POST"])
def agent_request():
    """Server-to-server: Wallet Server asks for a reader request.

    Optional `predicates` (list of "claim:OP:value" strings) are passed
    through verbatim so the resulting reader_request binds the same
    predicate set the prover used.
    """
    body = _json_body()
    claims = body.get("claims") or ["age_over_18"]
    predicates = body.get("predicates") or []
    try:
        req_id, _, _, _, zip_bytes = _create_reader_request(claims, predicates)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return Response(zip_bytes, mimetype="application/zip",
                    headers={"X-Request-Id": req_id})


@app.route("/oid4vp/request", methods=["GET", "POST"])
def oid4vp_request():
    """OpenID4VP-style request object for delegated ZK-AgentAuth proof."""
    if request.method == "POST":
        body = _json_body()
        try:
            authorization_details, agent_policy = _agent_policy_from_authorization_details(
                body.get("authorization_details")
            )
        except (json.JSONDecodeError, ValueError) as e:
            return jsonify({"error": f"invalid authorization_details: {e}"}), 400
        claims = body.get("claims") or agent_policy.get("allowed_claims") or ["age_over_18"]
        predicates = body.get("predicates") or agent_policy.get("predicates") or []
        state = body.get("state")
    else:
        claims_q = request.args.get("claims", "age_over_18")
        claims = [c.strip() for c in claims_q.split(",") if c.strip()]
        predicates_q = request.args.get("predicates", "")
        predicates = [p.strip() for p in predicates_q.split(",") if p.strip()]
        state = request.args.get("state")
        try:
            authorization_details, _ = _agent_policy_from_authorization_details(
                request.args.get("authorization_details")
            )
        except (json.JSONDecodeError, ValueError) as e:
            return jsonify({"error": f"invalid authorization_details: {e}"}), 400
    try:
        req_id, state, _, oid4vp_req, zip_bytes = _create_reader_request(
            claims, predicates, state, authorization_details
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({
        "request_id": req_id,
        "state": state,
        "request": oid4vp_req,
        "request_object_jwt": oid4vp_req.get("request_object_jwt"),
        "reader_request_zip_b64": base64.b64encode(zip_bytes).decode("ascii"),
    })


def _parse_verify_output(out: str) -> dict:
    """Parse the PASS/FAIL lines + Overall.

    delegation_demo_verifier emits 6 protocol-level lines:
      ZK proof / Delegation sig / Policy claims / Policy predicates /
      Policy expiry / Delegation revocation
    plus an Overall line.
    """
    res = {
        "zk_proof": None, "delegation_sig": None,
        "policy_claims": None, "policy_predicates": None,
        "policy_expiry": None, "delegation_revocation": None,
        "overall": None, "raw": out,
    }
    for line in out.splitlines():
        s = line.strip()
        if ":" not in s:
            continue
        k, _, v = s.partition(":")
        kl, vl = k.strip().lower(), v.strip()
        if kl == "zk proof": res["zk_proof"] = vl
        elif kl == "delegation sig": res["delegation_sig"] = vl
        elif kl == "policy claims": res["policy_claims"] = vl
        elif kl == "policy predicates": res["policy_predicates"] = vl
        elif kl == "policy expiry": res["policy_expiry"] = vl
        elif kl == "delegation revocation": res["delegation_revocation"] = vl
        elif kl == "overall": res["overall"] = vl
    return res


def _verify_presentation(order_req: dict, request_dir: Path, presentation_dir: Path,
                         order_id: str) -> tuple[dict, int]:
    claims = order_req.get("claims") or _read_claims_from_request_dir(request_dir)

    public_delegation_path = presentation_dir / "public_delegation.json"
    public_delegation = {}
    if public_delegation_path.exists():
        try:
            public_delegation = json.loads(public_delegation_path.read_text())
        except Exception:
            pass
    proof_size = (presentation_dir / "proof.bin").stat().st_size if (presentation_dir / "proof.bin").exists() else 0

    FEED.publish("incoming",
                 order_id=order_id,
                 hotel_id=order_req.get("hotel_id"),
                 claims=claims,
                 agent_id=order_req.get("agent_id"),
                 proof_size=proof_size,
                 public_delegation=public_delegation,
                 task_id=order_req.get("task_id"))

    verify_lines = []
    try:
        out = verifier.verify(
            issuer_public=ISSUER_PUBLIC_DIR,
            request_dir=request_dir,
            presentation=presentation_dir,
            on_line=lambda l: verify_lines.append(l),
        )
    except RuntimeError as e:
        FEED.publish("verified", order_id=order_id, accepted=False,
                     checks={"raw": str(e)}, error=str(e))
        return {
            "order_id": order_id,
            "accepted": False,
            "checks": {"raw": str(e)},
            "error": str(e),
        }, 200

    checks = _parse_verify_output(out)
    crypto_accepted = checks.get("overall", "").upper() == "ACCEPT"

    catalog = _load_catalog()
    hotel = next((h for h in catalog if h["id"] == order_req.get("hotel_id")), None)

    business_check = "PASS"
    if hotel and hotel.get("age") and "age_over_18" not in claims:
        business_check = "FAIL: 18+ hotel requires age_over_18 in claims_proven"
    checks["business_rule"] = business_check

    accepted = crypto_accepted and business_check == "PASS"
    if not accepted:
        checks["overall"] = "REJECT"

    order = None
    if accepted and hotel:
        default_checkin, default_checkout = _default_stay_dates()
        order = {
            "order_id": order_id,
            "channel": order_req.get("channel", "agent"),
            "hotel_id": hotel["id"],
            "hotel_name": hotel["name"],
            "checkin": order_req.get("checkin") or default_checkin,
            "checkout": order_req.get("checkout") or default_checkout,
            "agent_id": order_req.get("agent_id"),
            "claims_proven": claims,
            "proof_size": proof_size,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "ACCEPT",
        }
        order["amount"] = hotel["price"] * _stay_nights(order["checkin"], order["checkout"])
        _save_order(order)

    FEED.publish("verified",
                 order_id=order_id, accepted=accepted, checks=checks,
                 order=order, hotel=hotel)

    return {
        "order_id": order_id,
        "accepted": accepted,
        "checks": checks,
        "order": order,
    }, 200


@app.route("/api/agent/order", methods=["POST"])
def agent_order():
    """Receive presentation+order, run verifier, create order."""
    if "presentation" not in request.files:
        return jsonify({"error": "missing presentation zip"}), 400
    try:
        order_req = json.loads(request.form.get("order_request", "{}"))
    except Exception:
        return jsonify({"error": "bad order_request"}), 400

    order_id = _new_order_id("A")
    work = TASKS_DIR / order_id
    work.mkdir(parents=True, exist_ok=True)
    presentation_dir = work / "presentation"
    presentation_dir.mkdir(exist_ok=True)
    pres_zip = request.files["presentation"]
    pres_bytes = pres_zip.read()
    try:
        _safe_extract_zip(pres_bytes, presentation_dir)
    except (ValueError, zipfile.BadZipFile) as e:
        return jsonify({"error": f"bad presentation zip: {e}"}), 400

    # Look up the original reader request (TripGo issued it earlier; the prover
    # bound the proof to its session_transcript, so we MUST verify against the
    # same files — re-generating would change the nonce and break merkle_check).
    request_id = order_req.get("request_id", "")
    if not request_id:
        return jsonify({"error": "missing request_id (call /api/agent/request first)"}), 400
    request_dir = _resolve_request_dir(request_id)
    if request_dir is None:
        return jsonify({"error": f"request_id {request_id} not found"}), 400

    result, status = _verify_presentation(order_req, request_dir, presentation_dir, order_id)
    return jsonify(result), status

@app.route("/oid4vp/response", methods=["POST"])
def oid4vp_response():
    """Accept an OpenID4VP direct_post response carrying a ZK-AgentAuth proof."""
    body = _json_body()
    vp_token = body.get("vp_token") or {}
    submission_error = _validate_presentation_submission(body)
    if submission_error:
        return jsonify({"error": submission_error}), 400
    state = body.get("state") or vp_token.get("state") or body.get("request_id")
    if not state:
        return jsonify({"error": "missing state"}), 400

    meta_path, meta = _resolve_request_metadata(state)
    if meta_path is None:
        return jsonify({"error": f"state/request_id {state} not found"}), 400
    if meta.get("consumed"):
        return jsonify({
            "error": "replay_detected",
            "state": state,
            "request_id": meta.get("request_id"),
            "consumed_at": meta.get("consumed_at"),
            "consumed_order_id": meta.get("consumed_order_id"),
        }), 409

    request_dir = meta_path.parent / "request"
    if not request_dir.exists():
        return jsonify({"error": f"request files for state/request_id {state} not found"}), 400

    presentation_zip_b64 = (
        vp_token.get("presentation_zip_b64")
        or body.get("presentation_zip_b64")
        or vp_token.get("zkaa_presentation_zip_b64")
    )
    if not presentation_zip_b64:
        return jsonify({"error": "missing vp_token.presentation_zip_b64"}), 400

    try:
        pres_bytes = base64.b64decode(presentation_zip_b64, validate=True)
    except Exception:
        return jsonify({"error": "bad presentation_zip_b64"}), 400

    order_id = _new_order_id("VP")
    work = TASKS_DIR / order_id
    work.mkdir(parents=True, exist_ok=True)
    presentation_dir = work / "presentation"
    presentation_dir.mkdir(exist_ok=True)
    try:
        _safe_extract_zip(pres_bytes, presentation_dir)
    except (ValueError, zipfile.BadZipFile) as e:
        return jsonify({"error": f"bad presentation zip: {e}"}), 400

    order_req = body.get("order_request") or vp_token.get("order_request") or {}
    order_req.setdefault("claims", vp_token.get("claims") or _read_claims_from_request_dir(request_dir))
    order_req.setdefault("channel", "oid4vp")

    result, status = _verify_presentation(order_req, request_dir, presentation_dir, order_id)
    _mark_oid4vp_consumed(meta_path, meta, order_id, result)
    result.update({
        "state": state,
        "vp_token_format": vp_token.get("format", "zkaa+ligero"),
    })
    return jsonify(result), status


@app.route("/api/agent/feed")
def agent_feed():
    q = FEED.subscribe()

    @stream_with_context
    def gen():
        try:
            yield ": feed open\n\n"
            while True:
                try:
                    ev = q.get(timeout=30)
                except Empty:
                    yield ": ping\n\n"
                    continue
                yield f"event: {ev['kind']}\ndata: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
        finally:
            FEED.unsubscribe(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/agent/feed/history")
def agent_feed_history():
    return jsonify(FEED.history())


def main():
    DATA.mkdir(exist_ok=True)
    TASKS_DIR.mkdir(parents=True, exist_ok=True)
    if not ISSUER_PUBLIC_DIR.exists() or not (ISSUER_PUBLIC_DIR / "issuer_pkx.txt").exists():
        print(f"[tripgo] WARNING: {ISSUER_PUBLIC_DIR} not present yet — start Wallet Server first", flush=True)
    ssl_context = "adhoc" if USE_HTTPS else None
    print(f"[tripgo] listening on {DEFAULT_SCHEME}://localhost:{PORT}", flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False,
            ssl_context=ssl_context)


if __name__ == "__main__":
    main()
