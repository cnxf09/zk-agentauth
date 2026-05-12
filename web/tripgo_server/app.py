"""TripGo Server (Verifier) — port 8003.

Holds: issuer_public/ (public keys only).
Serves Service UI at /, exposes /api/catalog, /api/order/human, /api/agent/order.
"""
from __future__ import annotations
import json
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context
from queue import Empty
import io
import zipfile
import tempfile

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

PORT = int(os.environ.get("TRIPGO_PORT", "8003"))


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


app = Flask(__name__, static_folder=None)


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:fname>")
def static_files(fname):
    return send_from_directory(STATIC_DIR, fname)


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
        "checkin": body.get("checkin", "2026-05-10"),
        "checkout": body.get("checkout", "2026-05-12"),
        "contact_name": body.get("contact_name", ""),
        "phone": body.get("phone", ""),
        "amount": hotel["price"] * 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "ACCEPT",
    }
    _save_order(order)
    return jsonify(order)


@app.route("/api/agent/request", methods=["POST"])
def agent_request():
    """Server-to-server: Wallet Server asks for a reader request."""
    body = request.get_json(force=True, silent=True) or {}
    claims = body.get("claims") or ["age_over_18"]
    if not ISSUER_PUBLIC_DIR.exists():
        return jsonify({"error": "issuer_public not provisioned"}), 500
    req_id = uuid.uuid4().hex[:10]
    req_dir = TASKS_DIR / req_id / "request"
    verifier.request(
        issuer_public=ISSUER_PUBLIC_DIR,
        claims=claims,
        out_dir=req_dir,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(req_dir.iterdir()):
            if f.is_file():
                z.write(f, f.name)
    buf.seek(0)
    return Response(buf.read(), mimetype="application/zip",
                    headers={"X-Request-Id": req_id})


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
    with zipfile.ZipFile(io.BytesIO(pres_bytes)) as z:
        z.extractall(presentation_dir)

    # Look up the original reader request (TripGo issued it earlier; the prover
    # bound the proof to its session_transcript, so we MUST verify against the
    # same files — re-generating would change the nonce and break merkle_check).
    claims = order_req.get("claims") or ["age_over_18"]
    request_id = order_req.get("request_id", "")
    if not request_id:
        return jsonify({"error": "missing request_id (call /api/agent/request first)"}), 400
    request_dir = TASKS_DIR / request_id / "request"
    if not request_dir.exists():
        return jsonify({"error": f"request_id {request_id} not found"}), 400

    # Read public delegation input for feed display. Sensitive witness/debug
    # material is intentionally not part of the uploaded presentation.
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

    # Run verifier
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
        return jsonify({"order_id": order_id, "accepted": False,
                        "checks": {"raw": str(e)}, "error": str(e)}), 200

    checks = _parse_verify_output(out)
    crypto_accepted = checks.get("overall", "").upper() == "ACCEPT"

    catalog = _load_catalog()
    hotel = next((h for h in catalog if h["id"] == order_req.get("hotel_id")), None)

    # Business rule: 18+ hotels require age_over_18 to be in claims_proven.
    # The ZK protocol verifies *that the agent is authorized to disclose what it
    # disclosed*; it doesn't enforce the merchant-side requirement that the
    # disclosed claim set is sufficient for this product. Enforce that here.
    business_check = "PASS"
    if hotel and hotel.get("age") and "age_over_18" not in claims:
        business_check = "FAIL: 18+ hotel requires age_over_18 in claims_proven"
    checks["business_rule"] = business_check

    accepted = crypto_accepted and business_check == "PASS"
    # Reflect the combined verdict in the overall field so the client sees REJECT
    # when the merchant rule fails, even if all four crypto checks PASSed.
    if not accepted:
        checks["overall"] = "REJECT"

    order = None
    if accepted and hotel:
        order = {
            "order_id": order_id,
            "channel": "agent",
            "hotel_id": hotel["id"],
            "hotel_name": hotel["name"],
            "checkin": order_req.get("checkin", "2026-05-10"),
            "checkout": order_req.get("checkout", "2026-05-12"),
            "amount": hotel["price"] * 2,
            "agent_id": order_req.get("agent_id"),
            "claims_proven": claims,
            "proof_size": proof_size,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "ACCEPT",
        }
        _save_order(order)

    FEED.publish("verified",
                 order_id=order_id, accepted=accepted, checks=checks,
                 order=order, hotel=hotel)

    return jsonify({"order_id": order_id, "accepted": accepted,
                    "checks": checks, "order": order})


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
    print(f"[tripgo] listening on http://localhost:{PORT}", flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True, debug=False)


if __name__ == "__main__":
    main()
