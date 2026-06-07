"""Agent dispatch task runner — orchestrates the full ZK delegation flow.

A Task progresses through phases: delegating → fetching_request → proving →
posting → done (or failed). Every transition emits an SSE event.
"""
from __future__ import annotations
import base64
import io
import json
import os
import threading
import time
import uuid
import zipfile
from pathlib import Path
from queue import Queue, Empty

import requests

import bins


# Bypass system HTTP_PROXY/HTTPS_PROXY/ALL_PROXY for localhost — many devs run
# a Clash / V2Ray proxy on 127.0.0.1:7890 that 'requests' would otherwise use
# even for loopback. trust_env=False also disables SOCKS env (which would
# otherwise raise "Missing dependencies for SOCKS support").
_HTTP = requests.Session()
_HTTP.trust_env = False

# Long timeouts: the Agent flow includes a ~5s ZK proof on the wallet side and
# a verifier round-trip (~5–30s) on the TripGo side. 5 minutes covers
# slow CI / cold-cache runs without hanging forever on real failures.
_HTTP_TIMEOUT = 300
_HTTP_VERIFY = os.environ.get("ZKAA_TLS_VERIFY", "1") != "0"


_TASKS: dict[str, "Task"] = {}
_TASKS_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()


def _log_path(tasks_dir: Path) -> Path:
    # Persisted, append-only log of every ZK presentation. Survives restart.
    return tasks_dir.parent / "agent_log.jsonl"


def _append_log(tasks_dir: Path, entry: dict):
    try:
        with _LOG_LOCK:
            with _log_path(tasks_dir).open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read_log(tasks_dir: Path, limit: int = 100) -> list[dict]:
    path = _log_path(tasks_dir)
    if not path.exists():
        return []
    out = []
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        return []
    out.reverse()  # newest first
    return out[:limit]


def _safe_extract_zip(zip_bytes: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ValueError(f"unsafe zip member: {info.filename}")
        z.extractall(dest)


def _claims_from_oid4vp_request(request_object: dict, fallback: list[str]) -> list[str]:
    parsed: list[str] = []
    claims = request_object.get("claims")

    if isinstance(claims, list):
        for claim in claims:
            if isinstance(claim, dict):
                alias = claim.get("alias") or claim.get("id") or claim.get("name")
                if alias:
                    parsed.append(str(alias))
            elif isinstance(claim, str):
                parsed.append(claim)

    if not parsed:
        descriptors = (
            (request_object.get("presentation_definition") or {})
            .get("input_descriptors")
            or []
        )
        for descriptor in descriptors:
            fields = ((descriptor.get("constraints") or {}).get("fields") or [])
            for field in fields:
                field_id = field.get("id")
                if isinstance(field_id, str) and field_id.startswith("claim-"):
                    parsed.append(field_id.removeprefix("claim-"))

    deduped: list[str] = []
    for claim in parsed or fallback:
        if claim not in deduped:
            deduped.append(claim)
    return deduped


class Task:
    def __init__(self, params: dict):
        self.id = uuid.uuid4().hex[:12]
        self.params = params
        self.status = "created"
        self.events: list[dict] = []
        self.subs: list[Queue] = []
        self.lock = threading.Lock()
        self.result: dict | None = None
        self.created_at = time.time()
        self.terminal = False

    def emit(self, phase: str, **data):
        ev = {"phase": phase, "data": data, "ts": time.time()}
        with self.lock:
            self.events.append(ev)
            self.status = phase
            if phase in ("done", "failed"):
                self.terminal = True
            for q in list(self.subs):
                q.put(ev)

    def subscribe(self) -> Queue:
        q: Queue = Queue()
        with self.lock:
            for ev in self.events:
                q.put(ev)
            if not self.terminal:
                self.subs.append(q)
            else:
                q.put(None)  # signal end
        return q

    def unsubscribe(self, q: Queue):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "params": self.params,
            "result": self.result,
            "created_at": self.created_at,
            "events": len(self.events),
        }


def get_task(tid: str) -> Task | None:
    with _TASKS_LOCK:
        return _TASKS.get(tid)


def list_tasks(limit: int = 20) -> list[dict]:
    with _TASKS_LOCK:
        items = sorted(_TASKS.values(), key=lambda t: t.created_at, reverse=True)
    return [t.to_summary() for t in items[:limit]]


def dispatch(params: dict, holder_dir: Path, issuer_public_dir: Path,
             tasks_dir: Path, tripgo_base: str) -> Task:
    task = Task(params)
    with _TASKS_LOCK:
        _TASKS[task.id] = task
    threading.Thread(
        target=_run, args=(task, holder_dir, issuer_public_dir, tasks_dir, tripgo_base),
        daemon=True,
    ).start()
    return task


def _run(task: Task, holder_dir: Path, issuer_public_dir: Path,
         tasks_dir: Path, tripgo_base: str):
    p = task.params
    work = tasks_dir / task.id
    work.mkdir(parents=True, exist_ok=True)
    delegation_dir = work / "delegation"
    request_dir = work / "request"
    presentation_dir = work / "presentation"

    try:
        # ── 1. Delegate ─────────────────────────────────────────
        predicates = p.get("predicates") or []
        revoked = bool(p.get("revoked"))
        task.emit("delegating",
                  message="Alice 创建委托 (SM2/SM3 签名)",
                  claims=p["claims"], agent_id=p["agent_id"],
                  expires=p["expires"], predicates=predicates,
                  revoked=revoked)
        bins.alice_delegate(
            holder=holder_dir,
            claims=p["claims"],
            expires_iso=p["expires"],
            agent_id=p["agent_id"],
            out_dir=delegation_dir,
            predicates=predicates,
            revoked=revoked,
        )
        policy = json.loads((delegation_dir / "policy.json").read_text())
        agent_pkx = (delegation_dir / "agent_pkx_sm2.txt").read_text().strip()
        task.emit("delegated",
                  policy=policy,
                  agent_pkx=agent_pkx[:34] + "...",
                  delegation_msg=(delegation_dir / "delegation_msg_sm3.txt").read_text().strip()[:42] + "...")

        # ── 2. Fetch OID4VP request from TripGo ─────────────────
        # Predicates must round-trip to the verifier so the reader request
        # encodes the same `--predicate` flags the prover used; otherwise the
        # zk circuit's predicate binding would mismatch.
        task.emit("fetching_request", message="向 TripGo 申请 OID4VP 展示请求")
        r = _HTTP.post(f"{tripgo_base}/oid4vp/request",
                       json={
                           "claims": p["claims"],
                           "predicates": predicates,
                           "state": task.id,
                           "authorization_details": p.get("authorization_details") or [],
                       },
                       timeout=_HTTP_TIMEOUT,
                       verify=_HTTP_VERIFY)
        r.raise_for_status()
        oid4vp = r.json()
        request_id = oid4vp.get("request_id", "")
        request_object = oid4vp.get("request", {})
        state = request_object.get("state") or oid4vp.get("state") or task.id
        nonce = request_object.get("nonce")
        requested_claims = _claims_from_oid4vp_request(request_object, p["claims"])
        reader_zip_b64 = oid4vp.get("reader_request_zip_b64", "")
        if not request_id or not reader_zip_b64:
            raise RuntimeError("TripGo OID4VP request missing request_id or reader_request_zip_b64")
        if not nonce:
            raise RuntimeError("TripGo OID4VP request missing nonce")
        request_dir.mkdir(exist_ok=True)
        _safe_extract_zip(base64.b64decode(reader_zip_b64, validate=True), request_dir)
        task.emit("got_request",
                  files=sorted(os.listdir(request_dir)),
                  request_id=request_id,
                  state=state,
                  nonce=nonce,
                  claims=requested_claims,
                  response_uri=request_object.get("response_uri"))

        # ── 3. ZK Prove ─────────────────────────────────────────
        task.emit("proving", message="生成 Ligero v2 ZK 证明 (~5s)")

        def line_cb(line: str):
            if any(k in line for k in ("ZK ", "Prover Done", "proof_len", "com_proof")):
                task.emit("prover_log", line=line.strip())

        bins.agent_present(
            delegation=delegation_dir,
            issuer_public=issuer_public_dir,
            request=request_dir,
            out_dir=presentation_dir,
            on_line=line_cb,
        )
        proof_path = presentation_dir / "proof.bin"
        proof_size = proof_path.stat().st_size if proof_path.exists() else 0
        public_delegation_path = presentation_dir / "public_delegation.json"
        public_delegation = (
            json.loads(public_delegation_path.read_text())
            if public_delegation_path.exists()
            else {}
        )
        task.emit("proven",
                  proof_size=proof_size,
                  presentation_files=sorted(os.listdir(presentation_dir)),
                  public_delegation=public_delegation)

        # ── 4. Direct-post OID4VP response to TripGo ────────────
        task.emit("posting", message="向 TripGo direct_post OID4VP vp_token")
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(presentation_dir.iterdir()):
                if f.is_file():
                    z.write(f, f.name)
        presentation_zip_b64 = base64.b64encode(zip_buf.getvalue()).decode("ascii")
        order_req = {
            "hotel_id": p["hotel_id"],
            "checkin": p["checkin"],
            "checkout": p["checkout"],
            "claims": requested_claims,
            "predicates": predicates,
            "agent_id": p["agent_id"],
            "channel": "oid4vp",
            "task_id": task.id,
            "request_id": request_id,
            "authorization_details": p.get("authorization_details") or [],
        }
        oid4vp_response = {
            "state": state,
            "vp_token": {
                "format": "zkaa+ligero",
                "profile": "https://zk-agentauth.local/profiles/vp-token/zkaa-ligero-v1",
                "presentation_zip_b64": presentation_zip_b64,
                "claims": requested_claims,
            },
            "presentation_submission": {
                "id": f"ps-{task.id}",
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
                ],
            },
            "order_request": order_req,
        }
        r = _HTTP.post(f"{tripgo_base}/oid4vp/response",
                       json=oid4vp_response, timeout=_HTTP_TIMEOUT,
                       verify=_HTTP_VERIFY)
        if r.status_code != 200:
            task.emit("failed", error=f"TripGo {r.status_code}: {r.text[:200]}")
            return
        result = r.json()
        task.result = result

        # ── 5. Done ─────────────────────────────────────────────
        order = result.get("order") or {}
        checks = result.get("checks") or {}
        _append_log(tasks_dir, {
            "ts": time.time(),
            "task_id": task.id,
            "status": "done",
            "accepted": bool(result.get("accepted")),
            "overall": checks.get("overall"),
            "checks": checks,
            "agent_id": p.get("agent_id"),
            "claims": order.get("claims_proven") or requested_claims,
            "hotel_id": p.get("hotel_id"),
            "hotel_name": order.get("hotel_name"),
            "proof_size": order.get("proof_size") or proof_size,
            "order_id": result.get("order_id") or order.get("order_id"),
        })
        task.emit("done", **result)
    except Exception as e:
        _append_log(tasks_dir, {
            "ts": time.time(),
            "task_id": task.id,
            "status": "failed",
            "accepted": False,
            "agent_id": p.get("agent_id"),
            "claims": p.get("claims"),
            "hotel_id": p.get("hotel_id"),
            "error": str(e),
        })
        task.emit("failed", error=str(e))
