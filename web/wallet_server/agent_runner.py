"""Agent dispatch task runner — orchestrates the full ZK delegation flow.

A Task progresses through phases: delegating → fetching_request → proving →
posting → done (or failed). Every transition emits an SSE event.
"""
from __future__ import annotations
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


_TASKS: dict[str, "Task"] = {}
_TASKS_LOCK = threading.Lock()


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
        task.emit("delegating",
                  message="Alice 创建委托 (P-256 ECDSA 签名)",
                  claims=p["claims"], agent_id=p["agent_id"],
                  expires=p["expires"])
        bins.alice_delegate(
            holder=holder_dir,
            claims=p["claims"],
            expires_iso=p["expires"],
            agent_id=p["agent_id"],
            out_dir=delegation_dir,
        )
        policy = json.loads((delegation_dir / "policy.json").read_text())
        agent_pkx = (delegation_dir / "agent_pkx.txt").read_text().strip()
        task.emit("delegated",
                  policy=policy,
                  agent_pkx=agent_pkx[:34] + "...",
                  delegation_msg=(delegation_dir / "delegation_msg.txt").read_text().strip()[:42] + "...")

        # ── 2. Fetch reader request from TripGo ─────────────────
        task.emit("fetching_request", message="向 TripGo 申请挑战 (reader request)")
        r = _HTTP.post(f"{tripgo_base}/api/agent/request",
                       json={"claims": p["claims"]}, timeout=_HTTP_TIMEOUT)
        r.raise_for_status()
        request_id = r.headers.get("X-Request-Id", "")
        request_dir.mkdir(exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            z.extractall(request_dir)
        task.emit("got_request",
                  files=sorted(os.listdir(request_dir)),
                  request_id=request_id)

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

        # ── 4. Post to TripGo ───────────────────────────────────
        task.emit("posting", message="向 TripGo 投递 ZK presentation + public delegation")
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(presentation_dir.iterdir()):
                if f.is_file():
                    z.write(f, f.name)
        zip_buf.seek(0)
        order_req = {
            "hotel_id": p["hotel_id"],
            "checkin": p["checkin"],
            "checkout": p["checkout"],
            "claims": p["claims"],
            "agent_id": p["agent_id"],
            "task_id": task.id,
            "request_id": request_id,
        }
        files = {"presentation": ("presentation.zip", zip_buf, "application/zip")}
        data = {"order_request": json.dumps(order_req)}
        r = _HTTP.post(f"{tripgo_base}/api/agent/order",
                       files=files, data=data, timeout=_HTTP_TIMEOUT)
        if r.status_code != 200:
            task.emit("failed", error=f"TripGo {r.status_code}: {r.text[:200]}")
            return
        result = r.json()
        task.result = result

        # ── 5. Done ─────────────────────────────────────────────
        task.emit("done", **result)
    except Exception as e:
        task.emit("failed", error=str(e))
