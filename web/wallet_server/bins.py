"""Subprocess wrappers around the four delegation_demo C++ binaries.

Path discovery: BIN_DIR env var → fallback to known build location.
All wrappers stream stdout/stderr; callers may pass a line callback.
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

_HERE = Path(__file__).resolve().parent
# Default binary location: <repo>/build/examples/delegation_demo, which is the
# output of `make build` in the sibling web/ directory (or `cmake -B ../build`
# from lib/). Set ZKAA_BIN_DIR to override.
_REPO = _HERE.parent.parent  # …/zk-agentauth/
_DEFAULT_BIN_DIR = _REPO / "build" / "examples" / "delegation_demo"
BIN_DIR = Path(os.environ.get("ZKAA_BIN_DIR", str(_DEFAULT_BIN_DIR)))


def _bin(name: str) -> Path:
    p = BIN_DIR / name
    if not p.exists():
        raise FileNotFoundError(
            f"binary not found: {p}\n"
            f"hint: run `make build` from web/ to compile delegation_demo, "
            f"or set ZKAA_BIN_DIR to point at an existing build."
        )
    return p


def _run(cmd: List[str], on_line: Optional[Callable[[str], None]] = None) -> str:
    """Run synchronously; stream lines to callback; return all output."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
    )
    buf = []
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        buf.append(line)
        if on_line:
            try:
                on_line(line)
            except Exception:
                pass
    rc = proc.wait()
    out = "\n".join(buf)
    if rc != 0:
        raise RuntimeError(f"{cmd[0]} exited {rc}\n{out}")
    return out


def issuer_issue(out_dir: Path, example: int = 3,
                 on_line: Optional[Callable[[str], None]] = None) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    return _run([str(_bin("delegation_demo_issuer")), "issue",
                 "--example", str(example),
                 "--out", str(out_dir)], on_line)


def alice_delegate(holder: Path, claims: List[str], expires_iso: str,
                   agent_id: str, out_dir: Path,
                   predicates: Optional[List[str]] = None,
                   revoked: bool = False,
                   on_line: Optional[Callable[[str], None]] = None) -> str:
    """Run `delegation_demo_alice delegate`.

    `predicates` are passed verbatim as `--predicate <claim:OP:value>` flags
    (e.g. `age_over_18:EQ:true`, `height:GE:170`). When `revoked=True`, Alice
    writes a pre-revoked delegation_revocation_status.json — for negative tests.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(_bin("delegation_demo_alice")), "delegate",
           "--holder", str(holder),
           "--expires", expires_iso,
           "--agent-id", agent_id,
           "--out", str(out_dir)]
    for c in claims:
        cmd += ["--claim", c]
    for p in (predicates or []):
        cmd += ["--predicate", p]
    if revoked:
        cmd.append("--revoked")
    return _run(cmd, on_line)


def agent_present(delegation: Path, issuer_public: Path, request: Path,
                  out_dir: Path,
                  on_line: Optional[Callable[[str], None]] = None) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    return _run([str(_bin("delegation_demo_agent")), "present",
                 "--delegation", str(delegation),
                 "--issuer-public", str(issuer_public),
                 "--request", str(request),
                 "--out", str(out_dir)], on_line)


def verifier_request(issuer_public: Path, claims: List[str], out_dir: Path,
                     predicates: Optional[List[str]] = None,
                     on_line: Optional[Callable[[str], None]] = None) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(_bin("delegation_demo_verifier")), "request",
           "--issuer-public", str(issuer_public),
           "--out", str(out_dir)]
    for c in claims:
        cmd += ["--claim", c]
    for p in (predicates or []):
        cmd += ["--predicate", p]
    return _run(cmd, on_line)


def verifier_verify(issuer_public: Path, request: Path, presentation: Path,
                    on_line: Optional[Callable[[str], None]] = None) -> str:
    return _run([str(_bin("delegation_demo_verifier")), "verify",
                 "--issuer-public", str(issuer_public),
                 "--request", str(request),
                 "--presentation", str(presentation)], on_line)
