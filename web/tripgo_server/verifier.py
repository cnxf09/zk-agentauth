"""Subprocess wrapper around delegation_demo_verifier (TripGo side)."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

_HERE = Path(__file__).resolve().parent
# Same default location as wallet_server/bins.py — keep in sync.
_REPO = _HERE.parent.parent
_DEFAULT_BIN_DIR = _REPO / "build" / "examples" / "delegation_demo"
BIN_DIR = Path(os.environ.get("ZKAA_BIN_DIR", str(_DEFAULT_BIN_DIR)))


def _bin(name: str) -> Path:
    p = BIN_DIR / name
    if not p.exists():
        raise FileNotFoundError(
            f"binary not found: {p}\n"
            f"hint: run `make build` from web/ to compile delegation_demo."
        )
    return p


def _run(cmd: List[str], on_line: Optional[Callable[[str], None]] = None) -> str:
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, text=True,
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
        raise RuntimeError(f"verifier exited {rc}\n{out}")
    return out


def request(issuer_public: Path, claims: List[str], out_dir: Path,
            predicates: Optional[List[str]] = None,
            on_line: Optional[Callable[[str], None]] = None) -> str:
    """Issue a reader request. Optional `predicates` map to `--predicate`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [str(_bin("delegation_demo_verifier")), "request",
           "--issuer-public", str(issuer_public),
           "--out", str(out_dir)]
    for c in claims:
        cmd += ["--claim", c]
    for p in (predicates or []):
        cmd += ["--predicate", p]
    return _run(cmd, on_line)


def verify(issuer_public: Path, request_dir: Path, presentation: Path,
           on_line: Optional[Callable[[str], None]] = None) -> str:
    return _run([str(_bin("delegation_demo_verifier")), "verify",
                 "--issuer-public", str(issuer_public),
                 "--request", str(request_dir),
                 "--presentation", str(presentation)], on_line)
