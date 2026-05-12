#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
BIN="${BIN:-$BUILD/examples/delegation_demo}"
WORK="${WORK:-/tmp/zkaa_security_cli}"

mkdir -p "$BUILD"
cmake -S "$ROOT/lib" -B "$BUILD" >/dev/null
cmake --build "$BUILD" --target \
  delegation_demo_issuer \
  delegation_demo_alice \
  delegation_demo_agent \
  delegation_demo_verifier >/dev/null

pass() {
  printf "PASS,%s\n" "$1"
}

fail() {
  printf "FAIL,%s\n" "$1"
  exit 1
}

expect_ok() {
  local name="$1"
  shift
  if "$@" >/tmp/zkaa_security_ok.out 2>/tmp/zkaa_security_ok.err; then
    pass "$name"
  else
    cat /tmp/zkaa_security_ok.err >&2 || true
    fail "$name"
  fi
}

expect_fail() {
  local name="$1"
  shift
  if "$@" >/tmp/zkaa_security_fail.out 2>/tmp/zkaa_security_fail.err; then
    cat /tmp/zkaa_security_fail.out >&2 || true
    fail "$name"
  else
    pass "$name"
  fi
}

setup_base() {
  local dir="$1"
  local expires="${2:-2027-01-01T00:00:00Z}"
  local extra_delegate_flag="${3:-}"
  rm -rf "$dir"
  mkdir -p "$dir"

  "$BIN/delegation_demo_issuer" issue \
    --example 3 \
    --out "$dir/issue" >/dev/null

  if [[ -n "$extra_delegate_flag" ]]; then
    "$BIN/delegation_demo_alice" delegate \
      --holder "$dir/issue/holder" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --expires "$expires" \
      --agent-id bookstore-agent \
      "$extra_delegate_flag" \
      --out "$dir/delegation" >/dev/null
  else
    "$BIN/delegation_demo_alice" delegate \
      --holder "$dir/issue/holder" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --expires "$expires" \
      --agent-id bookstore-agent \
      --out "$dir/delegation" >/dev/null
  fi

  "$BIN/delegation_demo_verifier" request \
    --issuer-public "$dir/issue/issuer_public" \
    --predicate age_over_18:EQ:true \
    --predicate height:GE:170 \
    --out "$dir/request" >/dev/null
}

printf "result,test\n"

BASE="$WORK/baseline"
setup_base "$BASE"
expect_ok baseline_present "$BIN/delegation_demo_agent" present \
  --delegation "$BASE/delegation" \
  --issuer-public "$BASE/issue/issuer_public" \
  --request "$BASE/request" \
  --out "$BASE/presentation"
expect_ok baseline_verify "$BIN/delegation_demo_verifier" verify \
  --issuer-public "$BASE/issue/issuer_public" \
  --request "$BASE/request" \
  --presentation "$BASE/presentation"

REVOKED="$WORK/revoked"
setup_base "$REVOKED" "2027-01-01T00:00:00Z" "--revoked"
expect_fail revoked_delegation_rejected "$BIN/delegation_demo_agent" present \
  --delegation "$REVOKED/delegation" \
  --issuer-public "$REVOKED/issue/issuer_public" \
  --request "$REVOKED/request" \
  --out "$REVOKED/presentation"

EXPIRED="$WORK/expired"
setup_base "$EXPIRED" "2024-01-01T00:00:00Z"
expect_fail expired_policy_rejected "$BIN/delegation_demo_agent" present \
  --delegation "$EXPIRED/delegation" \
  --issuer-public "$EXPIRED/issue/issuer_public" \
  --request "$EXPIRED/request" \
  --out "$EXPIRED/presentation"

PRED="$WORK/predicate_fail"
rm -rf "$PRED"
mkdir -p "$PRED"
"$BIN/delegation_demo_issuer" issue --example 3 --out "$PRED/issue" >/dev/null
"$BIN/delegation_demo_alice" delegate \
  --holder "$PRED/issue/holder" \
  --predicate height:GE:180 \
  --expires 2027-01-01T00:00:00Z \
  --agent-id bookstore-agent \
  --out "$PRED/delegation" >/dev/null
"$BIN/delegation_demo_verifier" request \
  --issuer-public "$PRED/issue/issuer_public" \
  --predicate height:GE:180 \
  --out "$PRED/request" >/dev/null
expect_fail unsatisfied_predicate_rejected "$BIN/delegation_demo_agent" present \
  --delegation "$PRED/delegation" \
  --issuer-public "$PRED/issue/issuer_public" \
  --request "$PRED/request" \
  --out "$PRED/presentation"

TAMPER_PROOF="$WORK/tamper_proof"
cp -a "$BASE" "$TAMPER_PROOF"
python3 - "$TAMPER_PROOF/presentation/proof.bin" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
b = bytearray(p.read_bytes())
if not b:
    raise SystemExit("empty proof")
b[len(b) // 2] ^= 1
p.write_bytes(b)
PY
expect_fail tampered_proof_rejected "$BIN/delegation_demo_verifier" verify \
  --issuer-public "$TAMPER_PROOF/issue/issuer_public" \
  --request "$TAMPER_PROOF/request" \
  --presentation "$TAMPER_PROOF/presentation"

TAMPER_POLICY="$WORK/tamper_policy"
cp -a "$BASE" "$TAMPER_POLICY"
python3 - "$TAMPER_POLICY/presentation/public_delegation.json" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('"height"', '"family_name"', 1)
p.write_text(s)
PY
expect_fail tampered_policy_rejected "$BIN/delegation_demo_verifier" verify \
  --issuer-public "$TAMPER_POLICY/issue/issuer_public" \
  --request "$TAMPER_POLICY/request" \
  --presentation "$TAMPER_POLICY/presentation"

TAMPER_REVOCATION="$WORK/tamper_revocation_status"
cp -a "$BASE" "$TAMPER_REVOCATION"
python3 - "$TAMPER_REVOCATION/presentation/delegation_revocation_status.json" <<'PY'
from pathlib import Path
import json
import sys
p = Path(sys.argv[1])
obj = json.loads(p.read_text())
obj["revoked"] = True
p.write_text(json.dumps(obj, indent=2) + "\n")
PY
expect_fail tampered_revocation_status_rejected "$BIN/delegation_demo_verifier" verify \
  --issuer-public "$TAMPER_REVOCATION/issue/issuer_public" \
  --request "$TAMPER_REVOCATION/request" \
  --presentation "$TAMPER_REVOCATION/presentation"
