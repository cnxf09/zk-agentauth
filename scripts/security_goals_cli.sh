#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
BIN="${BIN:-$BUILD/examples/delegation_demo}"
WORK="${WORK:-/tmp/zkaa_security_goals_cli}"

mkdir -p "$BUILD"
cmake -S "$ROOT/lib" -B "$BUILD" >/dev/null
cmake --build "$BUILD" --target \
  delegation_demo_issuer \
  delegation_demo_alice \
  delegation_demo_agent \
  delegation_demo_verifier >/dev/null

pass() {
  printf "PASS,%s,%s\n" "$1" "$2"
}

fail() {
  printf "FAIL,%s,%s\n" "$1" "$2"
}

expect_ok() {
  local goal="$1"
  local name="$2"
  shift 2
  if "$@" >/tmp/zkaa_goal_ok.out 2>/tmp/zkaa_goal_ok.err; then
    pass "$goal" "$name"
  else
    fail "$goal" "$name"
    cat /tmp/zkaa_goal_ok.err >&2 || true
  fi
}

expect_fail() {
  local goal="$1"
  local name="$2"
  shift 2
  if "$@" >/tmp/zkaa_goal_fail.out 2>/tmp/zkaa_goal_fail.err; then
    fail "$goal" "$name"
    cat /tmp/zkaa_goal_fail.out >&2 || true
  else
    pass "$goal" "$name"
  fi
}

setup_valid() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  "$BIN/delegation_demo_issuer" issue \
    --example 3 \
    --out "$dir/issue" >/dev/null
  "$BIN/delegation_demo_alice" delegate \
    --holder "$dir/issue/holder" \
    --predicate age_over_18:EQ:true \
    --predicate height:GE:170 \
    --expires 2027-01-01T00:00:00Z \
    --agent-id bookstore-agent \
    --out "$dir/delegation" >/dev/null
  "$BIN/delegation_demo_verifier" request \
    --issuer-public "$dir/issue/issuer_public" \
    --predicate age_over_18:EQ:true \
    --predicate height:GE:170 \
    --out "$dir/request" >/dev/null
}

flip_hex_file_first_digit() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text().strip()
prefix = "0x" if s.startswith("0x") else ""
body = s[2:] if prefix else s
if not body:
    raise SystemExit("empty hex file")
body = ("0" if body[0] != "0" else "1") + body[1:]
p.write_text(prefix + body + "\n")
PY
}

json_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as f:
    obj = json.load(f)
print(obj.get(sys.argv[2], ""))
PY
}

printf "result,goal,test\n"

BASE="$WORK/baseline"
setup_valid "$BASE"
expect_ok "baseline" "valid_agent_presentation_generated" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$BASE/delegation" \
    --issuer-public "$BASE/issue/issuer_public" \
    --request "$BASE/request" \
    --out "$BASE/presentation"
expect_ok "baseline" "valid_agent_presentation_accepted" \
  "$BIN/delegation_demo_verifier" verify \
    --issuer-public "$BASE/issue/issuer_public" \
    --request "$BASE/request" \
    --presentation "$BASE/presentation"

FORGED_DELEGATION="$WORK/forged_delegation_sig"
cp -a "$BASE" "$FORGED_DELEGATION"
flip_hex_file_first_digit "$FORGED_DELEGATION/delegation/delegation_sig.txt"
expect_fail "unforgeability" "tampered_delegation_signature_cannot_present" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$FORGED_DELEGATION/delegation" \
    --issuer-public "$FORGED_DELEGATION/issue/issuer_public" \
    --request "$FORGED_DELEGATION/request" \
    --out "$FORGED_DELEGATION/presentation"

FORGED_AGENT="$WORK/forged_agent_key"
cp -a "$BASE" "$FORGED_AGENT"
flip_hex_file_first_digit "$FORGED_AGENT/delegation/agent_sk.txt"
expect_fail "unforgeability" "wrong_agent_secret_cannot_present" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$FORGED_AGENT/delegation" \
    --issuer-public "$FORGED_AGENT/issue/issuer_public" \
    --request "$FORGED_AGENT/request" \
    --out "$FORGED_AGENT/presentation"

"$BIN/delegation_demo_verifier" verify \
  --issuer-public "$BASE/issue/issuer_public" \
  --request "$BASE/request" \
  --presentation "$BASE/presentation" >/tmp/zkaa_transparency.out
if grep -q "Delegation sig: PASS" /tmp/zkaa_transparency.out &&
   grep -q "Policy claims: PASS" /tmp/zkaa_transparency.out &&
   grep -q "Delegation revocation: PASS" /tmp/zkaa_transparency.out; then
  pass "delegation_transparency" "verifier_reports_authorized_agent_checks"
else
  fail "delegation_transparency" "verifier_reports_authorized_agent_checks"
fi

OUT_OF_SCOPE="$WORK/out_of_scope_policy"
cp -a "$BASE" "$OUT_OF_SCOPE"
"$BIN/delegation_demo_verifier" request \
  --issuer-public "$OUT_OF_SCOPE/issue/issuer_public" \
  --claim family_name \
  --out "$OUT_OF_SCOPE/request_family_name" >/dev/null
expect_fail "policy_constraint" "agent_cannot_present_unallowed_claim" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$OUT_OF_SCOPE/delegation" \
    --issuer-public "$OUT_OF_SCOPE/issue/issuer_public" \
    --request "$OUT_OF_SCOPE/request_family_name" \
    --out "$OUT_OF_SCOPE/presentation_family_name"

REVOKED="$WORK/revoked"
rm -rf "$REVOKED"
mkdir -p "$REVOKED"
"$BIN/delegation_demo_issuer" issue --example 3 --out "$REVOKED/issue" >/dev/null
"$BIN/delegation_demo_alice" delegate \
  --holder "$REVOKED/issue/holder" \
  --predicate age_over_18:EQ:true \
  --expires 2027-01-01T00:00:00Z \
  --agent-id bookstore-agent \
  --revoked \
  --out "$REVOKED/delegation" >/dev/null
"$BIN/delegation_demo_verifier" request \
  --issuer-public "$REVOKED/issue/issuer_public" \
  --predicate age_over_18:EQ:true \
  --out "$REVOKED/request" >/dev/null
expect_fail "revocability" "revoked_delegation_cannot_present" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$REVOKED/delegation" \
    --issuer-public "$REVOKED/issue/issuer_public" \
    --request "$REVOKED/request" \
    --out "$REVOKED/presentation"

CROSS="$WORK/cross_credential"
cp -a "$BASE" "$CROSS"
"$BIN/delegation_demo_issuer" issue --example 3 --out "$CROSS/issue2" >/dev/null
cp "$CROSS/issue2/holder/device_response.cbor" "$CROSS/delegation/device_response.cbor"
cp "$CROSS/issue2/holder/device_sk.txt" "$CROSS/delegation/device_sk.txt"
cp "$CROSS/issue2/holder/device_pkx.txt" "$CROSS/delegation/device_pkx.txt"
cp "$CROSS/issue2/holder/device_pky.txt" "$CROSS/delegation/device_pky.txt"
expect_fail "credential_binding" "delegation_cannot_move_to_another_credential" \
  "$BIN/delegation_demo_agent" present \
    --delegation "$CROSS/delegation" \
    --issuer-public "$CROSS/issue/issuer_public" \
    --request "$CROSS/request" \
    --out "$CROSS/presentation"

ANON="$WORK/anonymity"
rm -rf "$ANON"
mkdir -p "$ANON"
cp -a "$BASE/issue" "$ANON/issue"
"$BIN/delegation_demo_alice" delegate \
  --holder "$ANON/issue/holder" \
  --predicate age_over_18:EQ:true \
  --expires 2027-01-01T00:00:00Z \
  --agent-id bookstore-agent \
  --out "$ANON/delegation2" >/dev/null
"$BIN/delegation_demo_verifier" request \
  --issuer-public "$ANON/issue/issuer_public" \
  --predicate age_over_18:EQ:true \
  --out "$ANON/request2" >/dev/null
"$BIN/delegation_demo_agent" present \
  --delegation "$ANON/delegation2" \
  --issuer-public "$ANON/issue/issuer_public" \
  --request "$ANON/request2" \
  --out "$ANON/presentation2" >/dev/null
if grep -R -q '"device_pkx"\\|"device_pky"\\|"delegation_sig"\\|"agent_sig"\\|"delegation_msg"' \
  "$BASE/presentation" "$ANON/presentation2"; then
  fail "delegator_anonymity" "presentation_exposes_hidden_witness_material"
else
  pass "delegator_anonymity" "presentation_omits_hidden_witness_material"
fi
