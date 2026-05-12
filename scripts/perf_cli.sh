#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD:-$ROOT/build}"
BIN="${BIN:-$BUILD/examples/delegation_demo}"
WORK="${WORK:-/tmp/zkaa_perf_cli}"
RUNS="${RUNS:-3}"
REUSE_SETUP="${REUSE_SETUP:-0}"

mkdir -p "$BUILD"
cmake -S "$ROOT/lib" -B "$BUILD" >/dev/null
cmake --build "$BUILD" --target \
  delegation_demo_issuer \
  delegation_demo_alice \
  delegation_demo_agent \
  delegation_demo_verifier >/dev/null

timestamp_ms() {
  date +%s%3N
}

measure() {
  local label="$1"
  shift
  local start end elapsed
  start="$(timestamp_ms)"
  "$@" >/tmp/zkaa_perf_step.out 2>/tmp/zkaa_perf_step.err
  end="$(timestamp_ms)"
  elapsed=$((end - start))
  printf "%s,%s\n" "$label" "$elapsed"
}

size_or_zero() {
  local file="$1"
  if [[ -f "$file" ]]; then
    stat -c%s "$file"
  else
    printf "0"
  fi
}

printf "run,step,elapsed_ms,proof_bytes,presentation_bytes\n"

if [[ "$REUSE_SETUP" == "1" ]]; then
  BASE_DIR="$WORK/reused_setup"
  rm -rf "$BASE_DIR"
  mkdir -p "$BASE_DIR"

  while IFS=, read -r step elapsed; do
    printf "%s,%s,%s,%s,%s\n" "setup" "$step" "$elapsed" "0" "0"
  done < <(
    measure issue "$BIN/delegation_demo_issuer" issue \
      --example 3 \
      --out "$BASE_DIR/issue"

    measure delegate "$BIN/delegation_demo_alice" delegate \
      --holder "$BASE_DIR/issue/holder" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --expires 2027-01-01T00:00:00Z \
      --agent-id bookstore-agent \
      --out "$BASE_DIR/delegation"

    measure request "$BIN/delegation_demo_verifier" request \
      --issuer-public "$BASE_DIR/issue/issuer_public" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --out "$BASE_DIR/request"
  )

  for run in $(seq 1 "$RUNS"); do
    RUN_DIR="$WORK/reused_run_$run"
    rm -rf "$RUN_DIR"
    mkdir -p "$RUN_DIR"

    while IFS=, read -r step elapsed; do
      printf "%s,%s,%s,%s,%s\n" "$run" "$step" "$elapsed" "0" "0"
    done < <(
      measure present "$BIN/delegation_demo_agent" present \
        --delegation "$BASE_DIR/delegation" \
        --issuer-public "$BASE_DIR/issue/issuer_public" \
        --request "$BASE_DIR/request" \
        --out "$RUN_DIR/presentation"

      measure verify "$BIN/delegation_demo_verifier" verify \
        --issuer-public "$BASE_DIR/issue/issuer_public" \
        --request "$BASE_DIR/request" \
        --presentation "$RUN_DIR/presentation"
    )

    proof_bytes="$(size_or_zero "$RUN_DIR/presentation/proof.bin")"
    presentation_bytes="$(du -sb "$RUN_DIR/presentation" | awk '{print $1}')"
    printf "%s,%s,%s,%s,%s\n" "$run" "artifacts" "0" "$proof_bytes" "$presentation_bytes"
  done
  exit 0
fi

for run in $(seq 1 "$RUNS"); do
  RUN_DIR="$WORK/run_$run"
  rm -rf "$RUN_DIR"
  mkdir -p "$RUN_DIR"

  while IFS=, read -r step elapsed; do
    printf "%s,%s,%s,%s,%s\n" "$run" "$step" "$elapsed" "0" "0"
  done < <(
    measure issue "$BIN/delegation_demo_issuer" issue \
      --example 3 \
      --out "$RUN_DIR/issue"

    measure delegate "$BIN/delegation_demo_alice" delegate \
      --holder "$RUN_DIR/issue/holder" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --expires 2027-01-01T00:00:00Z \
      --agent-id bookstore-agent \
      --out "$RUN_DIR/delegation"

    measure request "$BIN/delegation_demo_verifier" request \
      --issuer-public "$RUN_DIR/issue/issuer_public" \
      --predicate age_over_18:EQ:true \
      --predicate height:GE:170 \
      --out "$RUN_DIR/request"

    measure present "$BIN/delegation_demo_agent" present \
      --delegation "$RUN_DIR/delegation" \
      --issuer-public "$RUN_DIR/issue/issuer_public" \
      --request "$RUN_DIR/request" \
      --out "$RUN_DIR/presentation"

    measure verify "$BIN/delegation_demo_verifier" verify \
      --issuer-public "$RUN_DIR/issue/issuer_public" \
      --request "$RUN_DIR/request" \
      --presentation "$RUN_DIR/presentation"
  )

  proof_bytes="$(size_or_zero "$RUN_DIR/presentation/proof.bin")"
  presentation_bytes="$(du -sb "$RUN_DIR/presentation" | awk '{print $1}')"
  printf "%s,%s,%s,%s,%s\n" "$run" "artifacts" "0" "$proof_bytes" "$presentation_bytes"
done
