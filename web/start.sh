#!/usr/bin/env bash
# Start Wallet (8002) and TripGo (8003). Wallet starts first to bootstrap issuer artifacts.
set -e
cd "$(dirname "$0")"

if [[ -x .venv/bin/python ]]; then
  PYTHON="${PYTHON:-.venv/bin/python}"
else
  PYTHON="${PYTHON:-python3}"
fi

SCHEME="${SCHEME:-http}"
CURL_TLS=()
if [[ "${USE_HTTPS:-0}" == "1" ]]; then
  SCHEME="https"
  export ZKAA_TLS_VERIFY="${ZKAA_TLS_VERIFY:-0}"
  export OIDC_ISSUER="${OIDC_ISSUER:-https://localhost:8002}"
  export TRIPGO_ISSUER="${TRIPGO_ISSUER:-https://localhost:8003}"
  export TRIPGO_BASE="${TRIPGO_BASE:-https://localhost:8003}"
  CURL_TLS=(-k)
else
  export OIDC_ISSUER="${OIDC_ISSUER:-http://localhost:8002}"
  export TRIPGO_ISSUER="${TRIPGO_ISSUER:-http://localhost:8003}"
  export TRIPGO_BASE="${TRIPGO_BASE:-http://localhost:8003}"
fi

cleanup() {
  echo
  echo "[stop] killing servers..."
  [[ -n "$WALLET_PID" ]] && kill "$WALLET_PID" 2>/dev/null || true
  [[ -n "$TRIPGO_PID" ]] && kill "$TRIPGO_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[start] wallet on ${SCHEME}://localhost:8002"
$PYTHON wallet_server/app.py 2>&1 | sed 's/^/[wallet] /' &
WALLET_PID=$!

# Wait for wallet to be ready (and to finish bootstrap)
for i in {1..60}; do
  if curl "${CURL_TLS[@]}" -fs "${SCHEME}://127.0.0.1:8002/api/wallet/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[start] tripgo on ${SCHEME}://localhost:8003"
$PYTHON tripgo_server/app.py 2>&1 | sed 's/^/[tripgo] /' &
TRIPGO_PID=$!

for i in {1..30}; do
  if curl "${CURL_TLS[@]}" -fs "${SCHEME}://127.0.0.1:8003/api/catalog" >/dev/null 2>&1; then
    break
  fi
  sleep 0.3
done

echo
echo "  Wallet  → ${SCHEME}://localhost:8002  (Alice 的钱包)"
echo "  TripGo  → ${SCHEME}://localhost:8003  (服务商 / 验证者)"
if [[ "${USE_HTTPS:-0}" == "1" ]]; then
  echo "  HTTPS   → using Werkzeug adhoc self-signed certificates; browser warning is expected."
fi
echo
echo "  Ctrl+C to stop."

# Auto-open browsers (macOS / Linux)
if [[ "${OPEN_BROWSER:-1}" == "1" ]]; then
  if command -v open >/dev/null 2>&1; then
    (sleep 0.3; open "${SCHEME}://localhost:8002"; sleep 0.5; open "${SCHEME}://localhost:8003") &
  elif command -v xdg-open >/dev/null 2>&1; then
    (sleep 0.3; xdg-open "${SCHEME}://localhost:8002" >/dev/null 2>&1; sleep 0.5; xdg-open "${SCHEME}://localhost:8003" >/dev/null 2>&1) &
  fi
fi

wait
