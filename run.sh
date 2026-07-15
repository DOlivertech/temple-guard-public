#!/usr/bin/env bash
# Project Temple Guard — one-shot local launcher (backend + frontend).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "⛨  Project Temple Guard — starting locally"

# ── Backend ────────────────────────────────────────────────────────────────
cd "$ROOT/backend"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi
if [ ! -f temple_guard.db ]; then
  ./.venv/bin/python -m app.seed
fi
TG_EXECUTION_MODE="${TG_EXECUTION_MODE:-simulation}" \
  ./.venv/bin/uvicorn app.main:app --port 8000 &
API_PID=$!

# ── Frontend ───────────────────────────────────────────────────────────────
cd "$ROOT/frontend"
[ -d node_modules ] || npm install
npm run dev &
WEB_PID=$!

trap 'kill $API_PID $WEB_PID 2>/dev/null' EXIT
echo ""
echo "  API : http://localhost:8000  (docs at /docs)"
echo "  UI  : http://localhost:3000"
echo "  Mode: ${TG_EXECUTION_MODE:-simulation}   (set TG_EXECUTION_MODE=docker for real scans)"
echo ""
wait
