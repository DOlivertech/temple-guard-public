#!/usr/bin/env bash
#
# Project Temple Guard — start the whole stack with one command.
#   ./start.sh            # build (first run) + start postgres + backend + frontend
#   ./start.sh -d         # detached (run in the background)
#
# Open http://localhost:3000 once it's up. Data persists in Docker volumes;
# back it up with ./backup.sh.
set -euo pipefail
cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
  echo "⛨  Docker isn't running. Starting Docker Desktop…"
  if [ "$(uname -s)" = "Darwin" ]; then open -a Docker || true; fi
  printf "   waiting for Docker"
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; printf "."; sleep 2; done; echo
fi

DETACH=""
[ "${1:-}" = "-d" ] && DETACH="-d"

echo "⛨  Project Temple Guard — bringing up the stack (first run builds images)…"
docker compose up --build $DETACH

if [ -n "$DETACH" ]; then
  echo ""
  echo "  UI : http://localhost:3000"
  echo "  API: http://localhost:8000  (docs: /docs)"
  echo "  Stop with: docker compose down   ·   Back up with: ./backup.sh"
fi
