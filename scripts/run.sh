#!/usr/bin/env bash
# Start the Chaos Monkey backend on 127.0.0.1:8000.
# Set LLM_MOCK=1 for a fully offline run with recorded model responses.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO/backend"

if [ ! -d .venv ]; then
  echo "No .venv found. Run scripts/setup.sh first." >&2
  exit 1
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
echo "==> Chaos Monkey on http://$HOST:$PORT  (LLM_MOCK=${LLM_MOCK:-0})"
exec ./.venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" "$@"
