#!/usr/bin/env bash
# One-command setup for the Chaos Monkey backend.
# Creates a venv, installs deps, builds the CWE knowledge base, and (if Ollama is
# installed) pulls the local models. Everything is local — no cloud services.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO/backend"

PY="${PYTHON:-python3.11}"
command -v "$PY" >/dev/null 2>&1 || PY="python3"

echo "==> Creating virtualenv (.venv) with $PY"
"$PY" -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
echo "==> Installing Python dependencies"
./.venv/bin/pip install --quiet -r requirements.txt

echo "==> Building the CWE knowledge base"
./.venv/bin/python "$REPO/scripts/build_cwe_seed.py"

if command -v ollama >/dev/null 2>&1; then
  MODEL="${LLM_MODEL:-qwen2.5-coder:7b-instruct}"
  EMBED="${EMBED_MODEL:-nomic-embed-text}"
  echo "==> Ollama found — pulling models ($MODEL, $EMBED). Ctrl-C to skip."
  ollama pull "$MODEL" || echo "   (skipped $MODEL)"
  ollama pull "$EMBED" || echo "   (skipped $EMBED)"
else
  echo "==> Ollama not installed. The backend runs in detector-only mode and the"
  echo "    offline TF-IDF retriever + mock analyzer still work. Install from"
  echo "    https://ollama.com to enable the local LLM."
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Wrote backend/.env from .env.example"
fi

echo "==> Setup complete. Start the server with: scripts/run.sh"
