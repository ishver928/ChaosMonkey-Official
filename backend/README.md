# Chaos Monkey — backend

Local-only security checkpoint for AI-generated code. FastAPI + a deterministic analysis
pipeline. The server binds to loopback and the only model endpoint it will call is a loopback URL.

## Quick start

```bash
# from the repo root
scripts/setup.sh          # venv + deps + CWE knowledge base (+ Ollama models if installed)
scripts/run.sh            # http://127.0.0.1:8000

# fully offline (no Ollama needed) — recorded model responses:
LLM_MOCK=1 scripts/run.sh
```

Or manually:

```bash
cd backend
python3.11 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python ../scripts/build_cwe_seed.py
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## Tests

```bash
cd backend && LLM_MOCK=1 ./.venv/bin/python -m pytest -q
```

Covers every detector, the evidence validator rejecting hallucinated findings, determinism,
patch verification, report generation, and an end-to-end demo run for each scenario
(vulnerable → COMPROMISED, patched → BLOCKED).

## Layout

```
app/
  api/         REST + SSE routes, background scan store
  pipeline/    ingest → detect → llm_analyze → validate → severity → fixes → orchestrator
  detectors/   masking, common helpers, regex rules (CM-*), python_ast (CM-A*), js (CM-J*)
  kb/          CWE store + RAG retrieval, rule↔CWE mapping
  llm/         Ollama client (deterministic), SQLite cache, mock analyzer
  reports/     JSON / Markdown / HTML / SARIF renderers
  demo/        scenario registry, attack simulator, demo routes
  models/      Pydantic schemas (mirror the frontend contract)
tests/         pytest suite
```

## Modes

- **full** — Ollama running with the configured model → real local LLM analysis.
- **mock** — `LLM_MOCK=1` → deterministic recorded analyzer, no network at all.
- **detector-only** — Ollama absent → regex/AST/JS detectors still run; LLM stage is skipped
  gracefully. The CWE retriever falls back to offline TF-IDF, then keyword overlap.

## Determinism

Every LLM call pins `temperature=0, top_k=1, top_p=1, seed`, requests JSON output, retries
on invalid JSON (max 3, same params), and is cached by `sha256(model+prompt+params+content)`.
Finding ids are `sha256(file+line+cwe+snippet)[:12]` with stable ordering and no timestamps
in the hash. Verify with `GET /api/determinism-check`.

## Configuration

Copy `.env.example` to `.env`. Key vars: `OLLAMA_URL` (must be localhost), `LLM_MODEL`,
`EMBED_MODEL`, `SEED`, `LLM_MOCK`, `HOST`, `PORT`, `MAX_FILE_BYTES`.
