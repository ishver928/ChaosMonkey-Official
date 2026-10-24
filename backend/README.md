# Chaos Monkey — backend

Local-only security checkpoint for AI-generated code. FastAPI + a deterministic analysis
pipeline. No code ever leaves the machine.

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

## Sandbox verification layer

`POST /api/sandbox/run` / `GET /api/sandbox/{id}` (see [`API.md`](../API.md)) confirm whether a
*specific static finding* is actually exploitable by running the scanned app in Docker and
firing fixed, versioned, deterministic probes at it — no LLM involvement anywhere in this
layer. It is additive: existing endpoints and response shapes are unchanged except that a
`Finding` gains an optional `verification` field once a sandbox run has touched it.

```
app/sandbox/
  entrypoint.py     Best-effort Flask/FastAPI/Express entrypoint detection (never raises)
  docker_runner.py  Container/network lifecycle: internal-only network, hardening flags,
                    read-only project copy, rw scratch dir for the app's own SQLite file
  canary_host.py    Host-side half of canary generation (mirrors agent/cm_canary.py)
  service.py        Orchestration: static finding -> probe mapping -> VerificationResult
  agent/            Stdlib-only code that runs *inside* the probe container:
    cm_target.py      minimal HTTP client pinned to one host:port
    cm_discovery.py   black-box crawl (links/forms) + route extraction from static findings
    cm_canary.py      fake user/DOB/API-key canary values, seeded fresh per run
    cm_probes.py      the fixed probes (SQLi, XSS, command injection, exposed secrets,
                      PII-at-rest, debug-traceback) — each a single bounded HTTP exchange
                      (or a read of the mounted SQLite file) compared to a known-bad signature
    cm_agent.py       ties it together, prints one JSON object to stdout
```

Run `scripts/build_sandbox_images.sh` once to build `chaosmonkey-runner-python` and
`chaosmonkey-runner-node` (dependencies baked in at build time — the only point this layer
needs internet). If Docker isn't installed or the engine isn't running, `check_docker()`
reports `docker_unavailable`, every requested finding is marked `not_testable` with that
reason, the rest of ChaosMonkey (static scan, reports, demo) is unaffected, and
Docker-dependent tests (`tests/test_sandbox_docker.py`, `tests/test_sandbox_service.py`)
skip themselves automatically.

### Isolation

Per run: a fresh `--internal` Docker network (no gateway, so nothing routes off-host even if
the sandboxed app tries), a **read-only copy** of the project (never the original files) mounted
`:ro` into the app container, a small read-write scratch directory shared with the probe-agent
container (`:rw` into the app, `:ro` into the agent) for the one legitimate write a small
app needs — its own SQLite file — and nothing else writable. Both the app and the probe-agent
containers run `--user 10001:10001` (non-root), `--cap-drop ALL`,
`--security-opt no-new-privileges`, `--read-only` root filesystem with a `tmpfs` for `/tmp`,
and `--pids-limit`/`--memory`/`--cpus` limits. A hard wall-clock timeout
(`docker_runner.HARD_TIMEOUT_S`) bounds the probe-agent run, and every container is
force-removed (`docker rm -f`) in a `finally` block regardless of outcome. gVisor (`runsc`) is
used automatically via `--runtime runsc` when `docker info` reports it available, for a
stronger syscall boundary than the default runc.

Rules that would require an unsafe or meaningless dynamic re-run — unsafe deserialization
(`CM-A004`), weak crypto / hardcoded signing secrets (`CM-D002`, `CM-D004`), and browser
storage (`CM-D001`) — are never executed, even on request; they are reported `not_testable`
with a reason. No probe ever runs a deserialization payload.

### Threat model (read this before relying on it)

- **This sandbox runs code the user themselves uploaded to ChaosMonkey.** It is a verification
  convenience for findings on your own project, not a vehicle for running code you don't own or
  trust, and not a general-purpose malware sandbox.
- **Docker is a strong but not perfect isolation boundary.** Containers share the host kernel;
  container-escape vulnerabilities in the runtime, kernel, or container runtime exist and are
  occasionally found. gVisor (used automatically when present) adds a user-space syscall
  boundary that meaningfully reduces this risk but does not eliminate it — this is defense in
  depth, not a guarantee.
- **The internal Docker network has no route off the host**, but it does not prevent every
  possible side channel (timing, resource exhaustion against the host, etc.) — the
  memory/CPU/pids limits and hard timeout are there to bound exactly that.
- **"not_confirmed" is not "safe."** A probe can fail to reproduce an issue for reasons that
  have nothing to do with the code being secure: the entrypoint detector guessed wrong, the
  crawler never found the vulnerable route, the probe's specific payload shape didn't match
  this app's quirks, etc. `verification.status` distinguishes `confirmed` (reproduced),
  `not_confirmed` (this probe didn't reproduce it — not proof of absence),
  `not_testable` (no safe/meaningful way to check dynamically), and `skipped`.
- **All probes are fixed, versioned, and deterministic.** No LLM is ever involved in deciding
  what to probe or how; everything is attacker-adjacent only in the narrow, intentional sense of
  "the same canary-based checks a developer would script by hand."
