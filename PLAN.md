# Work plan: detection, deterministic LLM pipeline, sandbox verification

Branch: `feat/detection-llm-sandbox`. This is an additive plan, not a redesign. Existing UI,
endpoints and features stay as they are.

## What exists today (baseline, measured 2026-10-24)

- Backend: 34 pytest tests pass (`LLM_MOCK=1`). Frontend: `npm run selftest` 31/31, `tsc` clean, build OK.
- **Two rule engines.** The frontend folder-upload flow scans entirely in the browser
  (`intake.ts` -> `scan.worker.ts` -> `scanner.ts` -> `rules.ts`, 29 rules). It never calls the
  backend. The backend (`app/detectors/`) ports those 29 rules and adds 7 Python AST rules
  (`CM-A*`) and 5 JS rules (`CM-J*`) that do **not** exist in the frontend.
- **Severity differs between engines.** The backend recomputes severity from a CWE score, so the
  same rule can be "critical" in the browser and "high" in the API.
- **LLM can add findings.** `llm_analyze` asks the model for findings, which are merged into the
  report. When Ollama is absent the client silently substitutes `mock_analyze`, so "LLM"
  findings appear even without a model.
- Model calls: backend `httpx` client (`app/llm/client.py`, `/api/generate`, `format: "json"`,
  default `trust_env=True`) and a browser-side streaming call in `frontend/src/lib/ollama.ts`
  (temperature 0.2). Browser AI is off by default (`ollamaEnabled: false`).
- Known-broken fixes: the Node bcrypt fix inserts `await` into non-async functions; the
  frontend's plaintext-password fix emits JavaScript into Python files; the Python log-redaction
  fix pastes a column-0 helper into an indented block (IndentationError). Several backend
  "fixes" are only comments, so the vulnerability remains.

## Environment

- Node was not installed. A checksum-verified Node 22 tarball was unpacked to
  `~/.local/cm-node` (outside the repo) and used for the frontend checks.
- Docker: **not installed**. Ollama: **not installed**. Docker/Ollama-dependent paths are
  tested with mocks/fakes and reported as such.

## Phase 1: Part C (detection and remediation)

1. `rules/catalog.json` becomes the single source of truth for rule **metadata**: id, title,
   category, severity, CWE, explanation, steps, and per-language fix examples. The backend reads
   it directly. The frontend imports it for every new rule and for CWE/explanation fallback.
   Detection logic itself cannot be shared (Python AST vs browser JS), so a **parity test**
   runs both engines on the same corpus and checks that ids, CWEs and severities match and that
   findings agree.
2. Port the 12 backend-only rules to the frontend and add new rules to both engines:
   SQLi, XSS (DOM and server-side reflected), command injection, unsafe deserialization,
   weak crypto (ciphers/modes, insecure randomness), insecure config (debug, permissive CORS,
   TLS verification off), secrets, browser storage, and plaintext PII at rest or in logs.
3. Severity uses one rubric, documented in `docs/SEVERITY.md`. The rule's severity is the
   finding's severity in both engines. The backend numeric score is kept but clamped into that
   band.
4. False-positive controls: skip test/fixture/vendor/minified/lockfile paths unless
   `include_test_paths` is set. Ignore placeholders and env-var reads. Combine known key
   formats with entropy checks. SQLi requires dynamic string building into a query sink.
   XSS requires an unsanitized sink with non-literal input.
5. Rewrite fixes so they are real and syntactically valid in context. Add tests that apply
   each fix to its source file and syntax-check the result (`ast.parse`; `node --check` for JS;
   the TypeScript parser for TS).
6. Evaluation corpus (`eval/corpus/`) with vulnerable and safe samples per rule, including
   lookalike safe cases. `eval/run_eval.py` prints per-rule and overall precision/recall for
   both engines and fails below the documented thresholds.

## Phase 2: Part A (deterministic local LLM)

- `app/llm/client.py` becomes the only module that talks to a model. Every request goes
  through a loopback check, uses `trust_env=False`, and does not follow redirects. A socket
  guard test proves no non-loopback connect happens during a full scan.
- `/api/chat` calls use fixed options (temperature 0, seed, top_k 1, top_p, num_ctx,
  num_predict, `stream: false`) and a JSON-schema `format`. Responses are validated.
- The model digest comes from `/api/tags` / `/api/show` at startup and on toggle-on. The cache
  key covers model, digest, prompt version, options and input hash.
- The LLM only enriches existing findings with an explanation and a fix. Any failure falls back
  to the catalog text and marks the finding `ai_fallback`. AI stays **off by default**
  (`AI_ENABLED=0`).
- Prompt-injection hardening, additive `/api/health` fields, and tests (determinism x10,
  locality, AI-off, fake Ollama server).

## Phase 3: Part B (sandbox verification)

- `app/sandbox/`: entrypoint detection, a Docker runner (internal network, no egress,
  non-root, read-only rootfs, cap-drop ALL, no-new-privileges, limits, timeout, gVisor if
  present), canary seeding, a black-box crawler, and a fixed probe catalog mapped to rules.
- `POST /api/sandbox/run`, `GET /api/sandbox/{id}` (additive). If Docker is missing, the
  status is `disabled` and the static scan is unaffected.
- Probe logic is unit-tested against in-process mock targets (vulnerable and safe Flask
  fixtures). Docker tests are marked and skipped when Docker is unavailable.
- Stretch (fix verification) only if everything else passes.

## Frontend touch policy

Only additive changes. Expected touches: new rules and catalog wiring in `src/lib`, a `cwe`
field on findings, one extra category ("Unsafe code") in the existing lists, one extra
skip reason label, and deterministic options on the existing browser Ollama call. Every
touched file is listed in the final summary.
