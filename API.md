# Chaos Monkey API

Base URL: `http://127.0.0.1:8000`. All endpoints are prefixed with `/api`. CORS is enabled
only for `http://127.0.0.1:5173` and `http://localhost:5173`. The server binds to loopback
and refuses to start if any configured endpoint (e.g. Ollama) is not localhost.

Responses are JSON unless noted. Errors return a structured body: `{"error": "...", "detail": "..."}`
and the server never crashes on bad input.

## Contract vs. the existing frontend

The shipped frontend (`frontend/`) scans **entirely in the browser** via a Web Worker
(`src/lib/scanClient.ts` → `scanner.ts`) — there was no pre-existing backend scan contract.
The backend therefore:

- **Reuses the frontend's data shapes** (`Finding`, `ScanReport`, `Severity`, `Category`
  from `src/lib/types.ts`) and the **same rule ids** (`CM-S*`, `CM-P*`, `CM-D*`), adding
  backend-only fields (`cwe_id`, `evidence_snippet`, `attack_scenario`, `validation`,
  `severity_score`, `fix_diff`, `source`) as optional extensions.
- **Reuses the masking rules** from `src/lib/redaction.ts`.
- Adds the endpoints below. The only frontend change is a Vite dev proxy (`/api` →
  `127.0.0.1:8000`); the app falls back to the in-browser scanner when the backend is off.

## Health & privacy

### `GET /api/health`
```json
{
  "status": "ok",
  "mode": "full | mock | detector-only",
  "llm": { "available": true, "mode": "ollama|mock|offline", "model": "qwen2.5-coder:7b-instruct", "detail": "" },
  "kb_size": 32,
  "embed_backend": "ollama:nomic-embed-text | tfidf | keyword",
  "data_leaves_machine": false,
  "privacy_ok": true,
  "privacy_attestation": { "analysis_location": "local-machine", "model": "...", "seed": 42, "endpoints": ["http://127.0.0.1:11434"] }
}
```
`data_leaves_machine` is proven `false` by checking that every configured endpoint is loopback.

### `GET /api/determinism-check`
Runs the same scan twice and returns whether the reports are byte-identical.
```json
{ "identical": true, "hash_run1": "…", "hash_run2": "…", "finding_ids_run1": ["…"], "finding_ids_run2": ["…"] }
```

## Scanning

### `POST /api/scan`
Body (any one of `code`, `files`, `path`):
```json
{
  "name": "my scan",
  "code": "…",              "filename": "app.py",
  "files": [{ "path": "a.py", "content": "…" }],
  "path": "/abs/dir/or/file",
  "enabled_rule_ids": ["CM-S005", "CM-A001"],
  "use_llm": true,
  "chaos_mode": false
}
```
Returns `{ "scan_id": "scan_…", "status": "queued" }`. The scan runs in the background.

### `POST /api/scan/upload` (multipart)
Fields: `file` (a single file or a `.zip`), `name`, `use_llm`, `chaos_mode`. Returns a `scan_id`.

### `GET /api/scan/{id}`
```json
{ "scan_id": "…", "status": "queued|running|done|error", "stage": "detectors", "progress": 0.5, "report": { … } | null }
```

### `GET /api/scan/{id}/events` (SSE)
Server-Sent Events streaming live pipeline progress. Event `data` payloads include:
- `{ "stage": "ingest|detectors|llm|validation|fixes|chaos|done", "message": "…", "progress": 0.0-1.0 }`
- per finding: `{ "stage": "finding", "source": "detector", "rule": "CM-A001", "severity": "critical", "file": "…", "line": 4, "title": "…" }`
- a terminal `event: done` with `{ "status": "done" }`.

### `GET /api/scan/{id}/report?format=json|md|html|sarif`
Returns the canonical JSON, Markdown, a self-contained HTML report, or SARIF 2.1.0. Each
includes an executive summary, 0–100 security score, counts by severity, per-finding
evidence / CWE / attack scenario / fix diff, and the privacy attestation.

### `POST /api/scan/{id}/apply-fixes`
Applies every **verified** fix to a patched copy. Returns:
```json
{ "fixes_applied": 3, "combined_diff": "…unified diff…", "patched_files": { "app.py": "…patched content…" } }
```

## Knowledge base

### `GET /api/cwe/{id}`  — e.g. `/api/cwe/89` or `/api/cwe/CWE-89`
Full KB entry: name, description, consequences, mitigation, vulnerable/fixed examples, mapped rules.

### `GET /api/cwe/search?q=…`
`{ "query": "…", "results": [{ "id": "CWE-89", "name": "SQL Injection", "description": "…" }] }`

## Demo engine (SSE)

### `GET /api/demo/scenarios`
`{ "scenarios": [{ "key": "flask_store", "title": "…", "blurb": "…", "attacks": 5 }, …] }`

Scenarios: `flask_store`, `notes_api`, `ai_chatbot`.

### `POST /api/demo/{scenario}/attack?target=vulnerable|patched`
Launches the bundled demo app on `127.0.0.1` (ephemeral port) and streams scripted attacks.
Each attack event: `{ "type": "attack", "name": "sqli_login_bypass", "description": "…",
"request": "GET …", "response": "401 …", "verdict": "COMPROMISED|BLOCKED", "stolen": "masked/canary" }`,
ending with a `summary` then `done`.

### `POST /api/demo/{scenario}/scan`
Runs the real pipeline on the vulnerable source; streams progress then a `report` event.

### `POST /api/demo/{scenario}/fix`
Streams the verified fixes for the scenario.

### `POST /api/demo/{scenario}/replay`
Re-runs the same attacks against the patched app; streams a `comparison`:
`{ "before": { "compromised": 5, "total": 5 }, "after": { "compromised": 0, "total": 5 } }`.

### `POST /api/demo/{scenario}/full`
One SSE stream for the whole **Attack → Scan → Fix → Attack-again** sequence with stage
markers, ending in a `comparison` with both attack counts and before/after security scores.

### `POST /api/demo/{scenario}/reset`
Clears cached demo state.

## Chaos Mode

Pass `"chaos_mode": true` to `POST /api/scan`. In addition to the normal report, the scan
injects randomly chosen known-vulnerable snippets from the KB into a copy of the code and
verifies Chaos Monkey catches them, returning a detection rate in
`report.chaos_mode = { "injected": n, "detected": m, "detection_rate": 0.0-1.0, "details": [...] }`.

## Sandbox verification (additive)

Confirms whether specific static findings are actually exploitable by running the scanned app
in an isolated Docker sandbox and firing fixed, deterministic probes at it. No LLM involvement.
Existing endpoints/response shapes are unchanged; a `Finding` gains an optional `verification`
field once a sandbox run has touched it. See `backend/README.md` for the full threat model.

### `POST /api/sandbox/run`
```json
{ "scan_id": "scan_…", "finding_ids": ["…"] }
```
`finding_ids` omitted/`null` = verify every testable finding in the scan. Returns
`{ "sandbox_run_id": "…", "status": "queued" }`. Runs in the background.

### `GET /api/sandbox/{id}`
```json
{
  "id": "…", "scan_id": "scan_…",
  "status": "queued|running|done|error|docker_unavailable",
  "docker_available": true, "gvisor": false, "stack_detected": "flask|fastapi|express|unknown",
  "results": [{ "finding_id": "…", "ruleId": "CM-A001", "file": "app.py",
    "verification": { "status": "confirmed|not_confirmed|not_testable|skipped",
                       "probe_id": "sqli-v1", "evidence": "…", "detail": "…",
                       "sandbox_run_id": "…" } }],
  "canary_tag": "…", "requests_sent": 0, "error": "", "log": ["…"]
}
```
`not_confirmed` is never "safe" — it only means this probe didn't reproduce the issue. When
Docker isn't installed/running, `status` is `docker_unavailable` and every requested finding is
`not_testable` with the reason; the rest of ChaosMonkey is unaffected.

## Safety guardrails (demo simulator)

- Attacks only ever target the bundled demo apps on `127.0.0.1`; any non-loopback host is
  hard-refused.
- Only fake canary secrets/data are used; "stolen" data is shown masked or as obvious canaries.
- No real exploit tooling or network scanning.
- Demo app subprocesses are time-limited and killed on exit.
