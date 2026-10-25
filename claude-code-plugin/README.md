# ChaosMonkey for Claude Code

A Claude Code plugin that puts ChaosMonkey's local security checkpoint into your coding loop:

1. You enable ChaosMonkey for a project. The ChaosMonkey UI opens in your browser on a
   **Connected to Claude Code** page (project path, privacy status, analysis mode).
2. When Claude finishes generating or changing code, it asks **"Run ChaosMonkey security
   analysis? (Y/N)"**.
3. On **Y** the project is scanned by the existing ChaosMonkey backend and the same browser tab
   jumps to the report.
4. You tick **Approve fix** on the findings you want fixed, look at the diff, and click
   **Apply approved fixes to my project**. Nothing is written without that click.
5. Claude is told what was applied and whether each fix was verified by a re-scan.

The plugin is a thin wrapper. Detection, CWE retrieval (RAG), the local LLM, evidence
validation, severity scoring and fix verification all stay in the existing backend, unchanged.

## Guarantees

- **Local only.** The MCP server and hooks only talk to the backend on `127.0.0.1` and refuse
  any non-loopback `CHAOSMONKEY_URL`. The backend still binds to loopback, keeps its CORS list,
  and refuses non-local endpoints. No telemetry.
- **No secrets in Claude's context.** MCP tool results are built from an allowlist of metadata
  only: counts, severities, static rule titles, CWE ids and `file:line`. No code, snippets,
  evidence or values. A last-resort redaction pass runs on top. Tests check that the demo canary
  key never shows up.
- **You stay in control.** No MCP tool can apply fixes. Only the UI's two-step apply button
  writes files, and the backend checks that the request comes from the UI page's own origin.
- **Safe writes.** Only approved fixes that the backend already verified are applied. Each path
  must stay inside the project root: `..`, absolute paths, symlinks and junctions are rejected.
  The apply is refused if a file changed since the scan. Originals are backed up to
  `.chaosmonkey/backups/<timestamp>/`, and a re-scan reports `fix_verified` or `fix_failed`
  for each fix.
- **Honest mode.** The UI and the MCP summary show which analysis mode ran: `full` (local
  Ollama), `mock` (recorded responses) or `detector-only` (no Ollama).

## Requirements

- Claude Code (tested with 2.1.310 on Windows 11)
- Node.js 18+ on `PATH` (runs the MCP server and hooks; no npm packages needed)
- Git on `PATH` (Claude Code needs it for `plugin marketplace add`)
- The ChaosMonkey backend set up: `backend/.venv` with `backend/requirements.txt` installed
  (see the repo README)
- The frontend built once, so the backend can serve it: `cd frontend && npm install && npm run build`
- Optional: Ollama on `127.0.0.1:11434` for `full` mode

## Install (local marketplace)

From the repository root:

```bash
# 1. Build the UI the backend serves on http://127.0.0.1:8000
cd frontend && npm install && npm run build && cd ..

# 2. Tell the plugin where this checkout lives. Installed plugins are copied into Claude
#    Code's plugin cache, so the plugin can't find the checkout on its own. The path is only
#    needed to *start* the backend.
node claude-code-plugin/scripts/register-home.js

# 3. Add this folder as a local marketplace and install the plugin
claude plugin marketplace add ./claude-code-plugin
claude plugin install chaosmonkey@chaosmonkey-local
```

Inside a Claude Code session you can do the same with
`/plugin marketplace add ./claude-code-plugin` and `/plugin install chaosmonkey@chaosmonkey-local`,
then `/reload-plugins`.

To try it for one session without installing:

```bash
claude --plugin-dir ./claude-code-plugin
```

To uninstall: `claude plugin uninstall chaosmonkey@chaosmonkey-local` and
`claude plugin marketplace remove chaosmonkey-local`.

## Use

| Command | What it does |
| --- | --- |
| `/chaosmonkey:enable` | Claude asks Y/N first. On yes: writes `.chaosmonkey/enabled`, starts or reuses the backend, opens the UI. If the project already has code, Claude offers to scan right away. |
| `/chaosmonkey:scan` | Scans now and shows the report in the UI. |
| `/chaosmonkey:disable` | Turns the automatic prompt off for this project. Backups are kept. |

**Automatic prompt.** The Stop hook asks Claude to offer a scan after it changes code in an
enabled project. It stays quiet when the project isn't enabled, when nothing changed since the
last scan, when you declined this batch of changes, and when it already asked about the same
batch. The SessionStart hook makes Claude offer `/chaosmonkey:enable` once per project. It
never opens the browser at session start.

**One tab.** The UI sends a heartbeat and keeps an SSE stream open. While a tab is alive, new
scans move that tab to the report. Otherwise a new tab opens. The URL is always printed in
Claude Code too, in case the browser doesn't launch.

### MCP tools

`chaosmonkey_enable`, `chaosmonkey_disable`, `chaosmonkey_scan`, `chaosmonkey_status`,
`chaosmonkey_review_status` (a quick, non-blocking poll), and `chaosmonkey_decline_batch`.
Claude Code shows them as `mcp__plugin_chaosmonkey_chaosmonkey__<tool>`.

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `CHAOSMONKEY_URL` | `http://127.0.0.1:8000` | Backend URL. Must be loopback. |
| `CHAOSMONKEY_HOME` | from `register-home.js` | Path of the ChaosMonkey checkout. |
| `CHAOSMONKEY_PYTHON` | `backend/.venv` Python | Python used to start the backend. |
| `CHAOSMONKEY_NO_BROWSER` | unset | `1` = never launch a browser (CI, tests). |

Per-project state lives in `<project>/.chaosmonkey/`, which git-ignores itself. Per-user state
(`home.json`, `backend.log`, `offered.json`) lives in `~/.chaosmonkey/`, or in
`CLAUDE_PLUGIN_DATA` for hook state when Claude Code sets it.

## Tests

```bash
# plugin unit tests: MCP tools against a mock backend, hooks with mocked stdin, browser launch,
# masking; non-loopback sockets are blocked during the run
cd claude-code-plugin && npm test

# backend tests, including plugin routes, apply/backup/confinement, UI serving
cd backend && LLM_MOCK=1 ./.venv/Scripts/python -m pytest -q      # Windows
cd backend && LLM_MOCK=1 ./.venv/bin/python -m pytest -q           # macOS/Linux

# end-to-end: real MCP server over stdio -> real backend (started on demand) -> temp copy of
# the vulnerable demo app: enable -> UI served -> scan -> apply approved fixes -> review status
node claude-code-plugin/scripts/smoke-test.js --port 8765            # add --open-browser to see the UI

# regression gate: health + determinism hash + demo report hash vs. the recorded baseline
backend/.venv/Scripts/python claude-code-plugin/tests/regression_gate.py --compare claude-code-plugin/tests/baseline.json
```

## Verified vs. not verified

Verified on Windows 11 with Claude Code 2.1.310 and Node 24:

- `claude plugin validate --strict` passes for the plugin and the marketplace.
- `claude --plugin-dir` loads it. In real headless sessions (`claude -p`), the SessionStart
  hook added context, the MCP server connected over stdio, the Stop hook blocked once and
  Claude asked "Run ChaosMonkey security analysis? (Y/N)", and `/chaosmonkey:scan` returned
  the masked summary.
- `claude plugin marketplace add` and `claude plugin install` succeed (tested with a throwaway
  `CLAUDE_CONFIG_DIR`).
- The UI was checked in headless Edge: the connected view, the report with a masked diff,
  approve, two-step apply, and the re-scan results.

Not verified:

- A full **interactive** session from a marketplace install. Only `--plugin-dir` sessions
  were run, so the copied plugin's `register-home.js` lookup was not exercised end to end.
- The real **default-browser launch**. Tests use `CHAOSMONKEY_NO_BROWSER=1`, and the launcher
  command (`rundll32 url.dll,FileProtocolHandler` on Windows, `open` on macOS, `xdg-open` on
  Linux) is unit-tested only.
- **macOS/Linux**. The code avoids shell- and Windows-specific paths but hasn't run there.
- **Symlink rejection** on Windows: that test skips without Developer Mode. Junction
  rejection was tested.
- **`full` mode with Ollama**. Ollama wasn't running on the test machine, so live runs were
  `detector-only`, and the test suite uses `mock`.

## Limitations

- Scans and reviews live in the backend's memory. After a backend restart, old report links
  and review status are gone; scan again.
- If some other backend is already on port 8000 (for example an older ChaosMonkey without the
  plugin routes), the plugin stops and asks you to stop it. It never kills processes.
- Fixes are the backend's existing template fixes. Some only add a guiding comment, and a fix
  can need an import it doesn't add (for example `bcrypt`). The per-fix re-scan result says
  whether the issue is gone, not whether the app still runs.
- The origin check on apply stops accidental scripted applies. It isn't a security boundary
  against local software that forges browser headers.
