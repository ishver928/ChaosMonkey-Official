# ChaosMonkey: notes for Claude Code

ChaosMonkey scans AI-generated code for exposed secrets, personal data (PII) and unsafe storage, explains each risk, and suggests a fix. Hackathon project (Cal Hacks 13.0). **Everything runs locally: nothing may leave the user's machine.**

## Layout

- `frontend/`: done and working. React 19 + Vite + TypeScript (strict) + Tailwind v4. See `frontend/AGENTS.md` and `frontend/README.md`.
- `backend/`: **to build next** (doesn't exist yet). Python + FastAPI.

Run the frontend: `cd frontend && npm install && npm run dev` (http://127.0.0.1:5173). Check it: `npm run selftest`, `npx tsc --noEmit`, `npm run build`.

## Read these before building the backend

- `frontend/src/lib/types.ts`: data shapes (`Finding`, `ScanReport`, `Severity`, `Category`). Mirror them as Pydantic models so the two sides agree.
- `frontend/src/lib/rules.ts`: the 29 detection rules (ids like `CM-S004`). The backend should reuse these ids rather than invent new ones.
- `frontend/src/lib/redaction.ts`: how values are masked (`sk_live_••••••••a91f`).
- `frontend/src/lib/ollama.ts`: the existing optional local-LLM call (Ollama on 127.0.0.1:11434). Follow the same pattern if the backend uses a model.

An earlier backend prototype (FastAPI `/health`, a `/analyze` endpoint that redacts emails/phones in agent logs, `policy.py` allow/block decisions, pytest tests) lives in a separate repo: github.com/anjalis-onion/ChaosMonkey (`Backend/`). Copy from it rather than starting from zero.

## Hard rules (the whole pitch depends on these)

1. **No outbound network calls.** No cloud AI APIs, analytics or telemetry. Only localhost (e.g. Ollama at 127.0.0.1:11434).
2. **Never return, log or store raw secret/PII values.** Mask them before they leave a function. Raw values may exist in memory only.
3. Bind the server to `127.0.0.1` (not `0.0.0.0`), port **8000**.
4. CORS: allow `http://127.0.0.1:5173` and `http://localhost:5173` only.
5. Never commit `.env` files or real credentials. Demo data must use obviously fake or officially documented example keys.

## How the frontend will connect (not wired yet)

- Add a Vite dev proxy in `frontend/vite.config.ts`: `server.proxy = { '/api': 'http://127.0.0.1:8000' }`, so the browser only talks to its own origin. The offline guard (`frontend/src/lib/offlineGuard.ts`) and CSP then need no changes.
- Frontend calls `/api/health` to show "Backend: connected / offline". It must **fall back silently** to the in-browser scanner when the backend isn't running, the same way the Ollama integration does.
- Suggested starting endpoints: `GET /health`, then `POST /analyze` (agent log in, masked findings + allow/block decision out), using the shapes from `types.ts`.

## Conventions

- Small, focused commits with clear messages, committed by whoever wrote the code.
- Add pytest tests for each detector or policy (`backend/tests/`).
- Backend run command to document in `backend/README.md`: `uvicorn main:app --host 127.0.0.1 --port 8000 --reload`.
