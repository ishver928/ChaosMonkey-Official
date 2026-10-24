# ChaosMonkey

**Shake the code before it ships.** ChaosMonkey catches exposed API keys, personal data and unsafe storage in AI-generated code, explains why each one is dangerous, and hands you the fix. It runs on your own machine: your code never leaves it.

Built at Cal Hacks 13.0.

## Repository layout

| Folder | What's in it |
| --- | --- |
| [`frontend/`](frontend/) | React + Vite + TypeScript app: scanner, rule registry, built-in analyst, reports. Fully offline. |
| `backend/` | FastAPI service for agent-log analysis and policy decisions (coming next). |

## Run the frontend

```bash
cd frontend
npm install
npm run dev        # http://127.0.0.1:5173
```

See [`frontend/README.md`](frontend/README.md) for build, preview, the self-test, the optional local model (Ollama), and how local-only is enforced.
