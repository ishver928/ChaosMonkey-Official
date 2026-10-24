# ChaosMonkey

**Shake the code before it ships.** ChaosMonkey finds exposed API keys, personal data and unsafe storage in AI-generated code, explains why each one is dangerous, and hands you a before/after fix. It runs entirely in your browser: your code never leaves your machine.

Built for Cal Hacks 13.0.

## Quick start

Requires Node.js 20+ (tested on Node 24). pnpm works too; npm is shown here.

```bash
npm install
npm run dev        # opens http://127.0.0.1:5173
```

The first launch seeds a demo project (`ai-todo-app`), so the Report and History views are populated right away. Click **Load demo project** on the Scan page to re-run it at any time.

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server on `127.0.0.1:5173` (override with `PORT=4000`) |
| `npm run build` | Type-check (`tsc --noEmit`) and build to `dist/` with a strict CSP |
| `npm run preview` | Serve the production build on `127.0.0.1:5173` |
| `npm run typecheck` | `tsc --noEmit` only |
| `npm run selftest` | Scan the bundled demo project and assert the expected findings |
| `npm run logo` | Re-crop `logo-source.png` into `public/logo.png`, favicons and the mascot |

## What it checks

There are 29 deterministic rules, all listed with toggles on the **Rules** page:

- **Exposed secrets:** AWS key IDs and secret keys, GitHub tokens, Stripe live keys, OpenAI-style and Anthropic keys, Google API keys, Slack tokens, PEM private keys, JWTs, database URLs with passwords, hardcoded Bearer tokens, committed `.env` files, and high-entropy values assigned to names like `token`/`secret`/`password`. The entropy rule ignores placeholders like `YOUR_API_KEY` and `changeme`.
- **Personal information:** emails, phone numbers, SSNs, Luhn-checked card numbers, dates of birth, PII written to logs, and PII in query strings.
- **Unsafe storage:** tokens and profiles in `localStorage`/`sessionStorage`, MD5/SHA-1 password hashing, plaintext password columns, hardcoded JWT/session secrets, cookies missing `HttpOnly`/`Secure`/`SameSite`, secrets or PII written to files, disabled TLS verification, and `.env` files not covered by `.gitignore`.

Scanning runs in a Web Worker. Folder scans skip `node_modules`, `.git`, build output, binaries and files over 1 MB.

The **Rules** page has an in-app self-test with the same assertions as `npm run selftest`.

## Explanations: two engines

1. **Built-in analyst** (always on): a hand-written knowledge base per rule, covering a realistic attack scenario, what to do, and a before/after fix generated from templates (env vars, bcrypt, HttpOnly cookies, redacted logs…). Every secret finding starts with "rotate this credential now".
2. **Local model via Ollama** (optional): streams an explanation from a model on your own machine.

### Enabling the local model

```bash
# 1. Install Ollama from its website, then pull a small model:
ollama pull llama3.2:3b        # ~2 GB; qwen2.5-coder:3b also works well
# 2. Make sure it's running (the desktop app does this for you):
ollama serve
```

Then open **Settings → Local model (Ollama)**, switch it on, and pick the model. ChaosMonkey talks only to `http://127.0.0.1:11434` and sends only **masked** snippets plus a few masked surrounding lines. If Ollama isn't running, it quietly falls back to the built-in analyst.

If you serve the app from a non-default origin and Ollama rejects requests, allow it with `OLLAMA_ORIGINS=http://127.0.0.1:5173 ollama serve`.

## How we guarantee local-only

- **Offline guard** (`src/lib/offlineGuard.ts`), imported first in `main.tsx`. It wraps `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `WebSocket` and `EventSource`, and blocks any request whose host isn't this origin, `localhost` or `127.0.0.1`. Blocked attempts are logged with `console.warn` and counted. The count is shown live in the header ("Local only · nothing leaves this device · 0 blocked") and on the About page. That page also has a **Try to phone home** button that proves the guard works by sending to a reserved `.invalid` hostname.
- **Content-Security-Policy:** a small Vite plugin injects a strict CSP meta tag into production builds (`default-src 'self'`; `connect-src` limited to `'self'` and the local Ollama port; no frames, objects or external scripts). Dev mode skips it because React Refresh needs inline scripts.
- **No external assets:** fonts are self-hosted via `@fontsource` (Fredoka, Nunito, IBM Plex Mono), icons come from the bundled `lucide-react`, and images live in `public/`. No CDNs, analytics, telemetry or error reporters.
- **Masked storage:** only settings, rule toggles, dismissed-finding fingerprints and scan history are persisted, in `localStorage`. History holds names, counts and **masked** snippets, never file contents. Every write also passes through a scrubber that blanks anything still shaped like a credential, and exports (Markdown/JSON/HTML) go through the same scrubber. "Reveal" holds a raw value in memory for 20 seconds and never persists it.

## Demo data

`src/data/seedProject.ts` is a deliberately leaky "AI-written" todo app. Every credential in it is either an officially documented example or obviously fake:

- AWS's `AKIAIOSFODNN7EXAMPLE` key pair
- the jwt.io sample token
- Slack's documented `xoxb-not-a-real-token-this-will-not-work`
- Stripe/Visa test card numbers
- SSA-voided SSNs
- strings that literally say `DEMO`/`not-real`

None of them work anywhere.

## Project layout

```
src/
  main.tsx, App.tsx, index.css
  components/   brand, charts, code viewer + diff, finding detail, severity badges, status pill
  views/        Scan, Report, History, Rules, Settings, About
  lib/          rules (registry), scanner, redaction, knowledge (built-in analyst), ollama,
                exportReport, storage, intake, offlineGuard, selfTest, router
  workers/      scan.worker.ts
  data/         seedProject.ts
scripts/        selftest.ts, make-logo.mjs
public/         logo.png, favicon.png/.ico, apple-touch-icon.png, assets/chaosmonkey-mascot.png
```
