# ChaosMonkey

React + Vite + Tailwind CSS app (originally scaffolded by Figma Make). Fully local and offline: no network calls except same-origin and the optional Ollama at 127.0.0.1:11434.

## Development Server

Run `npm run dev` (Vite on http://127.0.0.1:5173, override with `PORT`). `npm run build` type-checks and builds; `npm run selftest` asserts the scanner's findings on the demo project.

- Never add CDNs, Google Fonts, remote images, analytics or external fetches. `src/lib/offlineGuard.ts` must stay the first import in `src/main.tsx`.
- Never persist raw secret/PII values; storage and exports go through `scrub()` in `src/lib/redaction.ts`.

## Project Structure

This is the canonical project structure. Start with task-relevant files below. Only follow imports or inspect other files when required, when a documented path is missing, or when the repository contradicts this guide.

- `src/main.tsx` - React entrypoint; imports `src/index.css` and mounts `src/App.tsx` into the `#root` element
- `src/App.tsx` - Primary application component and the usual starting point for UI work
- `src/index.css` - Global CSS entrypoint and Tailwind CSS v4 import
- `index.html` - Vite HTML shell containing the `#root` element and loading `src/main.tsx`
- `package.json` - Project dependencies and the Vite build, development, preview, and formatting scripts
- `vite.config.ts` - Vite configuration with React, Tailwind CSS v4, a build-only CSP plugin, and the `@` alias for `src`
- `src/lib/` - rules registry, scanner, redaction, built-in analyst, Ollama client, exports, storage, offline guard
- `src/views/`, `src/components/`, `src/workers/`, `src/data/` - UI, scan worker and seeded demo project

## Dependencies

- Runtime: React 19 and React DOM 19
- Styling: Tailwind CSS v4 with the `@tailwindcss/vite` plugin
- Build tooling: Vite 8, TypeScript 5.7, and `@vitejs/plugin-react`
- Icons: lucide-react; fonts: @fontsource (Fredoka, Nunito, IBM Plex Mono)

## Styling

This project uses **Tailwind CSS v4** through the `@tailwindcss/vite` plugin configured in `vite.config.ts`. `src/index.css` imports Tailwind with `@import 'tailwindcss';`. Use Tailwind utility classes directly in JSX and put global CSS or Tailwind v4 theme customization in `src/index.css`. This scaffold does not need a Tailwind config file or PostCSS config.

`src/main.tsx` imports `src/index.css`, so global font wiring belongs in `src/index.css`. Keep CSS `@import` statements first, then add any `@font-face` rules and font-family defaults there.

Tailwind emits utility classes in `@layer utilities`, and CSS outside any cascade layer overrides every layer regardless of specificity. Put global element styles, such as resets and defaults for `body`, headings, `button`, or `input`, inside `@layer base { ... }` so utility classes on those elements still apply. Tailwind's Preflight already applies `box-sizing: border-box`, removes default margins, and sets `font: inherit` on form controls, so do not repeat those rules.
