import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self' http://127.0.0.1:11434 http://localhost:11434",
  "worker-src 'self' blob:",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

/** Injects a strict CSP meta tag into the built HTML. Dev is skipped: React Refresh needs inline scripts. */
function contentSecurityPolicy(): Plugin {
  return {
    name: 'chaosmonkey-csp',
    apply: 'build',
    transformIndexHtml() {
      return [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP }, injectTo: 'head-prepend' }]
    },
  }
}

const port = parseInt(process.env.PORT || '5173')

export default defineConfig({
  plugins: [react(), tailwindcss(), contentSecurityPolicy()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  // Proxy /api to the local Chaos Monkey backend so the browser only ever talks to its
  // own origin (keeps the offline guard and CSP happy). The backend is optional: the app
  // falls back to the in-browser scanner when it is not running.
  server: { host: '127.0.0.1', port, open: true, proxy: { '/api': 'http://127.0.0.1:8000' } },
  preview: { host: '127.0.0.1', port, open: true, proxy: { '/api': 'http://127.0.0.1:8000' } },
})
