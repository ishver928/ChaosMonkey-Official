'use strict'
/**
 * A tiny stand-in for the ChaosMonkey backend (127.0.0.1, random port) for MCP tool tests.
 * Its scan summary deliberately carries a raw canary secret and code in fields the MCP server
 * must never pass through, so tests can prove the allowlist holds.
 */
const http = require('node:http')

const CANARY = 'sk-fake-DEMOCANARY0000000000000000000000canary'
const SCAN_ID = 'scan_0123456789abcdef'

function startMockBackend(opts = {}) {
  const state = {
    calls: [],
    uiAlive: opts.uiAlive ?? false,
    health: opts.health ?? { status: 'ok', mode: 'mock', data_leaves_machine: false, privacy_ok: true },
    serveUi: opts.serveUi ?? true,
    pollsUntilDone: opts.pollsUntilDone ?? 1,
    review: opts.review ?? null,
    polls: 0,
  }

  const summary = () => ({
    scan_id: SCAN_ID,
    status: state.polls >= state.pollsUntilDone ? 'done' : 'running',
    stage: 'detectors',
    progress: 0.5,
    mode: 'mock',
    project_path: 'C:/proj',
    snippet: `OPENAI_API_KEY = "${CANARY}"`,
    summary: state.polls >= state.pollsUntilDone ? {
      security_score: 60,
      counts_by_severity: { critical: 2, high: 1, medium: 0, low: 0, info: 0 },
      total_findings: 3,
      files_scanned: 1,
      files_skipped: 0,
      llm_mock: true,
      data_leaves_machine: false,
      evidence_snippet: CANARY,
      findings: [
        { id: 'abc123abc123', rule_id: 'CM-S005', cwe_id: 'CWE-798', title: 'Hard-coded API key', severity: 'critical', location: 'app.py:24', fix_available: true, fix_verified: true, snippet: CANARY },
        { id: 'def456def456', rule_id: 'CM-A001', cwe_id: 'CWE-89', title: `Leaky title ${CANARY}`, severity: 'critical', location: `app.py:${CANARY}`, fix_available: true, fix_verified: false },
        { id: 'not-hex!', rule_id: 'evil', cwe_id: 'x', title: '<script>', severity: 'bogus', location: '../../etc/passwd:1', fix_available: 'yes' },
      ],
    } : undefined,
  })

  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      const parsed = body ? JSON.parse(body) : undefined
      state.calls.push({ method: req.method, url: req.url, body: parsed, headers: req.headers })
      const json = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)) }
      const url = req.url.split('?')[0]
      if (req.method === 'GET' && url === '/') {
        if (state.serveUi && (req.headers.accept || '').includes('text/html')) {
          res.writeHead(200, { 'Content-Type': 'text/html' })
          return res.end('<html></html>')
        }
        return json(200, { app: 'Chaos Monkey' })
      }
      if (url === '/api/health') return json(200, state.health)
      if (url === '/api/plugin/project') return json(200, { connected: false, mode: 'mock' })
      if (req.method === 'POST' && req.headers['x-chaosmonkey-client'] === undefined) return json(403, { detail: 'header' })
      if (url === '/api/plugin/connect') return json(200, { connected: true, project_path: parsed.project_path })
      if (url === '/api/plugin/disconnect') return json(200, { connected: false })
      if (url === '/api/plugin/navigate') return json(200, { delivered: state.uiAlive, ui_alive: state.uiAlive })
      if (url === '/api/scan') return json(200, { scan_id: SCAN_ID, status: 'queued' })
      if (url === '/api/plugin/link') return json(200, { scan_id: SCAN_ID })
      if (url === `/api/plugin/scan/${SCAN_ID}/summary`) {
        state.polls += 1
        return json(200, summary())
      }
      if (url === `/api/plugin/review/${SCAN_ID}`) return json(200, state.review)
      return json(404, { detail: 'not found' })
    })
  })

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const base = `http://127.0.0.1:${server.address().port}`
      resolve({ base, state, close: () => new Promise((r) => server.close(r)) })
    })
  })
}

module.exports = { startMockBackend, CANARY, SCAN_ID }
