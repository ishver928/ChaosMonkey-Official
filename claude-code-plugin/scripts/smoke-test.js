#!/usr/bin/env node
'use strict'
/**
 * End-to-end smoke test: real MCP server over stdio -> real backend -> vulnerable demo fixture.
 *
 *   enable -> UI opens (or is pushed) -> scan -> (simulated UI click) apply approved fixes -> review status
 *
 * Runs against a temp COPY of demo/apps/flask_store/vulnerable.py, never the original.
 * Usage:  node claude-code-plugin/scripts/smoke-test.js [--port 8765] [--open-browser] [--keep]
 * Without --open-browser, CHAOSMONKEY_NO_BROWSER=1 is set and the "UI opens" step is checked by
 * asserting the backend serves the UI and that the tool reports the launch route.
 * The backend is started by the MCP server itself if nothing is listening on the port.
 */
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const http = require('node:http')
const { spawn } = require('node:child_process')
const { findHome } = require('./lib/config')

const args = process.argv.slice(2)
const port = args.includes('--port') ? args[args.indexOf('--port') + 1] : '8765'
const openBrowser = args.includes('--open-browser')
const keep = args.includes('--keep')
const BASE = `http://127.0.0.1:${port}`
const CANARY = 'sk-fake-DEMOCANARY0000000000000000000000canary'

const home = findHome()
if (!home) {
  console.error('Cannot find the ChaosMonkey checkout; set CHAOSMONKEY_HOME.')
  process.exit(2)
}

function check(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`)
    process.exitCode = 1
    throw new Error(msg)
  }
  console.log(`ok   ${msg}`)
}

function noLeak(text, where) {
  check(!text.includes(CANARY) && !text.includes('DEMOCANARY'), `${where}: no raw canary secret`)
}

function httpJson(method, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? Buffer.from(JSON.stringify(body)) : null
    const req = http.request(`${BASE}${p}`, {
      method,
      headers: { Accept: 'application/json', 'X-ChaosMonkey-Client': 'smoke-test', ...(payload ? { 'Content-Type': 'application/json' } : {}), ...headers },
    }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => resolve({ status: res.statusCode, text: data, type: res.headers['content-type'] || '', json: (() => { try { return JSON.parse(data) } catch { return null } })() }))
    })
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

function startMcp() {
  const env = { ...process.env, CHAOSMONKEY_URL: BASE, CHAOSMONKEY_HOME: home }
  if (!openBrowser) env.CHAOSMONKEY_NO_BROWSER = '1'
  const child = spawn(process.execPath, [path.join(__dirname, 'mcp-server.js')], { env, stdio: ['pipe', 'pipe', 'inherit'] })
  let buf = ''
  const pending = new Map()
  child.stdout.on('data', (c) => {
    buf += c
    let i
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i)
      buf = buf.slice(i + 1)
      if (!line.trim()) continue
      const msg = JSON.parse(line)
      pending.get(msg.id)?.(msg)
      pending.delete(msg.id)
    }
  })
  let id = 0
  const rpc = (method, params) => new Promise((resolve) => {
    id += 1
    pending.set(id, resolve)
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
  })
  const tool = async (name, a) => {
    const r = await rpc('tools/call', { name, arguments: a })
    const text = r.result.content.map((c) => c.text).join('\n')
    noLeak(JSON.stringify(r), `${name} response`)
    return { text, isError: r.result.isError }
  }
  return { child, rpc, tool }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function main() {
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-smoke-'))
  fs.copyFileSync(path.join(home, 'demo', 'apps', 'flask_store', 'vulnerable.py'), path.join(proj, 'app.py'))
  const root = fs.realpathSync.native(proj)
  console.log(`project copy: ${root}\nbackend: ${BASE}`)
  const mcp = startMcp()
  try {
    const init = await mcp.rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } })
    check(init.result.serverInfo.name === 'chaosmonkey', 'MCP initialize')
    const list = await mcp.rpc('tools/list', {})
    check(list.result.tools.length >= 5, `tools/list (${list.result.tools.map((t) => t.name).join(', ')})`)

    // ENABLE
    const en = await mcp.tool('chaosmonkey_enable', { project_path: root })
    console.log(en.text.replace(/^/gm, '     | '))
    check(!en.isError, 'chaosmonkey_enable succeeded')
    check(fs.existsSync(path.join(root, '.chaosmonkey', 'enabled')), '.chaosmonkey/enabled written')
    check(/#\/connected/.test(en.text), 'enable prints the connected-view URL')
    const ui = await httpJson('GET', '/', null, { Accept: 'text/html' })
    check(ui.status === 200 && ui.type.includes('text/html'), 'backend serves the built UI on the same port')
    const health = await httpJson('GET', '/api/health')
    check(health.json.data_leaves_machine === false && health.json.privacy_ok === true, `health: data_leaves_machine=false, privacy_ok=true (mode ${health.json.mode})`)
    const proj1 = await httpJson('GET', '/api/plugin/project')
    check(proj1.json.project_path && proj1.json.connected, 'backend knows the connected project')

    // ONE TAB: simulate a live tab heartbeat, then a scan must push instead of opening.
    await httpJson('POST', '/api/plugin/heartbeat', { route: '#/connected' })

    // SCAN
    const sc = await mcp.tool('chaosmonkey_scan', { project_path: root })
    console.log(sc.text.replace(/^/gm, '     | '))
    check(!sc.isError, 'chaosmonkey_scan succeeded')
    const scanId = (sc.text.match(/scan_[0-9a-f]{16}/) || [])[0]
    check(!!scanId, `scan id ${scanId}`)
    check(/pushed to the open ChaosMonkey tab/.test(sc.text), 'live tab was pushed to the report (no new tab)')
    check(/Analysis mode: /.test(sc.text), 'summary states the analysis mode')
    let st = await mcp.tool('chaosmonkey_status', { scan_id: scanId })
    for (let i = 0; i < 60 && !/: done/.test(st.text.split('\n')[0]); i += 1) {
      await sleep(1000)
      st = await mcp.tool('chaosmonkey_status', { scan_id: scanId })
    }
    check(/: done/.test(st.text.split('\n')[0]), 'scan finished')
    check(/Security score: \d+\/100/.test(st.text), 'status has score + counts')

    const full = await httpJson('GET', `/api/scan/${scanId}`)
    const findings = full.json.report.findings
    noLeak(full.text, 'existing /api/scan report')
    const fixable = findings.filter((f) => f.fix_verified && f.fix_diff)
    check(fixable.length > 0, `${fixable.length} verified fix(es) available`)

    if (args.includes('--phase1')) return

    // APPLY (Phase 2): exactly what the UI's "Apply approved fixes" button sends.
    const approved = fixable.filter((f) => f.ruleId === 'CM-A005' || f.cwe_id === 'CWE-798').map((f) => f.id)
    check(approved.length > 0, `approving ${approved.length} fix(es) (debug mode / hard-coded key)`)
    const before = fs.readFileSync(path.join(root, 'app.py'), 'utf8')
    const noOrigin = await httpJson('POST', `/api/plugin/scan/${scanId}/apply`, { finding_ids: approved })
    check(noOrigin.status === 403, 'apply without the UI page Origin is refused (no scripted apply)')
    const ap = await httpJson('POST', `/api/plugin/scan/${scanId}/apply`, { finding_ids: approved }, { Origin: BASE })
    check(ap.status === 200, `apply accepted (${ap.status} ${ap.status !== 200 ? ap.text : ''})`)
    noLeak(ap.text, 'apply response')
    let rv = await mcp.tool('chaosmonkey_review_status', { scan_id: scanId })
    for (let i = 0; i < 60 && /applying|rescanning/.test(rv.text.split('\n')[0]); i += 1) {
      await sleep(1000)
      rv = await mcp.tool('chaosmonkey_review_status', { scan_id: scanId })
    }
    console.log(rv.text.replace(/^/gm, '     | '))
    check(/applied/.test(rv.text.split('\n')[0]), 'review status reports applied')
    const after = fs.readFileSync(path.join(root, 'app.py'), 'utf8')
    check(after !== before, 'project file was changed')
    check(!after.includes(CANARY), 'hard-coded canary key removed from the project file')
    const backups = fs.readdirSync(path.join(root, '.chaosmonkey', 'backups'))
    check(backups.length === 1 && fs.readFileSync(path.join(root, '.chaosmonkey', 'backups', backups[0], 'app.py'), 'utf8') === before, 'original backed up under .chaosmonkey/backups/<timestamp>')
    check(/fix_verified/.test(rv.text), 'per-fix verification reported')
    const again = await httpJson('POST', `/api/plugin/scan/${scanId}/apply`, { finding_ids: approved }, { Origin: BASE })
    check(again.status === 409, 'second apply of the same scan is refused (files changed since scan)')
  } finally {
    mcp.child.stdin.end()
    if (!keep) fs.rmSync(proj, { recursive: true, force: true })
  }
  console.log(process.exitCode ? 'SMOKE TEST FAILED' : 'SMOKE TEST PASSED')
}

main().catch((err) => {
  console.error(err.stack || String(err))
  process.exitCode = 1
})
