'use strict'
require('./netguard')
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const http = require('node:http')

const { makeClient, checkHealth } = require('../scripts/lib/backend')
const { createTools, TOOL_DEFS } = require('../scripts/lib/tools')
const { createServer } = require('../scripts/mcp-server')
const { backendUrl } = require('../scripts/lib/config')
const project = require('../scripts/lib/project')
const { startMockBackend, CANARY, SCAN_ID } = require('./mock-backend')

function tmpProject(withCode = true) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-proj-'))
  if (withCode) fs.writeFileSync(path.join(dir, 'app.py'), 'print("hi")\n')
  return fs.realpathSync.native(dir)
}

async function setup(opts) {
  const mock = await startMockBackend(opts)
  const opened = []
  const client = makeClient(mock.base)
  const tools = createTools({
    client,
    open: async (url) => { opened.push(url); return true },
    ensure: async (c) => ({ health: await c.get('/api/health'), started: false }),
    pollMs: 5,
    scanWaitMs: 2000,
  })
  return { mock, tools, opened }
}

test('netguard blocks non-loopback connections', async () => {
  await assert.rejects(() => new Promise((resolve, reject) => {
    try {
      http.get('http://93.184.216.34/', resolve).on('error', reject)
    } catch (e) { reject(e) }
  }), /netguard/)
})

test('backend URL must be loopback', () => {
  assert.equal(backendUrl({}), 'http://127.0.0.1:8000')
  assert.throws(() => backendUrl({ CHAOSMONKEY_URL: 'http://example.com:8000' }), /non-local/)
  assert.throws(() => backendUrl({ CHAOSMONKEY_URL: 'https://10.0.0.5:8000' }), /non-local/)
  assert.throws(() => makeClient('http://192.168.1.2:8000'), /non-loopback/)
})

test('health check refuses a non-private backend', () => {
  assert.equal(checkHealth({ status: 'ok', data_leaves_machine: false, privacy_ok: true }), null)
  assert.match(checkHealth({ status: 'ok', data_leaves_machine: true, privacy_ok: false }), /privacy/)
  assert.match(checkHealth({ hello: 'world' }), /other than ChaosMonkey/)
})

test('enable writes the marker, connects, and opens the connected view when no tab is alive', async () => {
  const { mock, tools, opened } = await setup({ uiAlive: false })
  const root = tmpProject()
  try {
    const text = await tools.call('chaosmonkey_enable', { project_path: root })
    assert.ok(project.isEnabled(root))
    assert.equal(fs.readFileSync(path.join(root, '.chaosmonkey', '.gitignore'), 'utf8'), '*\n')
    assert.equal(opened.length, 1)
    assert.match(opened[0], /^http:\/\/127\.0\.0\.1:\d+\/\?open=%2Fconnected#\/connected$/)
    assert.match(text, /#\/connected/)
    assert.match(text, /local only/)
    assert.match(text, /Ask the user whether to run a ChaosMonkey scan now/)
    const connect = mock.state.calls.find((c) => c.url === '/api/plugin/connect')
    assert.equal(connect.body.project_path, root)
    assert.ok(connect.headers['x-chaosmonkey-client'])
  } finally {
    await mock.close()
  }
})

test('enable on an empty project says it is waiting for code', async () => {
  const { mock, tools } = await setup()
  try {
    const text = await tools.call('chaosmonkey_enable', { project_path: tmpProject(false) })
    assert.match(text, /waiting for code/)
  } finally {
    await mock.close()
  }
})

test('a live tab is pushed instead of opening a new one', async () => {
  const { mock, tools, opened } = await setup({ uiAlive: true })
  try {
    const text = await tools.call('chaosmonkey_scan', { project_path: tmpProject() })
    assert.equal(opened.length, 0)
    assert.match(text, /pushed to the open ChaosMonkey tab/)
    const nav = mock.state.calls.find((c) => c.url === '/api/plugin/navigate')
    assert.equal(nav.body.route, `/report/${SCAN_ID}`)
  } finally {
    await mock.close()
  }
})

test('scan uses the existing scan-by-path API, links it, polls, and returns masked metadata only', async () => {
  const { mock, tools, opened } = await setup({ pollsUntilDone: 3 })
  const root = tmpProject()
  try {
    const text = await tools.call('chaosmonkey_scan', { project_path: root })
    const scan = mock.state.calls.find((c) => c.url === '/api/scan')
    assert.equal(scan.body.path, root)
    assert.ok(mock.state.calls.some((c) => c.url === '/api/plugin/link'))
    assert.equal(opened.length, 1)
    assert.match(text, /Security score: 60\/100/)
    assert.match(text, /2 critical, 1 high/)
    assert.match(text, /Hard-coded API key \(CWE-798\) at app\.py:24; verified fix available/)
    assert.match(text, /Analysis mode: mock/)
    assert.match(text, /Nothing is applied automatically/)
    // Allowlist: the canary planted in snippet/evidence/title/location never reaches Claude.
    assert.ok(!text.includes(CANARY), 'raw canary leaked into MCP output')
    assert.ok(!text.includes('DEMOCANARY'), 'canary body leaked into MCP output')
    assert.ok(!text.includes('OPENAI_API_KEY'), 'code leaked into MCP output')
    assert.ok(!text.includes('<script>'))
    assert.ok(!text.includes('etc/passwd') || /unknown location/.test(text))
    const state = project.readState(root)
    assert.equal(state.last_scan_id, SCAN_ID)
    assert.ok(state.last_scan_fingerprint)
  } finally {
    await mock.close()
  }
})

test('status returns the masked summary', async () => {
  const { mock, tools } = await setup()
  try {
    const text = await tools.call('chaosmonkey_status', { scan_id: SCAN_ID })
    assert.match(text, /done/)
    assert.ok(!text.includes(CANARY))
    await assert.rejects(() => tools.call('chaosmonkey_status', { scan_id: '../../etc' }), /scan_id must look like/)
  } finally {
    await mock.close()
  }
})

test('disable removes the marker and decline records the batch', async () => {
  const { mock, tools } = await setup()
  const root = tmpProject()
  try {
    await tools.call('chaosmonkey_enable', { project_path: root })
    await tools.call('chaosmonkey_decline_batch', { project_path: root })
    assert.equal(project.readState(root).declined_fingerprint, project.fingerprint(root).hash)
    await tools.call('chaosmonkey_disable', { project_path: root })
    assert.equal(project.isEnabled(root), false)
  } finally {
    await mock.close()
  }
})

test('project_path must be an absolute existing folder', async () => {
  const { mock, tools } = await setup()
  try {
    await assert.rejects(() => tools.call('chaosmonkey_scan', { project_path: 'relative/dir' }), /absolute/)
    await assert.rejects(() => tools.call('chaosmonkey_scan', { project_path: path.join(os.tmpdir(), 'cm-does-not-exist-xyz') }), /existing folder/)
  } finally {
    await mock.close()
  }
})

test('refuses to scan when the backend privacy attestation fails', async () => {
  const mock = await startMockBackend({ health: { status: 'ok', data_leaves_machine: true, privacy_ok: false } })
  const { ensureBackend } = require('../scripts/lib/backend')
  try {
    const tools = createTools({ client: makeClient(mock.base), open: async () => true, ensure: ensureBackend })
    await assert.rejects(() => tools.call('chaosmonkey_scan', { project_path: tmpProject() }), /privacy check failed/)
    assert.ok(!mock.state.calls.some((c) => c.url === '/api/scan'))
  } finally {
    await mock.close()
  }
})

test('MCP protocol: initialize, tools/list, tools/call, unknown method', async () => {
  const { mock, tools } = await setup()
  const out = []
  const server = createServer({ tools, write: (m) => out.push(m) })
  try {
    await server.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } })
    assert.equal(out[0].result.serverInfo.name, 'chaosmonkey')
    assert.equal(out[0].result.protocolVersion, '2025-06-18')
    await server.handle({ jsonrpc: '2.0', method: 'notifications/initialized' })
    assert.equal(out.length, 1)
    await server.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
    assert.deepEqual(out[1].result.tools.map((t) => t.name), TOOL_DEFS.map((t) => t.name))
    await server.handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'chaosmonkey_status', arguments: { scan_id: SCAN_ID } } })
    assert.equal(out[2].result.isError, false)
    assert.ok(!JSON.stringify(out[2]).includes(CANARY))
    await server.handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'chaosmonkey_status', arguments: { scan_id: 'bad' } } })
    assert.equal(out[3].result.isError, true)
    await server.handle({ jsonrpc: '2.0', id: 5, method: 'nope' })
    assert.equal(out[4].error.code, -32601)
  } finally {
    await mock.close()
  }
})
