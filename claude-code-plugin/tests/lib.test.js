'use strict'
require('./netguard')
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { EventEmitter } = require('node:events')

const { browserCommand, openBrowser } = require('../scripts/lib/browser')
const project = require('../scripts/lib/project')
const { redact, pickFinding } = require('../scripts/lib/safe')

test('browser launch is cross-platform and shell-free', () => {
  const url = 'http://127.0.0.1:8000/?open=%2Fconnected#/connected'
  assert.deepEqual(browserCommand(url, 'win32'), ['rundll32', ['url.dll,FileProtocolHandler', url]])
  assert.deepEqual(browserCommand(url, 'darwin'), ['open', [url]])
  assert.deepEqual(browserCommand(url, 'linux'), ['xdg-open', [url]])
})

test('openBrowser only opens loopback URLs', async () => {
  const spawned = []
  const spawnFn = (cmd, args, opts) => {
    spawned.push({ cmd, args, opts })
    const child = new EventEmitter()
    child.unref = () => {}
    setImmediate(() => child.emit('spawn'))
    return child
  }
  assert.equal(await openBrowser('https://example.com', { spawnFn, env: {} }), false)
  assert.equal(spawned.length, 0)
  assert.equal(await openBrowser('http://127.0.0.1:8000/#/connected', { spawnFn, platform: 'win32', env: {} }), true)
  assert.equal(spawned[0].opts.detached, true)
  assert.equal(spawned[0].opts.shell, undefined)
})

test('fingerprint changes when files change and ignores .chaosmonkey and node_modules', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cm-fp-'))
  fs.writeFileSync(path.join(dir, 'a.py'), 'x = 1\n')
  const fp1 = project.fingerprint(dir)
  assert.equal(fp1.files, 1)
  project.writeState(dir, { anything: true })
  fs.mkdirSync(path.join(dir, 'node_modules', 'pkg'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'node_modules', 'pkg', 'i.js'), '1')
  assert.equal(project.fingerprint(dir).hash, fp1.hash)
  fs.writeFileSync(path.join(dir, 'b.js'), 'let y = 2\n')
  assert.notEqual(project.fingerprint(dir).hash, fp1.hash)
})

test('redact catches secrets that slipped through', () => {
  const t = redact('key sk-fake-DEMOCANARY0000000000000000000000canary and AKIAABCDEFGHIJKLMNOP and 123-45-6789 a@b.co')
  assert.ok(!t.includes('DEMOCANARY'))
  assert.ok(!t.includes('AKIAABCDEFGHIJKLMNOP'))
  assert.ok(!t.includes('123-45-6789'))
  assert.ok(!t.includes('a@b.co'))
})

test('pickFinding keeps only allowlisted, well-formed fields', () => {
  const f = pickFinding({ id: 'abcdef123456', rule_id: 'CM-S005', cwe_id: 'CWE-798', title: 'Hard-coded key', severity: 'critical', location: 'src/a.py:3', fix_available: true, fix_verified: true, snippet: 'secret', evidence_snippet: 'secret' })
  assert.deepEqual(Object.keys(f).sort(), ['cwe_id', 'fix_available', 'fix_verified', 'id', 'location', 'rule_id', 'severity', 'title'])
  assert.equal(pickFinding({ location: 'a.py:"x"' }).location, 'unknown location')
})
