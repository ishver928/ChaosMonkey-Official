'use strict'
require('./netguard')
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const project = require('../scripts/lib/project')
const { decideStop, decideSessionStart } = require('../scripts/lib/hooks')

const STOP = path.join(__dirname, '..', 'scripts', 'stop-hook.js')
const START = path.join(__dirname, '..', 'scripts', 'session-start-hook.js')

function tmp(prefix) {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)))
}

function enabledProject() {
  const root = tmp('cm-hook-')
  fs.writeFileSync(path.join(root, 'app.py'), 'print(1)\n')
  project.enable(root)
  return root
}

/** Run a hook script exactly like Claude Code does: JSON on stdin, read stdout + exit code. */
function runHook(script, input, env = {}) {
  const r = spawnSync(process.execPath, [script], { input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, ...env }, timeout: 15000 })
  return { code: r.status, out: r.stdout.trim(), json: r.stdout.trim() ? JSON.parse(r.stdout) : null }
}

const stopInput = (cwd, extra = {}) => ({ session_id: 's', transcript_path: 't', cwd, hook_event_name: 'Stop', stop_hook_active: false, ...extra })

test('stop hook: quiet when stop_hook_active is true', () => {
  const root = enabledProject()
  const r = runHook(STOP, stopInput(root, { stop_hook_active: true }))
  assert.equal(r.code, 0)
  assert.equal(r.out, '')
})

test('stop hook: quiet when the project is not enabled', () => {
  const root = tmp('cm-hook-')
  fs.writeFileSync(path.join(root, 'app.py'), 'x')
  const r = runHook(STOP, stopInput(root))
  assert.equal(r.code, 0)
  assert.equal(r.out, '')
  assert.ok(!fs.existsSync(path.join(root, '.chaosmonkey')), 'hook must not write into projects that are not enabled')
})

test('stop hook: blocks once with an ask-the-user reason when files changed, then stays quiet', () => {
  const root = enabledProject()
  const r = runHook(STOP, stopInput(root))
  assert.equal(r.code, 0)
  assert.equal(r.json.decision, 'block')
  assert.match(r.json.reason, /Run ChaosMonkey security analysis\? \(Y\/N\)/)
  assert.match(r.json.reason, /chaosmonkey_scan/)
  assert.match(r.json.reason, /chaosmonkey_decline_batch/)
  assert.ok(r.json.reason.includes(JSON.stringify(root)))
  // Claude asks and stops again (stop_hook_active) -> quiet; a later stop with no new changes -> quiet.
  assert.equal(runHook(STOP, stopInput(root, { stop_hook_active: true })).out, '')
  assert.equal(runHook(STOP, stopInput(root)).out, '')
})

test('stop hook: quiet when nothing changed since the last scan', () => {
  const root = enabledProject()
  project.writeState(root, { last_scan_fingerprint: project.fingerprint(root).hash })
  assert.equal(decideStop(stopInput(root)), null)
})

test('stop hook: quiet when the user declined this batch, asks again after new changes', () => {
  const root = enabledProject()
  project.writeState(root, { declined_fingerprint: project.fingerprint(root).hash })
  assert.equal(decideStop(stopInput(root)), null)
  fs.writeFileSync(path.join(root, 'new.js'), 'const a = 1\n')
  assert.equal(decideStop(stopInput(root)).decision, 'block')
})

test('stop hook: quiet for an enabled project with no code yet', () => {
  const root = tmp('cm-hook-')
  project.enable(root)
  assert.equal(decideStop(stopInput(root)), null)
})

test('stop hook: garbage stdin never blocks', () => {
  const r = spawnSync(process.execPath, [STOP], { input: 'not json', encoding: 'utf8' })
  assert.equal(r.status, 0)
  assert.equal(r.stdout, '')
})

test('session start: offers /chaosmonkey:enable once per project, never for enabled ones', () => {
  const data = tmp('cm-data-')
  const env = { CLAUDE_PLUGIN_DATA: data }
  const root = tmp('cm-proj-')
  const first = runHook(START, { session_id: 's', cwd: root, hook_event_name: 'SessionStart', source: 'startup' }, env)
  assert.equal(first.code, 0)
  assert.equal(first.json.hookSpecificOutput.hookEventName, 'SessionStart')
  assert.match(first.json.hookSpecificOutput.additionalContext, /\/chaosmonkey:enable/)
  const second = runHook(START, { session_id: 's2', cwd: root, hook_event_name: 'SessionStart', source: 'startup' }, env)
  assert.equal(second.out, '')
  assert.ok(!fs.existsSync(path.join(root, '.chaosmonkey')), 'offering must not touch the project')

  const enabled = enabledProject()
  const ctx = decideSessionStart({ cwd: enabled }, { env })
  assert.match(ctx, /enabled for this project/)
  assert.doesNotMatch(ctx, /chaosmonkey:enable/)
})

test('session start: never offers for the home folder', () => {
  assert.equal(decideSessionStart({ cwd: os.homedir() }, { env: { CLAUDE_PLUGIN_DATA: tmp('cm-data-') } }), null)
})

test('hooks.json uses exec form (no shell) for Windows', () => {
  const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'hooks', 'hooks.json'), 'utf8'))
  for (const event of ['Stop', 'SessionStart']) {
    const h = cfg.hooks[event][0].hooks[0]
    assert.equal(h.command, 'node')
    assert.ok(Array.isArray(h.args) && h.args[0].startsWith('${CLAUDE_PLUGIN_ROOT}/scripts/'))
  }
})
