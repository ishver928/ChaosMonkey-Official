'use strict'
/**
 * Decision logic for the plugin's hooks, kept pure-ish so it can be unit tested with mocked input.
 * Hooks never start the backend, open a browser or scan: they only add instructions for Claude,
 * which must then ask the user (Y/N) before calling any ChaosMonkey tool.
 */
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const project = require('./project')
const { dataDir } = require('./config')

const TOOL = (name) => `mcp__plugin_chaosmonkey_chaosmonkey__${name}`

function projectRoot(input, env) {
  const dir = (input && typeof input.cwd === 'string' && input.cwd) || env.CLAUDE_PROJECT_DIR || ''
  if (!dir || !path.isAbsolute(dir)) return null
  try {
    return fs.realpathSync.native(dir)
  } catch {
    return null
  }
}

/** Stop hook: returns null (let Claude stop) or { decision: 'block', reason } (ask the user first). */
function decideStop(input, { env = process.env } = {}) {
  if (!input || typeof input !== 'object') return null
  if (input.stop_hook_active === true) return null
  const root = projectRoot(input, env)
  if (!root || !project.isEnabled(root)) return null
  const fp = project.fingerprint(root)
  if (fp.files === 0) return null
  const st = project.readState(root)
  if (fp.hash === st.last_scan_fingerprint) return null // nothing changed since the last scan
  if (fp.hash === st.declined_fingerprint) return null // the user said no to this batch
  if (fp.hash === st.prompted_fingerprint) return null // already asked about exactly this batch
  project.writeState(root, { prompted_fingerprint: fp.hash, prompted_at: new Date().toISOString() })
  return {
    decision: 'block',
    reason: [
      'ChaosMonkey (a local-only security checker) is enabled for this project, and project files changed since the last ChaosMonkey scan.',
      'Before finishing, ask the user exactly: "Run ChaosMonkey security analysis? (Y/N)" and then end your turn to wait for the answer. Do not call any ChaosMonkey tool yet.',
      `If the user answers yes: call ${TOOL('chaosmonkey_scan')} with project_path ${JSON.stringify(root)} and share the summary and report link.`,
      `If the user answers no: call ${TOOL('chaosmonkey_decline_batch')} with the same project_path.`,
      'Never apply ChaosMonkey fixes yourself; the user approves and applies them in the ChaosMonkey UI.',
    ].join('\n'),
  }
}

function offeredFile(env) {
  return path.join(dataDir(env), 'offered.json')
}

function readOffered(env) {
  try {
    return JSON.parse(fs.readFileSync(offeredFile(env), 'utf8'))
  } catch {
    return {}
  }
}

function markOffered(env, root) {
  const all = readOffered(env)
  all[root.toLowerCase()] = new Date().toISOString()
  fs.writeFileSync(offeredFile(env), JSON.stringify(all, null, 2) + '\n')
}

/** SessionStart hook: returns additional context for Claude, or null. Never opens the UI. */
function decideSessionStart(input, { env = process.env } = {}) {
  const root = projectRoot(input, env)
  if (!root) return null
  if (project.isEnabled(root)) {
    return [
      'ChaosMonkey (local-only security scanning) is enabled for this project.',
      'After you finish generating or changing code, a Stop hook will remind you to ask the user whether to run a ChaosMonkey scan; only scan on a yes.',
      'Fixes are reviewed and applied by the user in the ChaosMonkey UI, never by you automatically.',
    ].join(' ')
  }
  // Never nag about the home folder or a drive root.
  if (root === os.homedir() || path.dirname(root) === root) return null
  const key = root.toLowerCase()
  if (readOffered(env)[key]) return null // offered once already (accepted, declined or ignored)
  markOffered(env, root)
  return [
    'The ChaosMonkey plugin (local-only security scanning for AI-generated code) is installed but not enabled for this project.',
    'Once in this session, when it fits naturally (for example before you start generating code), briefly offer the user: "Want to enable ChaosMonkey security checks for this project? Run /chaosmonkey:enable". Do not enable it yourself and do not offer again if they decline or ignore it.',
  ].join(' ')
}

function readStdin(timeoutMs = 3000) {
  return new Promise((resolve) => {
    let data = ''
    const done = () => resolve(data)
    const timer = setTimeout(done, timeoutMs)
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (c) => { data += c })
    process.stdin.on('end', () => { clearTimeout(timer); done() })
    process.stdin.on('error', () => { clearTimeout(timer); done() })
  })
}

function parseInput(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

module.exports = { decideStop, decideSessionStart, readStdin, parseInput, offeredFile }
