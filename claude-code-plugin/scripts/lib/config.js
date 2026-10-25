'use strict'
/**
 * Configuration shared by the MCP server and the hooks. Everything here is local-only:
 * the backend URL must be loopback, and the ChaosMonkey checkout is found on disk.
 */
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])

function isLoopbackUrl(u) {
  try {
    const url = new URL(u)
    return url.protocol === 'http:' && LOOPBACK.has(url.hostname)
  } catch {
    return false
  }
}

/** Backend base URL. Refuses anything that isn't http on loopback (privacy guarantee). */
function backendUrl(env = process.env) {
  const raw = (env.CHAOSMONKEY_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '')
  if (!isLoopbackUrl(raw)) {
    throw new Error('CHAOSMONKEY_URL must be http://127.0.0.1:<port> (got a non-local URL). Refusing to continue.')
  }
  return raw
}

/** Per-user state outside any project: CLAUDE_PLUGIN_DATA when Claude Code sets it, else ~/.chaosmonkey. */
function dataDir(env = process.env) {
  const dir = env.CLAUDE_PLUGIN_DATA || path.join(os.homedir(), '.chaosmonkey')
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function homeFile() {
  return path.join(os.homedir(), '.chaosmonkey', 'home.json')
}

function looksLikeHome(dir) {
  return !!dir && fs.existsSync(path.join(dir, 'backend', 'app', 'main.py'))
}

/**
 * Locate the ChaosMonkey checkout (needed only to *start* the backend; a running backend is
 * reused without it). Order: CHAOSMONKEY_HOME, the folder above this plugin (when loaded with
 * --plugin-dir from the repo), then ~/.chaosmonkey/home.json written by register-home.js
 * (marketplace installs are copied into Claude's plugin cache, away from the repo).
 */
function findHome(env = process.env) {
  if (looksLikeHome(env.CHAOSMONKEY_HOME)) return path.resolve(env.CHAOSMONKEY_HOME)
  const fromPlugin = path.resolve(__dirname, '..', '..', '..')
  if (looksLikeHome(fromPlugin)) return fromPlugin
  try {
    const saved = JSON.parse(fs.readFileSync(homeFile(), 'utf8')).home
    if (looksLikeHome(saved)) return path.resolve(saved)
  } catch {
    // not registered
  }
  return null
}

function pythonFor(home, env = process.env) {
  if (env.CHAOSMONKEY_PYTHON) return env.CHAOSMONKEY_PYTHON
  const venv = process.platform === 'win32'
    ? path.join(home, 'backend', '.venv', 'Scripts', 'python.exe')
    : path.join(home, 'backend', '.venv', 'bin', 'python')
  if (fs.existsSync(venv)) return venv
  return process.platform === 'win32' ? 'python' : 'python3'
}

module.exports = { isLoopbackUrl, backendUrl, dataDir, findHome, homeFile, looksLikeHome, pythonFor }
