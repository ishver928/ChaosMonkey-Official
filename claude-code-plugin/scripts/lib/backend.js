'use strict'
/**
 * Thin HTTP client for the existing ChaosMonkey backend, plus "start it or reuse it".
 * Loopback only: every request goes to backendUrl(), which refuses non-local hosts.
 */
const fs = require('node:fs')
const http = require('node:http')
const path = require('node:path')
const { spawn } = require('node:child_process')
const { backendUrl, dataDir, findHome, isLoopbackUrl, pythonFor } = require('./config')

const CLIENT_HEADER = { 'X-ChaosMonkey-Client': 'claude-code-plugin' }

class BackendError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

function makeClient(base = backendUrl()) {
  if (!isLoopbackUrl(base)) throw new Error('Refusing a non-loopback backend URL.')

  function request(method, pathname, body, { timeoutMs = 10000, accept = 'application/json' } = {}) {
    const url = new URL(pathname, base + '/')
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body))
    return new Promise((resolve, reject) => {
      const req = http.request(url, {
        method,
        headers: {
          Accept: accept,
          ...CLIENT_HEADER,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        },
        timeout: timeoutMs,
      }, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          let json = null
          try { json = JSON.parse(text) } catch { /* not JSON */ }
          if (res.statusCode >= 400) {
            const detail = json && (json.detail || json.error)
            reject(new BackendError(`${method} ${url.pathname} -> ${res.statusCode}${detail ? `: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}` : ''}`, res.statusCode))
            return
          }
          resolve({ status: res.statusCode, json, text, contentType: res.headers['content-type'] || '' })
        })
      })
      req.on('timeout', () => req.destroy(new BackendError(`${method} ${url.pathname} timed out`)))
      req.on('error', reject)
      if (payload) req.write(payload)
      req.end()
    })
  }

  return {
    base,
    request,
    get: (p, opts) => request('GET', p, undefined, opts).then((r) => r.json),
    post: (p, body, opts) => request('POST', p, body ?? {}, opts).then((r) => r.json),
  }
}

/** The privacy attestation we require before handing the backend any project path. */
function checkHealth(h) {
  if (!h || h.status !== 'ok' || !('data_leaves_machine' in h)) {
    return 'Something other than ChaosMonkey is answering on the backend port.'
  }
  if (h.data_leaves_machine !== false || h.privacy_ok !== true) {
    return 'The ChaosMonkey backend reports a non-local endpoint (privacy check failed). Refusing to scan.'
  }
  return null
}

async function tryHealth(client) {
  try {
    return await client.get('/api/health', { timeoutMs: 4000 })
  } catch {
    return null
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * Reuse a running backend, or start the existing one (uvicorn app.main:app) bound to
 * 127.0.0.1 on the configured port. Never binds anything else.
 */
async function ensureBackend(client, { env = process.env, spawnFn = spawn, waitMs = 45000 } = {}) {
  let health = await tryHealth(client)
  if (health) {
    const problem = checkHealth(health)
    if (problem) throw new Error(problem)
    return { health, started: false }
  }
  const home = findHome(env)
  if (!home) {
    throw new Error('The ChaosMonkey backend is not running and the ChaosMonkey folder could not be found. '
      + 'Run `node <ChaosMonkey>/claude-code-plugin/scripts/register-home.js` once, or set CHAOSMONKEY_HOME.')
  }
  const port = new URL(client.base).port || '80'
  const python = pythonFor(home, env)
  const logPath = path.join(dataDir(env), 'backend.log')
  const log = fs.openSync(logPath, 'a')
  const child = spawnFn(python, ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(port)], {
    cwd: path.join(home, 'backend'),
    detached: true,
    stdio: ['ignore', log, log],
    windowsHide: true,
    env: { ...env, HOST: '127.0.0.1', PORT: String(port) },
  })
  let spawnError = null
  child.on('error', (e) => { spawnError = e })
  child.unref()
  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    if (spawnError) throw new Error(`Could not start the backend with ${python}: ${spawnError.message}`)
    await sleep(500)
    health = await tryHealth(client)
    if (health) {
      const problem = checkHealth(health)
      if (problem) throw new Error(problem)
      return { health, started: true, logPath }
    }
  }
  throw new Error(`The backend did not come up within ${Math.round(waitMs / 1000)}s. See ${logPath}.`)
}

/** Does the backend serve the built UI from its own origin? */
async function uiServed(client) {
  try {
    const r = await client.request('GET', '/', undefined, { accept: 'text/html', timeoutMs: 4000 })
    return r.contentType.includes('text/html')
  } catch {
    return false
  }
}

module.exports = { BackendError, makeClient, checkHealth, ensureBackend, uiServed }
