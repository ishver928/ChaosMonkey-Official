'use strict'
/** Cross-platform "open this URL in the default browser", spawned without a shell (no quoting bugs). */
const { spawn } = require('node:child_process')
const { isLoopbackUrl } = require('./config')

function browserCommand(url, platform = process.platform) {
  if (platform === 'win32') return ['rundll32', ['url.dll,FileProtocolHandler', url]]
  if (platform === 'darwin') return ['open', [url]]
  return ['xdg-open', [url]]
}

/** Only ever opens the local ChaosMonkey UI. Resolves true if the launcher process started. */
function openBrowser(url, { platform = process.platform, spawnFn = spawn, env = process.env } = {}) {
  if (!isLoopbackUrl(url)) return Promise.resolve(false)
  if (env.CHAOSMONKEY_NO_BROWSER === '1') return Promise.resolve(false)
  const [cmd, args] = browserCommand(url, platform)
  return new Promise((resolve) => {
    try {
      const child = spawnFn(cmd, args, { detached: true, stdio: 'ignore', windowsHide: true })
      child.on('error', () => resolve(false))
      child.on('spawn', () => { child.unref(); resolve(true) })
    } catch {
      resolve(false)
    }
  })
}

module.exports = { browserCommand, openBrowser }
