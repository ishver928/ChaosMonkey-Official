'use strict'
/**
 * MCP tool implementations. Each one only CALLS the existing backend; detection, CWE retrieval,
 * LLM, validation, severity and fix verification all stay in the backend untouched.
 * Tool results are metadata only (see safe.js): no code, snippets, evidence or secret values.
 */
const fs = require('node:fs')
const path = require('node:path')
const project = require('./project')
const { ensureBackend, uiServed } = require('./backend')
const { openBrowser } = require('./browser')
const { pickSummary, modeLabel, countsLine, redact } = require('./safe')

const SCAN_ID_RX = /^scan_[0-9a-f]{16}$/
const MAX_LISTED = 20

function resolveProject(projectPath) {
  if (typeof projectPath !== 'string' || !projectPath.trim()) throw new Error('project_path is required (absolute path to the project folder).')
  if (!path.isAbsolute(projectPath)) throw new Error('project_path must be an absolute path.')
  const root = path.resolve(projectPath)
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error('project_path is not an existing folder.')
  return fs.realpathSync.native(root)
}

function checkScanId(scanId) {
  if (!SCAN_ID_RX.test(String(scanId || ''))) throw new Error('scan_id must look like scan_0123456789abcdef.')
  return scanId
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function createTools({ client, open = openBrowser, ensure = ensureBackend, now = () => new Date(), scanWaitMs = 25000, pollMs = 700 } = {}) {
  const uiUrl = (route) => `${client.base}/#${route}`
  // Query-string copy of the route survives launchers that drop #fragments; the UI reads either.
  const launchUrl = (route) => `${client.base}/?open=${encodeURIComponent(route)}#${route}`

  /** One tab, not many: push a live tab to the route, else open a new one. */
  async function showInUi(route) {
    let delivered = false
    try {
      delivered = (await client.post('/api/plugin/navigate', { route })).delivered === true
    } catch {
      delivered = false
    }
    if (delivered) return { how: 'pushed to the open ChaosMonkey tab', url: uiUrl(route) }
    const opened = await open(launchUrl(route))
    return { how: opened ? 'opened in your default browser' : 'could not launch a browser; open it manually', url: uiUrl(route) }
  }

  async function backendReady() {
    const { health, started } = await ensure(client)
    try {
      await client.get('/api/plugin/project')
    } catch (err) {
      if (err && err.status === 404) {
        throw new Error(`An older ChaosMonkey backend without plugin support is running at ${client.base}. Stop it and try again (the plugin will start the current one).`)
      }
      throw err
    }
    const served = await uiServed(client)
    return { health, started, served }
  }

  function summaryText(data, projectRoot, shown) {
    const lines = []
    lines.push(`ChaosMonkey scan ${data.scan_id}: ${data.status}${data.status === 'running' || data.status === 'queued' ? ` (${Math.round((data.progress || 0) * 100)}%, stage ${String(data.stage || '').replace(/[^\w-]/g, '')})` : ''}`)
    if (projectRoot) lines.push(`Project: ${projectRoot}`)
    lines.push(`Analysis mode: ${modeLabel(data.mode)}`)
    lines.push('Privacy: local only, data_leaves_machine=false')
    lines.push(`Report: ${uiUrl(`/report/${data.scan_id}`)}${shown ? ` (${shown})` : ''}`)
    const s = pickSummary(data.summary)
    if (s) {
      lines.push(`Security score: ${s.security_score}/100. ${s.total_findings} finding(s): ${countsLine(s.counts_by_severity)}. ${s.files_scanned} file(s) scanned${s.files_skipped ? `, ${s.files_skipped} skipped` : ''}.`)
      if (s.findings.length) {
        lines.push('Findings (values masked; open the report to see details):')
        for (const f of s.findings.slice(0, MAX_LISTED)) {
          const fix = f.fix_verified ? 'verified fix available' : (f.fix_available ? 'fix proposed (unverified)' : 'manual fix')
          lines.push(`- [${f.severity}] ${f.title}${f.cwe_id ? ` (${f.cwe_id})` : ''} at ${f.location}; ${fix}`)
        }
        if (s.findings.length > MAX_LISTED) lines.push(`- ...and ${s.findings.length - MAX_LISTED} more in the report.`)
      }
      lines.push('Next: the user reviews findings and approves fixes in the ChaosMonkey UI. Nothing is applied automatically. '
        + `Call chaosmonkey_review_status with scan_id ${data.scan_id} later to learn what was applied.`)
    } else if (data.status === 'error') {
      lines.push('The scan failed. Check the ChaosMonkey server log.')
    } else {
      lines.push(`Still running. Call chaosmonkey_status with scan_id ${data.scan_id} in a few seconds.`)
    }
    return lines.join('\n')
  }

  const handlers = {
    async chaosmonkey_enable({ project_path }) {
      const root = resolveProject(project_path)
      project.enable(root)
      const { health, started, served } = await backendReady()
      await client.post('/api/plugin/connect', { project_path: root })
      const shown = served ? await showInUi('/connected') : null
      const fp = project.fingerprint(root)
      const lines = [
        `ChaosMonkey is enabled for ${root} (marker: .chaosmonkey/enabled).`,
        `Backend: ${started ? 'started' : 'reused'} at ${client.base}. Analysis mode: ${modeLabel(health.mode)}.`,
        'Privacy: local only (data_leaves_machine=false, privacy_ok=true).',
      ]
      if (shown) lines.push(`UI: ${shown.url} (${shown.how}).`)
      else lines.push('UI: the running backend does not serve the built UI. Build it with `npm run build` in frontend/ and restart the backend.')
      if (fp.files > 0) {
        lines.push(`The project already has ${fp.files} file(s). Ask the user whether to run a ChaosMonkey scan now (Y/N); call chaosmonkey_scan only if they say yes.`)
      } else {
        lines.push('The project has no code yet. The UI is waiting for code to be generated.')
      }
      return lines.join('\n')
    },

    async chaosmonkey_disable({ project_path }) {
      const root = resolveProject(project_path)
      project.disable(root)
      try {
        await client.post('/api/plugin/disconnect', { project_path: root })
      } catch {
        // backend not running: nothing to disconnect
      }
      return `ChaosMonkey is disabled for ${root}. The Stop hook will no longer offer scans here. Existing backups in .chaosmonkey/backups were kept.`
    },

    async chaosmonkey_scan({ project_path }) {
      const root = resolveProject(project_path)
      await backendReady()
      await client.post('/api/plugin/connect', { project_path: root })
      const fp = project.fingerprint(root)
      const { scan_id: scanId } = await client.post('/api/scan', { path: root, name: path.basename(root) || 'project' })
      checkScanId(scanId)
      await client.post('/api/plugin/link', { scan_id: scanId, project_path: root })
      project.writeState(root, { last_scan_id: scanId, last_scan_fingerprint: fp.hash, last_scan_at: now().toISOString() })
      const shown = await showInUi(`/report/${scanId}`)
      let data = await client.get(`/api/plugin/scan/${scanId}/summary`)
      const deadline = Date.now() + scanWaitMs
      while ((data.status === 'queued' || data.status === 'running') && Date.now() < deadline) {
        await sleep(pollMs)
        data = await client.get(`/api/plugin/scan/${scanId}/summary`)
      }
      return summaryText(data, root, shown.how)
    },

    async chaosmonkey_status({ scan_id }) {
      const data = await client.get(`/api/plugin/scan/${checkScanId(scan_id)}/summary`)
      return summaryText(data, data.project_path, null)
    },

    async chaosmonkey_decline_batch({ project_path }) {
      const root = resolveProject(project_path)
      const fp = project.fingerprint(root)
      project.writeState(root, { declined_fingerprint: fp.hash, declined_at: now().toISOString() })
      return 'Noted: no ChaosMonkey scan for this batch of changes. You will be asked again after the next code changes.'
    },
  }

  async function call(name, args) {
    const fn = handlers[name]
    if (!fn) throw new Error(`Unknown tool ${name}`)
    const text = await fn(args || {})
    return redact(text)
  }

  return { handlers, call, showInUi, summaryText }
}

const PROJECT_ARG = {
  type: 'object',
  properties: { project_path: { type: 'string', description: 'Absolute path of the project folder (usually the current working directory).' } },
  required: ['project_path'],
  additionalProperties: false,
}
const SCAN_ARG = {
  type: 'object',
  properties: { scan_id: { type: 'string', description: 'The scan id returned by chaosmonkey_scan, e.g. scan_0123456789abcdef.' } },
  required: ['scan_id'],
  additionalProperties: false,
}

const TOOL_DEFS = [
  {
    name: 'chaosmonkey_enable',
    description: 'Enable ChaosMonkey for a project ONLY after the user said yes. Writes .chaosmonkey/enabled, starts or reuses the local backend (127.0.0.1), and opens the local ChaosMonkey UI in the browser.',
    inputSchema: PROJECT_ARG,
  },
  {
    name: 'chaosmonkey_disable',
    description: 'Disable ChaosMonkey for a project (removes .chaosmonkey/enabled). Keeps backups.',
    inputSchema: PROJECT_ARG,
  },
  {
    name: 'chaosmonkey_scan',
    description: 'Run a local ChaosMonkey security scan of the project ONLY after the user said yes. Shows the report in the local UI and returns a masked, metadata-only summary (counts, severities, rule titles, file:line). Never applies fixes.',
    inputSchema: PROJECT_ARG,
  },
  {
    name: 'chaosmonkey_status',
    description: 'Get the status and masked summary of a ChaosMonkey scan.',
    inputSchema: SCAN_ARG,
  },
  {
    name: 'chaosmonkey_decline_batch',
    description: 'Record that the user declined a ChaosMonkey scan for the current batch of changes, so they are not asked again until files change.',
    inputSchema: PROJECT_ARG,
  },
]

module.exports = { createTools, TOOL_DEFS, resolveProject, checkScanId }
