'use strict'
/**
 * Per-project plugin state, kept in <project>/.chaosmonkey/ (which ignores itself in git):
 *   enabled        marker written by chaosmonkey_enable
 *   state.json     last scan fingerprint/id, the batch the user was last asked about or declined
 *   backups/       written by the backend before approved fixes are applied
 * The fingerprint is metadata only (relative path, size, mtime); file contents are never read.
 */
const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')

// Mirrors backend/app/pipeline/ingest.py so "files changed" means "the scan would differ".
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', '.cache',
  'vendor', '.idea', '.vscode', 'coverage', '.pytest_cache', '.chaosmonkey', '.claude',
])
const SKIP_SUFFIXES = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tar', '.woff',
  '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.wav', '.so', '.dylib', '.dll', '.pyc', '.class',
  '.jar', '.bin', '.exe', '.lock',
])
const MAX_FILES = 5000

function cmDir(root) {
  return path.join(root, '.chaosmonkey')
}

function isEnabled(root) {
  return fs.existsSync(path.join(cmDir(root), 'enabled'))
}

function ensureCmDir(root) {
  const dir = cmDir(root)
  fs.mkdirSync(dir, { recursive: true })
  // Backups hold original (possibly secret-bearing) files: keep the whole folder out of git.
  const gi = path.join(dir, '.gitignore')
  if (!fs.existsSync(gi)) fs.writeFileSync(gi, '*\n')
  return dir
}

function enable(root) {
  ensureCmDir(root)
  fs.writeFileSync(path.join(cmDir(root), 'enabled'), JSON.stringify({ enabled_at: new Date().toISOString() }) + '\n')
}

function disable(root) {
  fs.rmSync(path.join(cmDir(root), 'enabled'), { force: true })
}

function readState(root) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cmDir(root), 'state.json'), 'utf8'))
  } catch {
    return {}
  }
}

function writeState(root, patch) {
  ensureCmDir(root)
  const next = { ...readState(root), ...patch }
  fs.writeFileSync(path.join(cmDir(root), 'state.json'), JSON.stringify(next, null, 2) + '\n')
  return next
}

/** Walk the project like the backend ingester does: sorted "relpath|size|mtime" entries. */
function walk(root) {
  const entries = []
  const stack = ['']
  while (stack.length && entries.length < MAX_FILES) {
    const rel = stack.pop()
    let dirents
    try {
      dirents = fs.readdirSync(path.join(root, rel), { withFileTypes: true })
    } catch {
      continue
    }
    for (const d of dirents) {
      const childRel = rel ? `${rel}/${d.name}` : d.name
      if (d.isSymbolicLink()) continue
      if (d.isDirectory()) {
        if (!SKIP_DIRS.has(d.name)) stack.push(childRel)
        continue
      }
      if (!d.isFile() || SKIP_SUFFIXES.has(path.extname(d.name).toLowerCase())) continue
      try {
        const st = fs.statSync(path.join(root, childRel))
        entries.push(`${childRel}|${st.size}|${Math.floor(st.mtimeMs)}`)
      } catch {
        // vanished mid-walk
      }
    }
  }
  entries.sort()
  return entries
}

function fingerprint(root) {
  const entries = walk(root)
  const hash = crypto.createHash('sha256').update(entries.join('\n')).digest('hex').slice(0, 24)
  return { hash, files: entries.length }
}

module.exports = { SKIP_DIRS, cmDir, isEnabled, ensureCmDir, enable, disable, readState, writeState, fingerprint, walk }
