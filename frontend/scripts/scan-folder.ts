// Scans a folder on disk with the exact code the browser runs for "Choose folder":
// File objects with webkitRelativePath -> readFileList (intake rules) -> scanProject (what the
// Web Worker calls) -> adviceFor (built-in analyst). Prints JSON on stdout.
// Usage: npx tsx scripts/scan-folder.ts <folder> [--advice] [--include-tests]
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { intakeOptions, readFileList } from '../src/lib/intake'
import { scanProject } from '../src/lib/scanner'
import { adviceFor } from '../src/lib/knowledge'
import { applyMasks } from '../src/lib/redaction'
import { maskRangesFor } from '../src/lib/scanner'

const args = process.argv.slice(2)
const root = args.find((a) => !a.startsWith('--'))
if (!root) {
  console.error('usage: scan-folder.ts <folder> [--advice] [--include-tests]')
  process.exit(2)
}
intakeOptions.includeTestPaths = args.includes('--include-tests')

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name)
    return statSync(full).isDirectory() ? walk(full) : [full]
  })
}

const top = path.basename(path.resolve(root))
const files = walk(path.resolve(root)).sort().map((full) => {
  const rel = `${top}/${path.relative(path.resolve(root), full).split(path.sep).join('/')}`
  const file = new File([readFileSync(full)], path.basename(full))
  // Browsers set this for <input type="file" webkitdirectory>; intake reads it.
  Object.defineProperty(file, 'webkitRelativePath', { value: rel })
  return file
})

const intake = await readFileList(files)
const findings = scanProject(intake.files)
const byPath = new Map(intake.files.map((f) => [f.path, f]))

const out = findings.map((f) => {
  const base = { ruleId: f.ruleId, cwe: f.cwe, severity: f.severity, category: f.category, file: f.file, line: f.line, endLine: f.endLine, snippet: f.snippet, language: f.language }
  if (!args.includes('--advice')) return base
  const src = byPath.get(f.file)
  const masked = src ? applyMasks(src.content, maskRangesFor(findings, src.path, src.content)) : undefined
  const advice = adviceFor(f, masked?.split('\n')[f.line - 1], masked)
  return { ...base, explanation: advice.why, steps: advice.steps, fix: advice.fix }
})

console.log(JSON.stringify({ files: intake.files.map((f) => f.path), skipped: intake.skipped, findings: out }))
