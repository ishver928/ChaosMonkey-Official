import type { Finding, RawMatch, Rule, SourceFile } from './types'
import { RULES } from './rules'
import { baseName, detectLanguage } from './language'
import { applyMasks, maskValue, type MaskRange } from './redaction'
import { SEVERITY_RANK } from './severity'

export function fnv1a(input: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

function lineStarts(content: string): number[] {
  const starts = [0]
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1)
  return starts
}

function position(starts: number[], offset: number): { line: number; column: number } {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (starts[mid]! <= offset) lo = mid
    else hi = mid - 1
  }
  return { line: lo + 1, column: offset - starts[lo]! + 1 }
}

const overlaps = (a: RawMatch, b: RawMatch) => a.start < b.end && b.start < a.end

/** Mask ranges for every sensitive finding in a file, used to render it safely. */
export function maskRangesFor(findings: readonly Finding[], file: string, content: string): MaskRange[] {
  const seen = new Set<string>()
  const out: MaskRange[] = []
  for (const f of findings) {
    if (f.file !== file || !f.sensitive) continue
    const key = `${f.start}:${f.end}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ start: f.start, end: f.end, mask: maskValue(content.slice(f.start, f.end), f.ruleId, f.name) })
  }
  return out
}

const SNIPPET_MAX = 160

function windowed(line: string, column: number): string {
  const trimmed = line.trimEnd()
  if (trimmed.length <= SNIPPET_MAX) return trimmed.trim()
  const from = Math.max(0, column - 60)
  return `${from > 0 ? '…' : ''}${trimmed.slice(from, from + SNIPPET_MAX).trim()}${from + SNIPPET_MAX < trimmed.length ? '…' : ''}`
}

/** Scan one file with the given rules. Returned findings carry only masked values and snippets. */
export function scanFile(file: SourceFile, project: readonly SourceFile[], rules: readonly Rule[]): Finding[] {
  const language = detectLanguage(file.path) ?? 'text'
  const ctx = { path: file.path, fileName: baseName(file.path), language, content: file.content, project }

  const hits: { rule: Rule; m: RawMatch }[] = []
  for (const rule of rules) {
    let found: RawMatch[] = []
    try {
      found = rule.detect(ctx)
    } catch {
      found = []
    }
    for (const m of found) {
      if (!hits.some((h) => h.rule.id === rule.id && h.m.start === m.start && h.m.end === m.end)) hits.push({ rule, m })
    }
  }

  // Specific detectors beat generic ones: drop a generic hit that overlaps a specific sensitive hit.
  const specific = hits.filter((h) => !h.rule.generic && h.m.sensitive)
  let kept = hits.filter((h) => !h.rule.generic || !specific.some((s) => overlaps(s.m, h.m)))
  // A rule listed in another rule's supersededBy wins on the same line (e.g. CM-J004 over CM-C004).
  const lineOfHit = (m: RawMatch) => file.content.slice(0, m.start).split('\n').length
  kept = kept.filter((h) => !h.rule.supersededBy?.length || !kept.some((o) => h.rule.supersededBy!.includes(o.rule.id) && lineOfHit(o.m) === lineOfHit(h.m)))
  // Sensitive ranges must not partially overlap or masking breaks: keep the earliest/longest.
  const sensitive = kept.filter((h) => h.m.sensitive).sort((a, b) => a.m.start - b.m.start || b.m.end - a.m.end)
  const accepted: typeof sensitive = []
  for (const h of sensitive) {
    const clash = accepted.find((a) => overlaps(a.m, h.m))
    if (!clash || (h.m.start === clash.m.start && h.m.end === clash.m.end)) accepted.push(h)
  }
  kept = kept.filter((h) => !h.m.sensitive || accepted.includes(h))

  const starts = lineStarts(file.content)
  const masks: MaskRange[] = []
  const seen = new Set<string>()
  for (const h of accepted) {
    const key = `${h.m.start}:${h.m.end}`
    if (seen.has(key)) continue
    seen.add(key)
    masks.push({ start: h.m.start, end: h.m.end, mask: maskValue(file.content.slice(h.m.start, h.m.end), h.rule.id, h.m.name) })
  }
  const maskedLines = applyMasks(file.content, masks).split('\n')

  const fingerprints = new Map<string, number>()
  return kept.map(({ rule, m }) => {
    const a = position(starts, m.start)
    const b = position(starts, Math.max(m.start, m.end - 1))
    const maskedValue = m.sensitive ? maskValue(file.content.slice(m.start, m.end), rule.id, m.name) : ''
    const snippet = windowed(maskedLines[a.line - 1] ?? '', a.column)
    const base = fnv1a(`${rule.id}|${file.path}|${maskedValue}|${m.name ?? ''}|${snippet.replace(/\s+/g, ' ')}`)
    const dup = fingerprints.get(base) ?? 0
    fingerprints.set(base, dup + 1)
    const fingerprint = dup ? `${base}.${dup}` : base
    return {
      id: '',
      fingerprint,
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      file: file.path,
      language,
      line: a.line,
      column: a.column,
      endLine: b.line,
      endColumn: b.column + 1,
      start: m.start,
      end: m.end,
      sensitive: m.sensitive,
      maskedValue,
      snippet,
      confidence: Math.round(m.confidence * 100) / 100,
      note: m.note,
      name: m.name,
      cwe: rule.cwe,
    }
  })
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column,
  )
}

export function scanProject(
  files: readonly SourceFile[],
  enabledRuleIds?: readonly string[],
  onProgress?: (done: number, total: number, path: string) => void,
): Finding[] {
  const rules = enabledRuleIds ? RULES.filter((r) => enabledRuleIds.includes(r.id)) : RULES
  const findings: Finding[] = []
  files.forEach((file, i) => {
    findings.push(...scanFile(file, files, rules))
    onProgress?.(i + 1, files.length, file.path)
  })
  return sortFindings(findings).map((f, i) => ({ ...f, id: `f${i + 1}-${f.fingerprint}` }))
}
