import { useEffect, useMemo, useRef } from 'react'
import type { Finding, Language, Severity } from '@/lib/types'
import { maskValue } from '@/lib/redaction'
import { SEVERITY_RANK } from '@/lib/severity'

type SegKind = 'plain' | 'mask' | 'reveal'
interface Seg { text: string; kind: SegKind }

const KEYWORDS = new Set([
  'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'import', 'from', 'export', 'default', 'async', 'await',
  'new', 'class', 'type', 'interface', 'true', 'false', 'null', 'undefined', 'def', 'with', 'as', 'in', 'not', 'and', 'or', 'None',
  'True', 'False', 'try', 'except', 'catch', 'throw', 'CREATE', 'TABLE', 'INSERT', 'INTO', 'VALUES', 'SELECT', 'WHERE', 'PRIMARY',
  'KEY', 'NOT', 'NULL', 'UNIQUE', 'DEFAULT', 'export', 'set', 'echo', 'curl', 'of', 'this',
])

function commentStart(lang: Language): RegExp {
  if (lang === 'python' || lang === 'shell' || lang === 'env' || lang === 'yaml' || lang === 'toml' || lang === 'ini' || lang === 'text') return /#.*$/
  if (lang === 'sql') return /--.*$/
  return /\/\/.*$/
}

/** Tiny per-segment tokenizer: comments, strings, numbers, keywords. Good enough to read, never executed. */
function tint(text: string, lang: Language, keyBase: string): React.ReactNode[] {
  if (lang === 'json') lang = 'javascript'
  const re = new RegExp(`(${commentStart(lang).source})|("(?:\\\\.|[^"\\\\])*"?|'(?:\\\\.|[^'\\\\])*'?|\`[^\`]*\`?)|(\\b\\d+(?:\\.\\d+)?\\b)|(\\b[A-Za-z_]+\\b)`, 'g')
  const out: React.ReactNode[] = []
  let last = 0
  let i = 0
  for (const m of text.matchAll(re)) {
    const idx = m.index ?? 0
    if (idx > last) out.push(text.slice(last, idx))
    const k = `${keyBase}-${i++}`
    if (m[1]) out.push(<span key={k} className="tok-com">{m[0]}</span>)
    else if (m[2]) out.push(<span key={k} className="tok-str">{m[0]}</span>)
    else if (m[3]) out.push(<span key={k} className="tok-num">{m[0]}</span>)
    else if (m[4] && KEYWORDS.has(m[4])) out.push(<span key={k} className="tok-kw">{m[0]}</span>)
    else out.push(m[0])
    last = idx + m[0].length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

/** Split file content into per-line segments, swapping every sensitive range for its mask unless revealed. */
function buildLines(content: string, findings: Finding[], revealed: ReadonlySet<string>): Seg[][] {
  const ranges = new Map<string, { start: number; end: number; mask: string; revealed: boolean }>()
  for (const f of findings) {
    if (!f.sensitive) continue
    const key = `${f.start}:${f.end}`
    const prev = ranges.get(key)
    const isRevealed = revealed.has(f.id) || (prev?.revealed ?? false)
    ranges.set(key, { start: f.start, end: f.end, mask: maskValue(content.slice(f.start, f.end), f.ruleId, f.name), revealed: isRevealed })
  }
  const sorted = [...ranges.values()].sort((a, b) => a.start - b.start)
  const segs: Seg[] = []
  let cursor = 0
  for (const r of sorted) {
    if (r.start < cursor) continue
    if (r.start > cursor) segs.push({ text: content.slice(cursor, r.start), kind: 'plain' })
    segs.push(r.revealed ? { text: content.slice(r.start, r.end), kind: 'reveal' } : { text: r.mask, kind: 'mask' })
    cursor = r.end
  }
  if (cursor < content.length) segs.push({ text: content.slice(cursor), kind: 'plain' })

  const lines: Seg[][] = [[]]
  for (const s of segs) {
    const parts = s.text.split('\n')
    parts.forEach((p, i) => {
      if (i > 0) lines.push([])
      if (p) lines[lines.length - 1]!.push({ text: p, kind: s.kind })
    })
  }
  return lines
}

export function CodeViewer({
  content, language, findings, activeId, revealed, onSelect, maxHeight = 420, label,
}: {
  content: string
  language: Language
  findings: Finding[]
  activeId?: string
  revealed: ReadonlySet<string>
  onSelect?: (id: string) => void
  maxHeight?: number
  label: string
}) {
  const lines = useMemo(() => buildLines(content, findings, revealed), [content, findings, revealed])
  const flagged = useMemo(() => {
    const map = new Map<number, Finding>()
    for (const f of findings) {
      for (let l = f.line; l <= f.endLine; l++) {
        const prev = map.get(l)
        if (!prev || SEVERITY_RANK[f.severity] < SEVERITY_RANK[prev.severity]) map.set(l, f)
      }
    }
    return map
  }, [findings])
  const active = findings.find((f) => f.id === activeId)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!active || !box.current) return
    const row = box.current.querySelector<HTMLElement>(`[data-line="${active.line}"]`)
    if (row) box.current.scrollTo({ top: Math.max(0, row.offsetTop - box.current.clientHeight / 3), behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })
  }, [active])

  return (
    <div ref={box} className="code relative" style={{ maxHeight }} role="region" aria-label={label} tabIndex={0}>
      <div className="py-2">
        {lines.map((segs, i) => {
          const n = i + 1
          const flag = flagged.get(n)
          const isActive = !!active && n >= active.line && n <= active.endLine
          const sev: Severity | undefined = flag?.severity
          return (
            <div
              key={n}
              data-line={n}
              className={`code-line ${flag ? `flag flag-${sev}` : ''} ${isActive ? `active` : ''}`}
              onClick={flag && onSelect ? () => onSelect(flag.id) : undefined}
            >
              <span className="ln">{n}</span>
              <span className="tx">
                {segs.length === 0 ? ' ' : segs.map((s, j) =>
                  s.kind === 'plain' ? <span key={j}>{tint(s.text, language, `${n}-${j}`)}</span>
                    : s.kind === 'mask' ? <span key={j} className="masked" title="Masked by ChaosMonkey">{s.text}</span>
                      : <span key={j} className="revealed" title="Revealed in memory only">{s.text}</span>,
                )}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/** Before/after diff. Before lines are the masked original; after lines are the template fix. */
export function DiffView({ before, after }: { before: string; after: string }) {
  return (
    <div className="code !overflow-x-auto py-2 text-[12.5px]" role="figure" aria-label="Suggested change, before and after">
      {before.split('\n').map((l, i) => <div key={`b${i}`} className="diff-line diff-del"><span aria-label="removed">−</span><span>{l || ' '}</span></div>)}
      {after.split('\n').map((l, i) => <div key={`a${i}`} className="diff-line diff-add"><span aria-label="added">+</span><span>{l || ' '}</span></div>)}
    </div>
  )
}
