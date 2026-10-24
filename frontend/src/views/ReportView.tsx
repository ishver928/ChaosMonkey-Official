import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, Download, FileText, RefreshCw, Search } from 'lucide-react'
import type { Category, Dismissal, Finding, Severity } from '@/lib/types'
import type { Current } from '@/App'
import { RULE_BY_ID } from '@/lib/rules'
import { CATEGORIES, CATEGORY_SHORT, SEVERITIES, SEVERITY_LABEL, chaosScore, countBy, scoreLabel } from '@/lib/severity'
import { exportReport } from '@/lib/exportReport'
import { CableDivider, EmptyState, MonkeySwing } from '@/components/Brand'
import { CategoryBreakdown, ScoreDial, SeverityBreakdown } from '@/components/Charts'
import { CategoryIcon, SeverityIcon, SEV_VAR } from '@/components/Severity'
import { FindingDetail, type LocalModel } from '@/components/FindingDetail'

function timeAgo(t: number): string {
  const s = Math.round((Date.now() - t) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function ExportMenu({ onExport }: { onExport: (k: 'md' | 'json' | 'html') => void }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', close) }
  }, [open])
  return (
    <div className="relative" ref={ref}>
      <button type="button" className="btn btn-primary" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Download size={15} aria-hidden="true" /> Export report <ChevronDown size={14} aria-hidden="true" />
      </button>
      {open && (
        <div role="menu" className="card card-shadow rise absolute right-0 z-20 mt-2 w-64 p-1.5">
          {([['md', 'Markdown', 'for the PR description'], ['json', 'JSON', 'for CI or other tools'], ['html', 'HTML', 'self-contained, opens offline']] as const).map(([k, label, hint]) => (
            <button key={k} role="menuitem" type="button" className="flex w-full items-start gap-2.5 rounded-md px-3 py-2 text-left hover:bg-butter focus-visible:bg-butter" onClick={() => { onExport(k); setOpen(false) }}>
              <FileText size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
              <span><span className="block text-[14px] font-extrabold text-strong">{label}</span><span className="block text-[12px] text-muted">{hint}</span></span>
            </button>
          ))}
          <p className="border-t border-[var(--color-rule)] px-3 pb-1 pt-2 font-mono text-[10.5px] text-muted">All values masked · saved to your Downloads</p>
        </div>
      )}
    </div>
  )
}

export function ReportView({ current, dismissed, setDismissed, onRescan, onDemo, scanning, localModel }: {
  current: Current | null
  dismissed: Record<string, Dismissal>
  setDismissed: (d: Record<string, Dismissal>) => void
  onRescan: () => void
  onDemo: () => void
  scanning: boolean
  localModel: LocalModel
}) {
  const report = current?.report
  const [sevFilter, setSevFilter] = useState<Severity[]>([])
  const [catFilter, setCatFilter] = useState<Category[]>([])
  const [query, setQuery] = useState('')
  const [showDismissed, setShowDismissed] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Set<string>>(() => new Set())
  const listRef = useRef<HTMLUListElement>(null)

  // Revealed values are tied to this report only and dropped when it changes.
  useEffect(() => {
    setRevealed(new Set())
    setSelectedId(null)
  }, [report?.id])

  const all = report?.findings ?? []
  const active = useMemo(() => all.filter((f) => !dismissed[f.fingerprint]), [all, dismissed])
  const score = chaosScore(active)
  const sevCounts = countBy(active, (f) => f.severity, SEVERITIES)
  const catCounts = countBy(active, (f) => f.category, CATEGORIES)
  const dismissedCount = all.length - active.length

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return all.filter((f) =>
      (showDismissed || !dismissed[f.fingerprint]) &&
      (sevFilter.length === 0 || sevFilter.includes(f.severity)) &&
      (catFilter.length === 0 || catFilter.includes(f.category)) &&
      (!q || f.file.toLowerCase().includes(q) || f.ruleId.toLowerCase().includes(q) || (RULE_BY_ID[f.ruleId]?.title ?? '').toLowerCase().includes(q) || f.snippet.toLowerCase().includes(q)),
    )
  }, [all, dismissed, showDismissed, sevFilter, catFilter, query])

  const selected = visible.find((f) => f.id === selectedId) ?? visible[0]
  const source = selected && current?.sources ? current.sources.find((s) => s.path === selected.file) ?? null : null

  const toggleReveal = useCallback((id: string) => {
    setRevealed((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggle = <T,>(list: T[], v: T): T[] => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v])

  const onListKey = (e: React.KeyboardEvent) => {
    if (!selected || (e.key !== 'ArrowDown' && e.key !== 'ArrowUp')) return
    e.preventDefault()
    const i = visible.findIndex((f) => f.id === selected.id)
    const next = visible[Math.max(0, Math.min(visible.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))]
    if (next) {
      setSelectedId(next.id)
      listRef.current?.querySelector<HTMLButtonElement>(`[data-id="${next.id}"]`)?.focus()
    }
  }

  if (!report) {
    return (
      <div className="mx-auto max-w-[1240px] px-[4vw] py-24">
        {scanning ? <div className="flex justify-center"><MonkeySwing size={120} label="Preparing the demo report" /></div> : (
          <EmptyState title="No report yet." body="Scan some code, or load the demo project to see what a full report looks like." action={<button type="button" className="btn btn-primary" onClick={onDemo}>Load demo project</button>} />
        )}
      </div>
    )
  }

  const { label, blurb } = scoreLabel(score)
  const files = new Set(all.map((f) => f.file)).size

  return (
    <div className="mx-auto max-w-[1440px] px-[4vw] pb-10 pt-12">
      {/* Title strip */}
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <p className="eyebrow">Report</p>
          <h1 className="mt-1 text-[clamp(38px,5vw,64px)] font-semibold tracking-[-0.03em]">{report.name}</h1>
          <p className="mt-2 font-mono text-[12.5px] text-muted">
            {timeAgo(report.createdAt)} · {report.files.length} {report.files.length === 1 ? 'file' : 'files'} scanned{report.skipped.length ? ` · ${report.skipped.length} skipped` : ''} · {report.rulesRun} rules · {report.durationMs} ms in a Web Worker
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          {current?.sources && <button type="button" className="btn btn-quiet" onClick={onRescan} disabled={scanning}><RefreshCw size={15} aria-hidden="true" /> Re-scan</button>}
          <a href="#/scan" className="btn btn-secondary">New scan</a>
          <ExportMenu onExport={(k) => exportReport(k, { report, dismissed })} />
        </div>
      </div>

      {/* Score + breakdowns */}
      <section className="mt-8 grid gap-0 border-2 border-line bg-surface shadow-[4px_4px_0_var(--color-line)] lg:grid-cols-[1.25fr_1fr_1fr]" aria-label="Summary">
        <div className="flex flex-wrap items-center gap-6 border-b-2 border-line p-6 lg:border-b-0 lg:border-r-2">
          <ScoreDial score={score} />
          <div className="min-w-[180px] flex-1">
            <p className="eyebrow">Chaos Score</p>
            <p className="mt-1 font-display text-[30px] font-semibold text-strong">{label}</p>
            <p className="mt-1 text-[14.5px]">{blurb}</p>
            <p className="mt-3 font-mono text-[12px] text-muted">{active.length} open across {files} {files === 1 ? 'file' : 'files'}{dismissedCount ? ` · ${dismissedCount} dismissed` : ''}</p>
          </div>
        </div>
        <div className="border-b border-[var(--color-rule)] p-6 lg:border-b-0 lg:border-r"><SeverityBreakdown counts={sevCounts} /></div>
        <div className="p-6"><CategoryBreakdown counts={catCounts} /></div>
      </section>

      <CableDivider className="my-8" knot={0.3} />

      {all.length === 0 ? (
        <div className="card card-shadow">
          <EmptyState title="Nothing to shake loose." body={`${report.rulesRun} rules ran over ${report.files.length} files and found no exposed secrets, personal data or unsafe storage. Ship it.`} action={<a href="#/scan" className="btn btn-primary">Scan something else</a>} />
        </div>
      ) : (
        <div className="grid items-start gap-6 lg:grid-cols-[minmax(320px,400px)_1fr]">
          {/* Findings list */}
          <section className="card lg:sticky lg:top-4" aria-label="Findings">
            <div className="space-y-3 border-b-2 border-line p-4">
              <div className="relative">
                <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
                <input className="field h-9 !pl-9" placeholder="Filter by file, rule or text" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Filter findings" />
              </div>
              <div className="flex flex-wrap gap-1.5" aria-label="Severity filter">
                {SEVERITIES.map((s) => (
                  <button key={s} type="button" className="chip" aria-pressed={sevFilter.includes(s)} onClick={() => setSevFilter(toggle(sevFilter, s))}>
                    <span style={{ color: SEV_VAR[s] }} className="flex"><SeverityIcon severity={s} /></span>{SEVERITY_LABEL[s]} <span className="font-mono text-[11px] text-muted">{sevCounts[s]}</span>
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-1.5" aria-label="Category filter">
                {CATEGORIES.map((c) => (
                  <button key={c} type="button" className="chip" aria-pressed={catFilter.includes(c)} onClick={() => setCatFilter(toggle(catFilter, c))}>
                    <CategoryIcon category={c} size={13} />{CATEGORY_SHORT[c]} <span className="font-mono text-[11px] text-muted">{catCounts[c]}</span>
                  </button>
                ))}
              </div>
              {dismissedCount > 0 && (
                <label className="flex cursor-pointer items-center gap-2 text-[12.5px] font-bold">
                  <input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} className="accent-[var(--color-denim)]" />
                  Show {dismissedCount} dismissed
                </label>
              )}
            </div>
            <p className="px-4 pt-3 font-mono text-[11px] text-muted" aria-live="polite">{visible.length} of {all.length} findings · ↑↓ to move</p>
            <ul ref={listRef} className="max-h-[calc(100vh-280px)] min-h-[200px] overflow-y-auto p-2" onKeyDown={onListKey}>
              {visible.map((f: Finding) => {
                const isSel = selected?.id === f.id
                const isDis = !!dismissed[f.fingerprint]
                return (
                  <li key={f.id}>
                    <button
                      type="button" data-id={f.id} onClick={() => setSelectedId(f.id)} aria-current={isSel ? 'true' : undefined}
                      className={`w-full rounded-md border-[1.5px] px-3 py-2.5 text-left transition-colors ${isSel ? 'border-line bg-butter' : 'border-transparent hover:border-[var(--color-rule)] hover:bg-bg'} ${isDis ? 'opacity-55' : ''}`}
                    >
                      <span className="flex items-center gap-2">
                        <span style={{ color: SEV_VAR[f.severity] }} className="flex" title={SEVERITY_LABEL[f.severity]}><SeverityIcon severity={f.severity} size={12} /></span>
                        <span className="sr-only">{SEVERITY_LABEL[f.severity]}:</span>
                        <span className={`truncate text-[14px] font-extrabold text-strong ${isDis ? 'line-through' : ''}`}>{RULE_BY_ID[f.ruleId]?.title}</span>
                      </span>
                      <span className="mt-0.5 block truncate font-mono text-[11.5px] text-muted">{f.file.replace(/^[^/]+\//, '')}:{f.line}</span>
                      <span className="mt-1 block truncate font-mono text-[11.5px] text-ink">{f.snippet}</span>
                    </button>
                  </li>
                )
              })}
              {visible.length === 0 && <li className="px-3 py-10 text-center text-[14px] text-muted">No findings match these filters.</li>}
            </ul>
          </section>

          {/* Detail */}
          <section className="card card-shadow min-w-0" aria-label="Finding detail">
            {selected ? (
              <FindingDetail
                key={selected.id}
                finding={selected}
                related={all}
                source={source}
                dismissal={dismissed[selected.fingerprint]}
                onDismiss={(reason) => {
                  const next = { ...dismissed }
                  if (reason) next[selected.fingerprint] = { reason, at: Date.now() }
                  else delete next[selected.fingerprint]
                  setDismissed(next)
                }}
                revealed={revealed}
                onToggleReveal={toggleReveal}
                onSelect={setSelectedId}
                localModel={localModel}
              />
            ) : (
              <EmptyState title="Pick a finding." body="Choose something from the list to see why it’s risky and how to fix it." />
            )}
          </section>
        </div>
      )}
    </div>
  )
}
