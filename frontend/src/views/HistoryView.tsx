import { useState } from 'react'
import { ArrowUpRight, Trash2 } from 'lucide-react'
import type { HistoryEntry } from '@/lib/storage'
import { SEVERITIES, SEVERITY_LABEL, chaosScore, countBy, scoreLabel } from '@/lib/severity'
import { EmptyState } from '@/components/Brand'
import { ScoreTrend } from '@/components/Charts'
import { SeverityIcon, SEV_VAR } from '@/components/Severity'

const fmt = (t: number) => new Date(t).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })

export function HistoryView({ history, setHistory, onOpen, currentId }: {
  history: HistoryEntry[]
  setHistory: (h: HistoryEntry[]) => void
  onOpen: (h: HistoryEntry) => void
  currentId?: string
}) {
  const [confirming, setConfirming] = useState<string | null>(null)
  const trend = [...history].reverse().map((h) => ({ at: h.createdAt, score: chaosScore(h.findings), name: h.name }))

  return (
    <div className="mx-auto max-w-[1120px] px-[4vw] pt-14">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div>
          <p className="eyebrow">History</p>
          <h1 className="mt-1 text-[clamp(38px,5vw,58px)] font-semibold">Recent chaos</h1>
          <p className="mt-2 max-w-xl text-[15.5px]">A paper trail of past scans. Only names, counts and masked snippets are kept on this device. File contents never are.</p>
        </div>
        {trend.length > 1 && (
          <figure className="card-thin m-0 rounded-md px-4 py-3">
            <figcaption className="mono-label mb-1">CHAOS SCORE · OLDEST → NEWEST</figcaption>
            <ScoreTrend points={trend} />
          </figure>
        )}
      </div>

      {history.length === 0 ? (
        <div className="card mt-10"><EmptyState title="No scans yet." body="Your paper trail will appear here after the first scan." action={<a className="btn btn-primary" href="#/scan">Start a scan</a>} /></div>
      ) : (
        <ol className="relative mt-10 before:absolute before:bottom-6 before:left-[118px] before:top-6 before:w-px before:bg-[var(--color-line)] before:opacity-35 max-md:before:hidden">
          {history.map((h) => {
            const score = chaosScore(h.findings)
            const sev = countBy(h.findings, (f) => f.severity, SEVERITIES)
            return (
              <li key={h.id} className="relative grid items-center gap-x-5 gap-y-2 border-b border-[var(--color-rule)] py-5 md:grid-cols-[100px_20px_1fr_auto_auto]">
                <time className="font-mono text-[11.5px]" dateTime={new Date(h.createdAt).toISOString()}>{fmt(h.createdAt)}</time>
                <span className="z-[1] hidden h-3 w-3 rounded-full border-2 border-line md:block" style={{ background: score >= 55 ? 'var(--color-coral)' : score >= 25 ? 'var(--color-butter)' : 'var(--color-sage)' }} aria-hidden="true" />
                <div className="min-w-0">
                  <h2 className="truncate font-display text-[19px] font-medium">
                    {h.name}
                    {h.id === currentId && <span className="stamp ml-3 !text-[10px]">OPEN</span>}
                  </h2>
                  <p className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[12.5px]">
                    <span className="font-mono text-muted">{h.files.length} files</span>
                    {SEVERITIES.map((s) => sev[s] > 0 && (
                      <span key={s} className="inline-flex items-center gap-1 font-bold">
                        <span style={{ color: SEV_VAR[s] }} className="flex"><SeverityIcon severity={s} /></span>{sev[s]} {SEVERITY_LABEL[s].toLowerCase()}
                      </span>
                    ))}
                    {h.findings.length === 0 && <span className="font-bold text-sage-ink">clean</span>}
                  </p>
                </div>
                <div className="text-right">
                  <p className="font-display text-[30px] font-semibold leading-none text-strong">{score}</p>
                  <p className="mono-label">{scoreLabel(score).label}</p>
                </div>
                <div className="flex gap-2 justify-self-end">
                  <button type="button" className="btn btn-sm btn-secondary" onClick={() => onOpen(h)}>Open <ArrowUpRight size={14} aria-hidden="true" /></button>
                  {confirming === h.id ? (
                    <button type="button" className="btn btn-sm btn-danger" onClick={() => { setHistory(history.filter((x) => x.id !== h.id)); setConfirming(null) }} onBlur={() => setConfirming(null)} autoFocus>Delete?</button>
                  ) : (
                    <button type="button" className="btn btn-sm btn-quiet" onClick={() => setConfirming(h.id)} aria-label={`Delete scan ${h.name}`}><Trash2 size={14} aria-hidden="true" /></button>
                  )}
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </div>
  )
}
