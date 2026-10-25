import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, ShieldCheck, XCircle } from 'lucide-react'
import { EmptyState, MonkeySwing } from '@/components/Brand'
import { SeverityIcon, SEV_VAR } from '@/components/Severity'
import { getJson, MODE_LABEL, type BackendFinding, type BackendScan, type BackendSeverity, type PluginProject } from '@/lib/plugin'

const SEV_ORDER: BackendSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_TEXT: Record<BackendSeverity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
// The shared severity components only know critical..low; info renders with the low style.
const uiSev = (s: BackendSeverity) => (s === 'info' ? 'low' : s)

/** Unified diff, coloured per line. The backend has already masked every sensitive value in it. */
export function UnifiedDiff({ diff }: { diff: string }) {
  const lines = diff.split('\n').filter((l) => !l.startsWith('---') && !l.startsWith('+++'))
  return (
    <div className="code !overflow-x-auto py-2 text-[12.5px]" role="figure" aria-label="Proposed fix as a diff">
      {lines.map((l, i) => {
        if (l.startsWith('@@')) return <div key={i} className="px-3 font-mono text-[11.5px] text-muted">{l}</div>
        const cls = l.startsWith('+') ? 'diff-line diff-add' : l.startsWith('-') ? 'diff-line diff-del' : 'diff-line'
        return <div key={i} className={cls}><span aria-hidden="true">{l[0] === '+' || l[0] === '-' ? l[0] : ' '}</span><span>{l.slice(1) || ' '}</span></div>
      })}
    </div>
  )
}

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 font-mono text-[11px] ${ok ? 'text-sage-ink' : 'text-muted'}`}>
      {ok ? <CheckCircle2 size={12} aria-hidden="true" /> : <XCircle size={12} aria-hidden="true" />}{label}
    </span>
  )
}

export function FindingCard({ f, children }: { f: BackendFinding; children?: React.ReactNode }) {
  const sev = uiSev(f.severity)
  return (
    <article className="card p-5" aria-label={`${SEV_TEXT[f.severity]}: ${f.title}`}>
      <div className="flex flex-wrap items-start gap-3">
        <span style={{ color: SEV_VAR[sev] }} className="mt-1 flex"><SeverityIcon severity={sev} size={14} /></span>
        <div className="min-w-0 flex-1">
          <p className="text-[16px] font-extrabold text-strong">{f.title || f.ruleId}</p>
          <p className="mt-0.5 font-mono text-[12px] text-muted">
            {SEV_TEXT[f.severity]} · {f.file}:{f.line}{f.cwe_id ? ` · ${f.cwe_id}` : ''}{f.ruleId ? ` · ${f.ruleId}` : ''} · source: {f.source}
          </p>
        </div>
        {children}
      </div>
      {f.snippet && <pre className="code mt-3 overflow-x-auto rounded-md border border-[var(--color-rule)] p-3 text-[12.5px]">{f.snippet}</pre>}
      {f.explanation && <p className="mt-3 text-[14px]">{f.explanation}</p>}
      {f.attack_scenario && <p className="mt-2 text-[13.5px] text-muted"><strong className="text-strong">Attack: </strong>{f.attack_scenario}</p>}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
        <Check ok={f.validation.evidence_in_source} label="evidence verbatim" />
        <Check ok={f.validation.cwe_known} label="CWE in knowledge base" />
        <Check ok={f.validation.cwe_pattern_match} label="CWE pattern match" />
        <Check ok={f.validation.confirmed_by_detector || f.source !== 'llm'} label="detector-confirmed" />
      </div>
    </article>
  )
}

export function useBackendScan(scanId: string): { scan: BackendScan | null; error: string | null } {
  const [scan, setScan] = useState<BackendScan | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    setScan(null)
    setError(null)
    const poll = async () => {
      try {
        const s = await getJson<BackendScan>(`/api/scan/${scanId}`, 8000)
        if (cancelled) return
        setScan(s)
        if (s.status === 'queued' || s.status === 'running') timer = setTimeout(poll, 800)
      } catch {
        if (!cancelled) setError('This scan is not available. The ChaosMonkey backend may have restarted (scans are kept in memory only).')
      }
    }
    void poll()
    return () => { cancelled = true; if (timer) clearTimeout(timer) }
  }, [scanId])
  return { scan, error }
}

/** Report for a scan run by the backend (deep link #/report/<scan_id>, used by the Claude Code plugin). */
export function BackendReportView({ scanId, project }: { scanId: string; project: PluginProject | null }) {
  const { scan, error } = useBackendScan(scanId)
  const report = scan?.report ?? null
  const findings = useMemo(() => report?.findings ?? [], [report])

  if (error) {
    return <div className="mx-auto max-w-[1240px] px-[4vw] py-24"><EmptyState title="Report not found." body={error} action={<a href="#/scan" className="btn btn-primary">New scan</a>} /></div>
  }
  if (!scan || scan.status === 'queued' || scan.status === 'running') {
    return (
      <div className="mx-auto flex max-w-[1240px] flex-col items-center px-[4vw] py-24 text-center">
        <MonkeySwing size={120} label="Scanning your project" />
        <p className="mt-4 font-display text-[24px] font-semibold text-strong">Scanning your project…</p>
        <p className="mt-1 font-mono text-[12.5px] text-muted">{scan ? `${scan.stage} · ${Math.round(scan.progress * 100)}%` : 'starting'}</p>
      </div>
    )
  }
  if (scan.status === 'error' || !report) {
    return <div className="mx-auto max-w-[1240px] px-[4vw] py-24"><EmptyState title="The scan failed." body="Check the ChaosMonkey server log, then ask Claude to scan again." /></div>
  }

  const mode = report.privacy?.llm_mock ? MODE_LABEL.mock : (project ? MODE_LABEL[project.mode] : null)

  return (
    <div className="mx-auto max-w-[1240px] px-[4vw] pb-10 pt-12">
      <p className="eyebrow">Report · from Claude Code</p>
      <h1 className="mt-1 text-[clamp(34px,4.5vw,56px)] font-semibold tracking-[-0.03em]">{report.name}</h1>
      <p className="mt-2 font-mono text-[12.5px] text-muted">
        {report.files.length} files scanned{report.skipped.length ? ` · ${report.skipped.length} skipped` : ''} · {scanId}
      </p>

      <section className="card card-shadow mt-8 grid gap-0 md:grid-cols-[1fr_1.4fr_1.4fr]" aria-label="Summary">
        <div className="border-b-2 border-line p-6 md:border-b-0 md:border-r-2">
          <p className="eyebrow">Security score</p>
          <p className="mt-1 font-display text-[44px] font-semibold text-strong">{report.security_score}<span className="text-[20px] text-muted">/100</span></p>
        </div>
        <div className="border-b-2 border-line p-6 md:border-b-0 md:border-r-2">
          <p className="eyebrow">Findings</p>
          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            {SEV_ORDER.map((s) => (
              <li key={s} className="flex items-center gap-1.5 text-[14px]">
                <span style={{ color: SEV_VAR[uiSev(s)] }} className="flex"><SeverityIcon severity={uiSev(s)} /></span>
                {SEV_TEXT[s]} <span className="font-mono text-[12px] text-muted">{report.counts_by_severity[s] ?? 0}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-[13.5px]">{report.executive_summary}</p>
        </div>
        <div className="p-6">
          <p className="flex items-center gap-2 font-extrabold text-strong"><ShieldCheck size={16} aria-hidden="true" /> Local only</p>
          <p className="mt-1 text-[13.5px]">data_leaves_machine = {String(report.privacy?.data_leaves_machine ?? false)}</p>
          {mode && <p className="mt-2 text-[13.5px]"><strong>Mode: {mode.label}.</strong> {mode.detail}</p>}
        </div>
      </section>

      {findings.length === 0 ? (
        <div className="card card-shadow mt-8"><EmptyState title="Nothing to shake loose." body="No issues found in this project." /></div>
      ) : (
        <div className="mt-8 space-y-4">
          {findings.map((f) => (
            <FindingCard key={f.id} f={f}>
              {f.fix_diff ? (
                <span className={`font-mono text-[11.5px] font-bold ${f.fix_verified ? 'text-sage-ink' : 'text-muted'}`}>{f.fix_verified ? 'verified fix' : 'unverified fix'}</span>
              ) : <span className="font-mono text-[11.5px] text-muted">manual fix</span>}
            </FindingCard>
          ))}
        </div>
      )}
    </div>
  )
}
