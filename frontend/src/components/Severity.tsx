import type { Category, Severity } from '@/lib/types'
import { CATEGORY_SHORT, SEVERITY_LABEL } from '@/lib/severity'
import { Database, KeyRound, UserRound } from 'lucide-react'

/** Distinct shapes per severity so colour is never the only signal. */
export function SeverityIcon({ severity, size = 11 }: { severity: Severity; size?: number }) {
  const common = { width: size, height: size, viewBox: '0 0 12 12', 'aria-hidden': true } as const
  switch (severity) {
    case 'critical':
      return <svg {...common}><path d="M4 .8h4L11.2 4v4L8 11.2H4L.8 8V4z" fill="currentColor" /><path d="M6 3v3.6M6 8.2v.6" stroke="var(--color-surface)" strokeWidth="1.5" strokeLinecap="round" /></svg>
    case 'high':
      return <svg {...common}><path d="M6 .9 11.4 10.8H.6z" fill="currentColor" /></svg>
    case 'medium':
      return <svg {...common}><path d="M6 .8 11.2 6 6 11.2.8 6z" fill="currentColor" /></svg>
    default:
      return <svg {...common}><circle cx="6" cy="6" r="4.6" fill="none" stroke="currentColor" strokeWidth="2" /></svg>
  }
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`sev sev-${severity}`}><SeverityIcon severity={severity} />{SEVERITY_LABEL[severity]}</span>
}

export function CategoryIcon({ category, size = 15 }: { category: Category; size?: number }) {
  const Icon = category === 'secrets' ? KeyRound : category === 'pii' ? UserRound : Database
  return <Icon size={size} strokeWidth={2.2} aria-hidden="true" />
}

export function CategoryTag({ category }: { category: Category }) {
  return (
    <span className="inline-flex items-center gap-1 text-[12px] font-bold text-muted">
      <CategoryIcon category={category} size={13} />{CATEGORY_SHORT[category]}
    </span>
  )
}

export const SEV_VAR: Record<Severity, string> = {
  critical: 'var(--color-sev-critical)', high: 'var(--color-sev-high)', medium: 'var(--color-sev-medium)', low: 'var(--color-sev-low)',
}
export const SEV_BG_VAR: Record<Severity, string> = {
  critical: 'var(--color-sev-critical-bg)', high: 'var(--color-sev-high-bg)', medium: 'var(--color-sev-medium-bg)', low: 'var(--color-sev-low-bg)',
}
