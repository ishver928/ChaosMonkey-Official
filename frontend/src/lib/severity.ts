import type { Category, Finding, Severity } from './types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
export const CATEGORIES: Category[] = ['secrets', 'pii', 'storage']

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 18, high: 9, medium: 4, low: 1.5 }

export const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }
export const CATEGORY_LABEL: Record<Category, string> = { secrets: 'Exposed secrets', pii: 'Personal info', storage: 'Unsafe storage' }
export const CATEGORY_SHORT: Record<Category, string> = { secrets: 'Secrets', pii: 'PII', storage: 'Storage' }

/** 0-100 risk: a saturating sum of severity weight x confidence, so forty lows can't reach 100. */
export function chaosScore(findings: readonly Finding[]): number {
  const sum = findings.reduce((acc, f) => acc + SEVERITY_WEIGHT[f.severity] * (0.5 + f.confidence / 2), 0)
  const raw = Math.round(100 * (1 - Math.exp(-sum / 190)))
  // Floors so a single serious issue never reads as "fine".
  if (findings.some((f) => f.severity === 'critical')) return Math.max(raw, 40)
  if (findings.some((f) => f.severity === 'high')) return Math.max(raw, 20)
  return raw
}

export function scoreLabel(score: number): { label: string; blurb: string } {
  if (score === 0) return { label: 'Calm', blurb: 'Nothing for the monkey to shake loose.' }
  if (score < 25) return { label: 'Restless', blurb: 'A few loose cables. Tidy them up before you ship.' }
  if (score < 55) return { label: 'Rowdy', blurb: 'Real problems in here. Fix the critical ones first.' }
  if (score < 80) return { label: 'Swinging', blurb: 'This would leak on day one. Do not publish yet.' }
  return { label: 'Full chaos', blurb: 'Live credentials and personal data are exposed. Stop and rotate.' }
}

export function countBy<K extends string>(findings: readonly Finding[], key: (f: Finding) => K, keys: readonly K[]): Record<K, number> {
  const out = Object.fromEntries(keys.map((k) => [k, 0])) as Record<K, number>
  for (const f of findings) out[key(f)] += 1
  return out
}
