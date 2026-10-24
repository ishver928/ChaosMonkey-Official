import type { Category, Severity } from '@/lib/types'
import { CATEGORIES, CATEGORY_LABEL, SEVERITIES, SEVERITY_LABEL, scoreLabel } from '@/lib/severity'
import { CategoryIcon, SEV_VAR, SeverityIcon } from './Severity'

/** Hero number with a thin hand-built arc gauge. The number is the headline; the arc is context. */
export function ScoreDial({ score }: { score: number }) {
  const r = 70
  const cx = 90
  const cy = 86
  const arc = (from: number, to: number) => {
    const a0 = Math.PI * (1 - from)
    const a1 = Math.PI * (1 - to)
    const x0 = cx + r * Math.cos(a0), y0 = cy - r * Math.sin(a0)
    const x1 = cx + r * Math.cos(a1), y1 = cy - r * Math.sin(a1)
    return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`
  }
  const { label } = scoreLabel(score)
  const t = Math.max(0.001, score / 100)
  return (
    <figure className="m-0 flex flex-col items-center" aria-label={`Chaos Score ${score} out of 100, ${label}`}>
      <svg width="180" height="104" viewBox="0 0 180 104" role="img" aria-hidden="true">
        <title>{`Chaos Score ${score}/100`}</title>
        <path d={arc(0, 1)} fill="none" stroke="var(--color-rule)" strokeWidth="10" strokeLinecap="round" />
        <path d={arc(0, t)} fill="none" stroke={score >= 55 ? 'var(--color-sev-critical)' : score >= 25 ? 'var(--color-sev-high)' : 'var(--color-sage-ink)'} strokeWidth="10" strokeLinecap="round" />
        {[0, 0.25, 0.55, 0.8, 1].map((tick) => {
          const a = Math.PI * (1 - tick)
          return <line key={tick} x1={cx + (r + 9) * Math.cos(a)} y1={cy - (r + 9) * Math.sin(a)} x2={cx + (r + 14) * Math.cos(a)} y2={cy - (r + 14) * Math.sin(a)} stroke="var(--color-line)" strokeWidth="1.5" strokeLinecap="round" />
        })}
        <text x={cx} y={cy - 6} textAnchor="middle" fontFamily="var(--font-display)" fontWeight="600" fontSize="46" fill="var(--color-strong)">{score}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fontFamily="var(--font-mono)" fontSize="10" fill="var(--color-muted)">/ 100</text>
      </svg>
    </figure>
  )
}

interface Row { key: string; label: string; value: number; color: string; icon: React.ReactNode }

/** One labelled row per item: icon + name + count carry identity, the bar carries magnitude. */
function BarRows({ rows, title }: { rows: Row[]; title: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <div>
      <p className="eyebrow mb-3">{title}</p>
      <ul className="space-y-2.5" aria-label={title}>
        {rows.map((r) => (
          <li key={r.key} className="grid grid-cols-[minmax(0,118px)_1fr_28px] items-center gap-3 text-[13px]" title={`${r.label}: ${r.value}`}>
            <span className="flex items-center gap-1.5 font-bold text-strong truncate" style={{ color: 'var(--color-strong)' }}>
              <span style={{ color: r.color }} className="flex">{r.icon}</span>{r.label}
            </span>
            <span className="relative h-2.5 rounded-full bg-[var(--color-rule)]">
              <span
                className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-300"
                style={{ width: `${(r.value / max) * 100}%`, background: r.color, minWidth: r.value ? 8 : 0 }}
              />
            </span>
            <span className="text-right font-mono text-[12.5px] font-semibold text-strong">{r.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function SeverityBreakdown({ counts }: { counts: Record<Severity, number> }) {
  return <BarRows title="By severity" rows={SEVERITIES.map((s) => ({ key: s, label: SEVERITY_LABEL[s], value: counts[s], color: SEV_VAR[s], icon: <SeverityIcon severity={s} size={12} /> }))} />
}

export function CategoryBreakdown({ counts }: { counts: Record<Category, number> }) {
  return <BarRows title="By category" rows={CATEGORIES.map((c) => ({ key: c, label: CATEGORY_LABEL[c], value: counts[c], color: 'var(--color-denim)', icon: <CategoryIcon category={c} size={13} /> }))} />
}

/** Tiny score trend for History: one series, so no legend; the endpoint is direct-labelled. */
export function ScoreTrend({ points }: { points: { at: number; score: number; name: string }[] }) {
  if (points.length < 2) return null
  const w = 280, h = 64, pad = 8
  const xs = points.map((_, i) => pad + (i / (points.length - 1)) * (w - pad * 2 - 26))
  const ys = points.map((p) => h - pad - (p.score / 100) * (h - pad * 2))
  const d = xs.map((x, i) => `${i ? 'L' : 'M'} ${x.toFixed(1)} ${ys[i]!.toFixed(1)}`).join(' ')
  const last = points.length - 1
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Chaos Score trend across ${points.length} scans, latest ${points[last]!.score}`}>
      <line x1={pad} x2={w - pad - 26} y1={h - pad} y2={h - pad} stroke="var(--color-rule)" />
      <path d={d} fill="none" stroke="var(--color-denim)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      {xs.map((x, i) => (
        <circle key={i} cx={x} cy={ys[i]} r="4" fill="var(--color-surface)" stroke="var(--color-denim)" strokeWidth="2">
          <title>{`${points[i]!.name}: ${points[i]!.score}`}</title>
        </circle>
      ))}
      <text x={xs[last]! + 8} y={ys[last]! + 4} fontFamily="var(--font-mono)" fontSize="11" fontWeight="600" fill="var(--color-strong)">{points[last]!.score}</text>
    </svg>
  )
}
