import type { CSSProperties } from 'react'

/** The CalHacks 13.0 badge, cropped to its circle. Never redrawn. */
export function Logo({ size = 40, className = '', alt = 'ChaosMonkey logo: a cartoon monkey swinging from tangled cables with a laptop' }: { size?: number; className?: string; alt?: string }) {
  return <img src="/logo.png" width={size} height={size} alt={alt} className={`rounded-full ${className}`} style={{ width: size, height: size }} draggable={false} />
}

/** Hand-drawn cable squiggle with a knot, used as a section divider. */
export function CableDivider({ className = '', knot = 0.62 }: { className?: string; knot?: number }) {
  const kx = Math.round(1200 * knot)
  return (
    <svg className={`block w-full h-7 text-line ${className}`} viewBox="0 0 1200 28" preserveAspectRatio="none" aria-hidden="true">
      <path
        d={`M0 16 C 120 6, 220 24, 340 14 S 560 4, ${kx - 40} 15 C ${kx - 18} 18, ${kx - 10} 4, ${kx} 8 C ${kx + 12} 12, ${kx + 4} 24, ${kx - 6} 18 C ${kx - 14} 12, ${kx + 6} 6, ${kx + 22} 13 S ${kx + 160} 22, 1200 12`}
        fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" vectorEffect="non-scaling-stroke"
      />
      <path d="M0 19 C 140 12, 260 26, 380 18" fill="none" stroke="currentColor" strokeOpacity=".35" strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

/** The badge hanging from a cable and swinging. Used while scanning; still under reduced motion. */
export function MonkeySwing({ size = 120, label }: { size?: number; label?: string }) {
  return (
    <div className="flex flex-col items-center" role="img" aria-label={label ?? 'Scanning'}>
      <svg width={size * 1.6} height="34" viewBox="0 0 200 34" aria-hidden="true" className="text-line">
        <path d="M0 6 C 50 2, 80 14, 100 10 S 160 2, 200 8" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
        <path d="M100 10 L100 34" stroke="currentColor" strokeWidth="2" strokeDasharray="3 3" />
      </svg>
      <div className="swing" style={{ transformOrigin: '50% -34px' } as CSSProperties}>
        <Logo size={size} alt="" className="border-2 border-line" />
      </div>
    </div>
  )
}

/** Little powder-blue bow from the reference design. */
export function Bow({ className = '' }: { className?: string }) {
  return (
    <svg className={className} width="44" height="30" viewBox="0 0 44 30" aria-hidden="true">
      <path d="M21 14 C 12 2, 2 4, 3 14 C 4 23, 13 22, 21 15 Z" fill="var(--color-powder)" stroke="var(--color-line)" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M23 14 C 32 2, 42 4, 41 14 C 40 23, 31 22, 23 15 Z" fill="var(--color-powder)" stroke="var(--color-line)" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M19 16 L 13 28 L 18 25 L 21 29 L 22 18 M25 16 L 31 28 L 26 25 L 23 29" fill="var(--color-powder)" stroke="var(--color-line)" strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx="22" cy="14.5" r="4.2" fill="var(--color-sky)" stroke="var(--color-line)" strokeWidth="1.8" />
    </svg>
  )
}

/** Empty state: badge, a short line, and an optional action. */
export function EmptyState({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center px-6 py-14">
      <Logo size={96} alt="" className="border-2 border-line -rotate-6" />
      <h3 className="mt-5 text-2xl">{title}</h3>
      <p className="mt-2 max-w-sm text-[15px]">{body}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
