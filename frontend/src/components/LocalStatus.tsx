import { useSyncExternalStore } from 'react'
import { getBlockedCount, subscribeBlocked } from '@/lib/offlineGuard'

export function useBlockedCount(): number {
  return useSyncExternalStore(subscribeBlocked, getBlockedCount, getBlockedCount)
}

/** Truthful chrome indicator: reads the offline guard's live counter. */
export function LocalStatus({ compact = false }: { compact?: boolean }) {
  const blocked = useBlockedCount()
  return (
    <a
      href="#/about"
      className="inline-flex items-center gap-2 rounded-full border-[1.5px] border-line bg-surface px-3 py-1 text-[12px] font-bold text-strong no-underline hover:bg-sage transition-colors"
      title="Every outbound request is checked by the offline guard. Click for details."
    >
      <span className={`inline-block h-2 w-2 rounded-full ${blocked ? 'bg-sev-high' : 'bg-sage-ink pulse-dot'}`} aria-hidden="true" />
      <span>{compact ? 'Local only' : 'Local only · non-local requests blocked'}</span>
      <span className="font-mono text-[11px] font-medium text-muted" aria-label={`${blocked} outbound requests blocked`}>{blocked} blocked</span>
    </a>
  )
}
