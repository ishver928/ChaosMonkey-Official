import type { Dismissal, ScanReport } from './types'
import { scrub } from './redaction'

/*
 * Everything persisted lives in localStorage under "cm.*" and is metadata only:
 * settings, rule toggles, dismissed-finding fingerprints and scan history with masked snippets.
 * Raw file contents and raw secret/PII values are never written. As a last line of defence,
 * every write runs through scrub(), which blanks anything that still looks like a credential.
 */

const KEYS = {
  settings: 'cm.settings.v1',
  history: 'cm.history.v1',
  dismissed: 'cm.dismissed.v1',
  disabledRules: 'cm.disabledRules.v1',
  seeded: 'cm.seeded.v1',
} as const

export type Theme = 'light' | 'dark'
export interface Settings {
  theme: Theme
  ollamaEnabled: boolean
  ollamaModel: string
}

export const DEFAULT_SETTINGS: Settings = { theme: 'light', ollamaEnabled: false, ollamaModel: '' }
export const HISTORY_LIMIT = 30

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, scrub(JSON.stringify(value)))
  } catch {
    // Storage full or disabled (private mode): the app keeps working in memory.
  }
}

export const loadSettings = (): Settings => ({ ...DEFAULT_SETTINGS, ...read<Partial<Settings>>(KEYS.settings, {}) })
export const saveSettings = (s: Settings) => write(KEYS.settings, s)

/** History entries never include file contents: only summaries and masked findings. */
export type HistoryEntry = ScanReport
export const loadHistory = (): HistoryEntry[] => read<HistoryEntry[]>(KEYS.history, [])
export const saveHistory = (h: HistoryEntry[]) => write(KEYS.history, h.slice(0, HISTORY_LIMIT))

export const loadDismissed = (): Record<string, Dismissal> => read<Record<string, Dismissal>>(KEYS.dismissed, {})
export const saveDismissed = (d: Record<string, Dismissal>) => write(KEYS.dismissed, d)

export const loadDisabledRules = (): string[] => read<string[]>(KEYS.disabledRules, [])
export const saveDisabledRules = (ids: string[]) => write(KEYS.disabledRules, ids)

export const isSeeded = (): boolean => read<boolean>(KEYS.seeded, false)
export const markSeeded = () => write(KEYS.seeded, true)

export function resetAll(): void {
  Object.values(KEYS).forEach((k) => {
    try {
      localStorage.removeItem(k)
    } catch {
      /* ignore */
    }
  })
}

/** Used by the About view to prove what's on disk. */
export function storageSnapshot(): { key: string; bytes: number }[] {
  return Object.values(KEYS).map((key) => ({ key, bytes: (localStorage.getItem(key) ?? '').length }))
}
