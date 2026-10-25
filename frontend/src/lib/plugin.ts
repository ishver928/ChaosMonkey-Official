import { useEffect, useState } from 'react'

/*
 * Claude Code plugin integration. When the UI is served by (or proxied to) the local backend and
 * a project has been connected from Claude Code, this keeps one tab in sync: a heartbeat plus an
 * SSE stream of "navigate" events. Every call is same-origin (/api/...). If the backend isn't
 * there, everything here fails silently and the app behaves exactly as before.
 */

export type BackendSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AnalysisMode = 'full' | 'mock' | 'detector-only'

export interface PluginProject {
  connected: boolean
  project_path: string | null
  ui_alive: boolean
  mode: AnalysisMode
  llm_mode: string
  model: string
}

export interface BackendFinding {
  id: string
  ruleId: string
  severity: BackendSeverity
  file: string
  line: number
  /** Masked by the backend before it leaves the server. */
  snippet: string
  cwe_id?: string | null
  title: string
  explanation: string
  attack_scenario: string
  suggested_fix: string
  /** Unified diff with sensitive values already masked by the backend. */
  fix_diff: string
  fix_verified: boolean
  source: 'detector' | 'llm' | 'both'
  severity_score: number
  validation: {
    evidence_in_source: boolean
    cwe_known: boolean
    cwe_pattern_match: boolean
    confirmed_by_detector: boolean
    needs_review: boolean
  }
}

export interface BackendReport {
  id: string
  name: string
  files: { path: string }[]
  skipped: { path: string }[]
  findings: BackendFinding[]
  security_score: number
  counts_by_severity: Record<string, number>
  executive_summary: string
  privacy?: { data_leaves_machine: boolean; llm_mock: boolean; model: string; seed: number; temperature: number } | null
}

export interface BackendScan {
  scan_id: string
  status: 'queued' | 'running' | 'done' | 'error'
  stage: string
  progress: number
  error?: string | null
  report: BackendReport | null
}

export interface Health {
  status: string
  mode: AnalysisMode
  data_leaves_machine: boolean
  privacy_ok: boolean
  kb_size: number
}

export type ReviewState = 'pending_review' | 'applying' | 'rescanning' | 'applied' | 'declined' | 'error'

export interface ReviewEntry {
  id: string
  title: string
  severity: BackendSeverity
  location: string
  result?: 'fix_verified' | 'fix_failed' | 'pending' | 'unknown'
  reason?: string
}

export interface Review {
  scan_id: string
  status: ReviewState
  applied: ReviewEntry[]
  skipped: ReviewEntry[]
  files_changed: string[]
  backup_dir: string | null
  rescan_scan_id: string | null
  rescan?: { security_score: number; total_findings: number }
  error?: string
}

export interface ScanLink {
  project_path: string | null
}

const CLIENT_HEADER ={ 'X-ChaosMonkey-Client': 'chaosmonkey-ui' }
const ROUTE_RX = /^\/(connected|scan|report|report\/scan_[0-9a-f]{16})$/

export function isPluginRoute(route: string): boolean {
  return ROUTE_RX.test(route)
}

export async function getJson<T>(path: string, timeoutMs = 5000): Promise<T> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(path, { signal: ctrl.signal, headers: { Accept: 'application/json' } })
    if (!res.ok) throw new Error(`${path} → ${res.status}`)
    return (await res.json()) as T
  } finally {
    clearTimeout(timer)
  }
}

export async function postPlugin<T>(path: string, body: unknown, timeoutMs = 15000): Promise<T> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(path, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', ...CLIENT_HEADER },
      body: JSON.stringify(body),
    })
    const data = (await res.json().catch(() => ({}))) as T & { detail?: unknown }
    if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `${path} → ${res.status}`)
    return data
  } finally {
    clearTimeout(timer)
  }
}

/**
 * The plugin opens the UI as `/?open=/report/<id>#/report/<id>`: some OS URL launchers drop the
 * #fragment, so the route is duplicated in the query string. Move it into the hash, then tidy the URL.
 */
export function consumeOpenParam(): void {
  const params = new URLSearchParams(window.location.search)
  const open = params.get('open')
  if (!open) return
  if (isPluginRoute(open) && !window.location.hash.replace(/^#/, '')) window.location.hash = open
  params.delete('open')
  const qs = params.toString()
  window.history.replaceState(null, '', `${window.location.pathname}${qs ? `?${qs}` : ''}${window.location.hash}`)
}

/** Connected-project state + the one-tab heartbeat/navigate wiring. undefined = still checking, null = no plugin backend. */
export function usePluginConnection(): PluginProject | null | undefined {
  const [project, setProject] = useState<PluginProject | null | undefined>(undefined)

  useEffect(() => {
    let cancelled = false
    let events: EventSource | null = null
    let beatTimer: ReturnType<typeof setInterval> | undefined

    const refresh = async (): Promise<PluginProject | null> => {
      try {
        const p = await getJson<PluginProject>('/api/plugin/project', 4000)
        if (!cancelled) setProject(p)
        return p
      } catch {
        if (!cancelled) setProject((cur) => cur ?? null)
        return null
      }
    }

    void (async () => {
      const p = await refresh()
      if (!p || cancelled) return // backend absent or too old: silent fallback, nothing else runs
      const beat = () => {
        postPlugin('/api/plugin/heartbeat', { route: window.location.hash }, 4000).catch(() => {})
      }
      beat()
      beatTimer = setInterval(beat, 5000)
      events = new EventSource('/api/plugin/events')
      events.addEventListener('navigate', (e) => {
        try {
          const { route } = JSON.parse((e as MessageEvent<string>).data) as { route: string }
          if (isPluginRoute(route)) {
            window.location.hash = route
            window.focus()
          }
        } catch {
          // ignore malformed events
        }
      })
      events.addEventListener('project', () => void refresh())
    })()

    return () => {
      cancelled = true
      events?.close()
      if (beatTimer) clearInterval(beatTimer)
    }
  }, [])

  return project
}

export const MODE_LABEL: Record<AnalysisMode, { label: string; detail: string }> = {
  full: { label: 'Full: local LLM', detail: 'Local Ollama model + CWE knowledge base + deterministic detectors.' },
  mock: { label: 'Mock LLM', detail: 'Recorded local-model responses + CWE knowledge base + detectors. No live model.' },
  'detector-only': { label: 'Detector-only', detail: 'Ollama is not available, so only deterministic detectors + CWE grounding ran.' },
}

export function basename(p: string): string {
  return p.split(/[\\/]/).filter(Boolean).pop() ?? p
}
