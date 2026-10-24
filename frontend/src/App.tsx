import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Dismissal, Finding, ScanReport, SkippedFile, SourceFile } from '@/lib/types'
import { RULE_META } from '@/lib/rules'
import { detectLanguage } from '@/lib/language'
import { scanInWorker } from '@/lib/scanClient'
import { navigate, useRoute, type Route } from '@/lib/router'
import { detectOllama, type OllamaStatus } from '@/lib/ollama'
import {
  loadDisabledRules, loadDismissed, loadHistory, loadSettings, isSeeded, markSeeded, resetAll,
  saveDisabledRules, saveDismissed, saveHistory, saveSettings, type HistoryEntry, type Settings,
} from '@/lib/storage'
import { SEED_FILES, SEED_ID, SEED_NAME, patchedSeedFiles } from '@/data/seedProject'
import { Bow, Logo } from '@/components/Brand'
import { LocalStatus } from '@/components/LocalStatus'
import { ScanView } from '@/views/ScanView'
import { ReportView } from '@/views/ReportView'
import { HistoryView } from '@/views/HistoryView'
import { RulesView } from '@/views/RulesView'
import { SettingsView } from '@/views/SettingsView'
import { AboutView } from '@/views/AboutView'

export interface Current { report: ScanReport; sources: SourceFile[] | null }
export interface ScanProgress { name: string; done: number; total: number; path: string }

const PATCHED_SEED_ID = `${SEED_ID}#patched`

function sourcesForSeed(seedId?: string): SourceFile[] | null {
  if (seedId === SEED_ID) return SEED_FILES
  if (seedId === PATCHED_SEED_ID) return patchedSeedFiles()
  return null
}

const NAV: { route: Route; label: string }[] = [
  { route: 'scan', label: 'Scan' },
  { route: 'report', label: 'Report' },
  { route: 'history', label: 'History' },
  { route: 'rules', label: 'Rules' },
  { route: 'settings', label: 'Settings' },
  { route: 'about', label: 'About & Privacy' },
]

export default function App() {
  const route = useRoute()
  const [settings, setSettingsState] = useState<Settings>(loadSettings)
  const [disabledRules, setDisabledRulesState] = useState<string[]>(loadDisabledRules)
  const [dismissed, setDismissedState] = useState<Record<string, Dismissal>>(loadDismissed)
  const [history, setHistoryState] = useState<HistoryEntry[]>(loadHistory)
  const [current, setCurrent] = useState<Current | null>(null)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const [ollama, setOllama] = useState<OllamaStatus>({ state: 'offline' })
  const booted = useRef(false)

  const setSettings = useCallback((s: Settings) => { setSettingsState(s); saveSettings(s) }, [])
  const setDisabledRules = useCallback((ids: string[]) => { setDisabledRulesState(ids); saveDisabledRules(ids) }, [])
  const setDismissed = useCallback((d: Record<string, Dismissal>) => { setDismissedState(d); saveDismissed(d) }, [])
  const setHistory = useCallback((h: HistoryEntry[]) => { setHistoryState(h); saveHistory(h) }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = settings.theme
  }, [settings.theme])

  const enabledRuleIds = useMemo(() => RULE_META.filter((r) => !disabledRules.includes(r.id)).map((r) => r.id), [disabledRules])

  const buildReport = useCallback(async (files: SourceFile[], name: string, opts: { seedId?: string; skipped?: SkippedFile[]; createdAt?: number; onProgress?: boolean; ruleIds?: string[] }) => {
    const ruleIds = opts.ruleIds ?? enabledRuleIds
    const { findings, durationMs } = await scanInWorker(files, ruleIds, opts.onProgress ? (done, total, path) => setProgress({ name, done, total, path }) : undefined)
    const report: ScanReport = {
      id: `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      name,
      createdAt: opts.createdAt ?? Date.now(),
      durationMs,
      files: files.map((f) => ({ path: f.path, language: detectLanguage(f.path) ?? 'text', lines: f.content.split('\n').length, bytes: f.content.length })),
      skipped: opts.skipped ?? [],
      findings,
      rulesRun: ruleIds.length,
      seedId: opts.seedId,
    }
    return report
  }, [enabledRuleIds])

  /** Run a scan from the UI: animated progress, saved to history, then open the report. */
  const runScan = useCallback(async (files: SourceFile[], name: string, opts: { seedId?: string; skipped?: SkippedFile[] } = {}) => {
    setScanError(null)
    setProgress({ name, done: 0, total: files.length, path: files[0]?.path ?? '' })
    const started = performance.now()
    try {
      const report = await buildReport(files, name, { ...opts, onProgress: true })
      // Let the swing animation breathe for a beat so the scan doesn't feel fake-instant.
      const minVisible = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 900
      await new Promise((r) => setTimeout(r, Math.max(0, minVisible - (performance.now() - started))))
      setCurrent({ report, sources: files })
      setHistoryState((h) => {
        const next = [report, ...h]
        saveHistory(next)
        return next
      })
      navigate('report')
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'The scan failed unexpectedly.')
    } finally {
      setProgress(null)
    }
  }, [buildReport])

  const loadDemo = useCallback(() => runScan(SEED_FILES, SEED_NAME, { seedId: SEED_ID }), [runScan])

  // First launch: seed history with real scans of the demo project so every view is populated.
  // Every launch: have the demo report ready in memory so the Report view is never empty.
  useEffect(() => {
    if (booted.current) return
    booted.current = true
    void (async () => {
      const allRules = RULE_META.map((r) => r.id)
      if (!isSeeded()) {
        const now = Date.now()
        const patched = await buildReport(patchedSeedFiles(), `${SEED_NAME} · fix/rotate-keys`, { seedId: PATCHED_SEED_ID, createdAt: now - 1000 * 60 * 18, ruleIds: allRules })
        const main = await buildReport(SEED_FILES, SEED_NAME, { seedId: SEED_ID, createdAt: now, ruleIds: allRules })
        const seeded = [main, patched, ...loadHistory()]
        saveHistory(seeded)
        setHistoryState(seeded)
        markSeeded()
        setCurrent((c) => c ?? { report: main, sources: SEED_FILES })
      } else {
        const latest = loadHistory().find((h) => h.seedId === SEED_ID)
        const report = await buildReport(SEED_FILES, SEED_NAME, { seedId: SEED_ID, createdAt: latest?.createdAt, ruleIds: enabledRuleIds })
        setCurrent((c) => c ?? { report: latest ? { ...report, id: latest.id } : report, sources: SEED_FILES })
      }
    })()
  }, [buildReport, enabledRuleIds])

  const refreshOllama = useCallback(async () => {
    setOllama({ state: 'checking' })
    const status = await detectOllama()
    setOllama(status)
    return status
  }, [])

  useEffect(() => {
    if (settings.ollamaEnabled) void refreshOllama()
  }, [settings.ollamaEnabled, refreshOllama])

  const openHistory = useCallback((entry: HistoryEntry) => {
    setCurrent({ report: entry, sources: sourcesForSeed(entry.seedId) })
    navigate('report')
  }, [])

  const rescanCurrent = useCallback(() => {
    if (current?.sources) void runScan(current.sources, current.report.name, { seedId: current.report.seedId, skipped: current.report.skipped })
  }, [current, runScan])

  /** Merges sandbox verification results (from an explicit, user-triggered Docker run) back
   * onto the current report's findings. Does not touch anything else about the report. */
  const applySandboxVerification = useCallback((findings: Finding[]) => {
    setCurrent((c) => (c ? { ...c, report: { ...c.report, findings } } : c))
  }, [])

  const resetDemo = useCallback(() => {
    resetAll()
    window.location.hash = '/scan'
    window.location.reload()
  }, [])

  return (
    <div className="min-h-screen flex flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 btn btn-primary">Skip to content</a>
      <header className="relative z-10 border-b-2 border-line bg-surface">
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center gap-x-8 gap-y-3 px-[4vw] py-3.5">
          <a href="#/scan" className="flex items-center gap-2.5 no-underline" aria-label="ChaosMonkey home">
            <Logo size={42} alt="" className="border-2 border-line" />
            <span className="font-display text-[22px] font-semibold text-strong">ChaosMonkey</span>
          </a>
          <nav aria-label="Main" className="order-3 flex w-full gap-x-6 gap-y-1 overflow-x-auto lg:order-none lg:w-auto">
            {NAV.map((n) => (
              <a key={n.route} href={`#/${n.route}`} className="nav-link whitespace-nowrap" aria-current={route === n.route ? 'page' : undefined}>
                {n.label}
                {n.route === 'history' && history.length > 0 && <span className="ml-1 font-mono text-[10.5px] font-medium text-muted">{history.length}</span>}
              </a>
            ))}
          </nav>
          <div className="ml-auto"><LocalStatus /></div>
        </div>
        <div className="gingham h-3 border-t-2 border-line" aria-hidden="true" />
        <Bow className="pointer-events-none absolute -bottom-6 left-[22%] hidden md:block" />
        <Bow className="pointer-events-none absolute -bottom-5 right-[14%] hidden scale-75 rotate-12 md:block" />
      </header>

      <main id="main" className="flex-1">
        {route === 'scan' && <ScanView onScan={runScan} onDemo={loadDemo} progress={progress} error={scanError} latest={history[0]} />}
        {route === 'report' && (
          <ReportView
            current={current}
            dismissed={dismissed}
            setDismissed={setDismissed}
            onRescan={rescanCurrent}
            onDemo={loadDemo}
            scanning={!!progress}
            localModel={{ enabled: settings.ollamaEnabled, model: settings.ollamaModel, status: ollama }}
            onVerifyFindings={applySandboxVerification}
          />
        )}
        {route === 'history' && <HistoryView history={history} setHistory={setHistory} onOpen={openHistory} currentId={current?.report.id} />}
        {route === 'rules' && <RulesView disabled={disabledRules} setDisabled={setDisabledRules} />}
        {route === 'settings' && <SettingsView settings={settings} setSettings={setSettings} ollama={ollama} refreshOllama={refreshOllama} onReset={resetDemo} historyCount={history.length} onClearHistory={() => setHistory([])} dismissedCount={Object.keys(dismissed).length} onClearDismissed={() => setDismissed({})} />}
        {route === 'about' && <AboutView />}
      </main>

      <footer className="relative mt-16 bg-[#38291F] text-[#FFF9E9]">
        <div className="gingham h-4 border-y-2 border-line" aria-hidden="true" />
        <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-6 px-[4vw] py-9">
          <div className="flex items-center gap-3">
            <Logo size={52} alt="" className="border-2 border-[#FFF9E9]" />
            <div>
              <p className="font-display text-[20px] font-semibold">ChaosMonkey</p>
              <p className="text-[13px] opacity-80">Shake the code before it ships. Built for Cal Hacks 13.0.</p>
            </div>
          </div>
          <p className="max-w-md text-right font-mono text-[11.5px] opacity-75">
            Runs entirely in this browser tab. No servers, no accounts, no telemetry. Scanned code stays in memory and is gone when you close the tab.
          </p>
        </div>
      </footer>
    </div>
  )
}
