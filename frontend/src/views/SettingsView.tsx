import { useState } from 'react'
import { Cpu, Moon, RefreshCw, RotateCcw, Sun } from 'lucide-react'
import type { Settings } from '@/lib/storage'
import { OLLAMA_URL, type OllamaStatus } from '@/lib/ollama'

function Card({ title, children, eyebrow }: { title: string; eyebrow: string; children: React.ReactNode }) {
  return (
    <section className="card card-shadow p-6">
      <p className="eyebrow">{eyebrow}</p>
      <h2 className="mt-1 text-[24px]">{title}</h2>
      <div className="mt-4">{children}</div>
    </section>
  )
}

const gb = (bytes: number) => `${(bytes / 1e9).toFixed(1)} GB`

export function SettingsView({ settings, setSettings, ollama, refreshOllama, onReset, historyCount, onClearHistory, dismissedCount, onClearDismissed }: {
  settings: Settings
  setSettings: (s: Settings) => void
  ollama: OllamaStatus
  refreshOllama: () => Promise<OllamaStatus>
  onReset: () => void
  historyCount: number
  onClearHistory: () => void
  dismissedCount: number
  onClearDismissed: () => void
}) {
  const [confirmReset, setConfirmReset] = useState(false)

  const enable = async (on: boolean) => {
    setSettings({ ...settings, ollamaEnabled: on })
    if (on) {
      const status = await refreshOllama()
      if (status.state === 'ready' && !settings.ollamaModel && status.models[0]) setSettings({ ...settings, ollamaEnabled: true, ollamaModel: status.models[0].name })
    }
  }

  return (
    <div className="mx-auto max-w-[1120px] px-[4vw] pt-14">
      <p className="eyebrow">Settings</p>
      <h1 className="mt-1 text-[clamp(38px,5vw,58px)] font-semibold">Knobs and switches.</h1>

      <div className="mt-10 grid gap-8 lg:grid-cols-[1.3fr_1fr]">
        <Card eyebrow="Explanation engine" title="Local model (Ollama)">
          <p className="text-[14.5px]">
            The <strong className="text-strong">built-in analyst</strong> always works offline. If you run <a className="font-extrabold text-denim" href="#/about">Ollama</a> on this machine,
            ChaosMonkey can also ask a local model to explain findings. Only masked snippets go to <code className="font-mono text-[12.5px]">{OLLAMA_URL}</code>, nowhere else.
          </p>
          <div className="mt-5 flex items-center justify-between gap-4 rounded-md border-[1.5px] border-[var(--color-rule)] p-4">
            <div className="flex items-center gap-3">
              <Cpu size={20} className="text-denim" aria-hidden="true" />
              <div>
                <p className="font-extrabold text-strong">Use a local model</p>
                <p className="text-[13px] text-muted">Falls back to the built-in analyst silently if it’s not there.</p>
              </div>
            </div>
            <button type="button" role="switch" aria-checked={settings.ollamaEnabled} className="toggle" aria-label="Use a local model" onClick={() => void enable(!settings.ollamaEnabled)} />
          </div>

          {settings.ollamaEnabled && (
            <div className="mt-4 rise">
              <div className="flex flex-wrap items-center justify-between gap-3" role="status" aria-live="polite">
                <p className="flex items-center gap-2 text-[14px] font-bold text-strong">
                  <span className={`inline-block h-2.5 w-2.5 rounded-full ${ollama.state === 'ready' ? 'bg-sage-ink' : ollama.state === 'checking' ? 'bg-banana pulse-dot' : 'bg-[var(--color-muted)]'}`} aria-hidden="true" />
                  {ollama.state === 'ready' ? `Ollama detected · ${ollama.models.length} model${ollama.models.length === 1 ? '' : 's'} installed` : ollama.state === 'checking' ? 'Looking for Ollama on 127.0.0.1:11434…' : 'Ollama not detected. Using the built-in analyst.'}
                </p>
                <button type="button" className="btn btn-sm btn-quiet" onClick={() => void refreshOllama()} disabled={ollama.state === 'checking'}><RefreshCw size={13} aria-hidden="true" /> Check again</button>
              </div>
              {ollama.state === 'ready' && ollama.models.length > 0 && (
                <div className="mt-4">
                  <label htmlFor="model" className="mb-1.5 block text-[13px] font-extrabold text-strong">Model</label>
                  <select id="model" className="field h-10" value={settings.ollamaModel} onChange={(e) => setSettings({ ...settings, ollamaModel: e.target.value })}>
                    {!settings.ollamaModel && <option value="">Choose a model</option>}
                    {ollama.models.map((m) => <option key={m.name} value={m.name}>{m.name} · {gb(m.size)}</option>)}
                  </select>
                </div>
              )}
              {ollama.state === 'ready' && ollama.models.length === 0 && <p className="mt-3 text-[13.5px]">Ollama is running but has no models. Try <code className="rounded bg-butter px-1 font-mono text-[12.5px]">ollama pull llama3.2:3b</code>.</p>}
              {ollama.state === 'offline' && (
                <div className="mt-3 rounded-md bg-bg p-3 font-mono text-[12px] leading-relaxed">
                  <p className="text-muted"># install Ollama, then:</p>
                  <p>ollama pull llama3.2:3b</p>
                  <p>ollama serve</p>
                </div>
              )}
            </div>
          )}
        </Card>

        <div className="space-y-8">
          <Card eyebrow="Appearance" title="Theme">
            <div className="flex gap-2" role="radiogroup" aria-label="Theme">
              {([['light', 'Paper', Sun], ['dark', 'Night shift', Moon]] as const).map(([value, label, Icon]) => (
                <button key={value} type="button" role="radio" aria-checked={settings.theme === value} aria-pressed={settings.theme === value} className="chip !min-h-[38px] !px-4" onClick={() => setSettings({ ...settings, theme: value })}>
                  <Icon size={14} aria-hidden="true" /> {label}
                </button>
              ))}
            </div>
          </Card>

          <Card eyebrow="Data on this device" title="Storage">
            <ul className="space-y-3 text-[14px]">
              <li className="flex items-center justify-between gap-3"><span>{historyCount} scans in history</span><button type="button" className="btn btn-sm btn-quiet" onClick={onClearHistory} disabled={!historyCount}>Clear</button></li>
              <li className="flex items-center justify-between gap-3"><span>{dismissedCount} dismissed findings</span><button type="button" className="btn btn-sm btn-quiet" onClick={onClearDismissed} disabled={!dismissedCount}>Clear</button></li>
            </ul>
            <div className="mt-5 border-t border-[var(--color-rule)] pt-4">
              {confirmReset ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13.5px] font-bold text-coral-ink">Wipe everything and re-seed the demo?</span>
                  <button type="button" className="btn btn-sm btn-danger" onClick={onReset}>Yes, reset</button>
                  <button type="button" className="btn btn-sm btn-quiet" onClick={() => setConfirmReset(false)}>Cancel</button>
                </div>
              ) : (
                <button type="button" className="btn btn-sm btn-quiet" onClick={() => setConfirmReset(true)}><RotateCcw size={14} aria-hidden="true" /> Reset demo data</button>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
