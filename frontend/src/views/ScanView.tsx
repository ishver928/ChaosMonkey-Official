import { useRef, useState } from 'react'
import { ArrowRight, ClipboardPaste, FileCode2, FolderOpen, FolderUp, Lock, Upload } from 'lucide-react'
import type { SkippedFile, SourceFile } from '@/lib/types'
import type { ScanProgress } from '@/App'
import type { HistoryEntry } from '@/lib/storage'
import { readDataTransfer, readFileList, projectNameFrom, type IntakeResult } from '@/lib/intake'
import { detectLanguage } from '@/lib/language'
import { RULE_META } from '@/lib/rules'
import { CATEGORIES, CATEGORY_LABEL, chaosScore } from '@/lib/severity'
import { CableDivider, Logo, MonkeySwing } from '@/components/Brand'
import { CategoryIcon } from '@/components/Severity'

const PASTE_EXAMPLE = `// paste something an assistant wrote for you, e.g.
const stripe = new Stripe('sk_live_…')
localStorage.setItem('token', res.token)
console.log('signup', user.email, user.ssn)`

const CATEGORY_BLURB: Record<string, string> = {
  secrets: 'Cloud, payment, LLM and GitHub keys, private keys, JWTs, credentialed DB URLs, committed .env files, and high-entropy strings hiding behind names like token or secret.',
  pii: 'Emails, phone numbers, SSNs, Luhn-checked card numbers, dates of birth, plus personal data sneaking into logs or query strings.',
  storage: 'Tokens in localStorage, MD5/SHA-1 passwords, hardcoded session secrets, cookies without HttpOnly/Secure/SameSite, TLS checks switched off, unignored .env files.',
}

function skippedSummary(skipped: SkippedFile[]): string {
  const by = skipped.reduce<Record<string, number>>((acc, s) => ({ ...acc, [s.reason]: (acc[s.reason] ?? 0) + 1 }), {})
  const label: Record<string, string> = { 'ignored-dir': 'in node_modules/.git/build', unsupported: 'unsupported type', 'too-large': 'over 1 MB', binary: 'binary' }
  return Object.entries(by).map(([k, n]) => `${n} ${label[k] ?? k}`).join(' · ')
}

export function ScanView({ onScan, onDemo, progress, error, latest }: {
  onScan: (files: SourceFile[], name: string, opts?: { skipped?: SkippedFile[] }) => Promise<void>
  onDemo: () => void
  progress: ScanProgress | null
  error: string | null
  latest?: HistoryEntry
}) {
  const [mode, setMode] = useState<'paste' | 'files'>('paste')
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('snippet.ts')
  const [formError, setFormError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [picked, setPicked] = useState<IntakeResult | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const dirInput = useRef<HTMLInputElement>(null)

  const busy = !!progress

  const scanPaste = () => {
    const name = filename.trim()
    if (!code.trim()) return setFormError('Paste some code first. Or hit “Load demo project” to see a full report.')
    if (!name || !detectLanguage(name)) return setFormError('Give it a filename with a supported extension, like app.ts, main.py or .env.')
    setFormError('')
    void onScan([{ path: name, content: code.replace(/\r\n/g, '\n') }], name)
  }

  const take = (result: IntakeResult) => {
    setPicked(result)
    if (result.files.length === 0) {
      setFormError(result.skipped.length ? `Nothing scannable in there (${skippedSummary(result.skipped)}).` : 'No files found.')
      return
    }
    setFormError('')
    void onScan(result.files, projectNameFrom(result.files), { skipped: result.skipped })
  }

  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    setMode('files')
    take(await readDataTransfer(e.dataTransfer))
  }

  return (
    <>
      {/* Hero */}
      <section className="mx-auto grid max-w-[1320px] items-center gap-10 px-[6vw] pb-14 pt-20 lg:grid-cols-[1.15fr_.85fr] lg:gap-[6vw]">
        <div>
          <p className="eyebrow mb-4">A safety net for AI-written code</p>
          <h1 className="text-[clamp(56px,7.5vw,104px)] font-semibold tracking-[-0.05em]">ChaosMonkey</h1>
          <p className="mt-1 font-display text-[clamp(26px,2.8vw,40px)] font-medium text-denim">Shake the code before it ships.</p>
          <p className="mt-6 max-w-[620px] text-[18px] leading-relaxed">
            Your assistant writes fast. Sometimes it also pastes a live Stripe key into <code className="rounded bg-butter px-1 text-[15px]">billing.js</code>, hashes passwords with MD5 and logs your users’ SSNs.
            ChaosMonkey finds that before it leaves your laptop, explains why it matters, and hands you the fix.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <button type="button" className="btn btn-primary !min-h-[48px] !px-6 text-[15px]" onClick={onDemo} disabled={busy}>Load demo project</button>
            <a href="#intake" className="font-extrabold text-denim underline-offset-4 hover:underline">Scan your own code <ArrowRight size={15} className="inline" aria-hidden="true" /></a>
          </div>
          <p className="mt-5 flex items-center gap-2 text-[13px] text-muted"><Lock size={13} aria-hidden="true" /> {RULE_META.length} local detectors · runs in a Web Worker · 0 bytes uploaded</p>
        </div>
        <div className="relative grid min-h-[380px] place-items-center">
          <div
            className="gingham absolute h-[290px] w-[350px] -rotate-6 border-2 border-line"
            style={{ borderRadius: '54% 46% 60% 40% / 46% 52% 48% 54%' }}
            aria-hidden="true"
          />
          <Logo size={330} className="relative drop-shadow-[5px_7px_0_rgba(89,66,55,0.14)]" />
          <p className="absolute bottom-2 right-0 -rotate-6 font-display text-[17px] text-denim">your code’s tiny bodyguard ↗</p>
        </div>
      </section>

      {/* Intake */}
      <section id="intake" className="mx-auto max-w-[1240px] scroll-mt-6 px-[3vw]">
        <div className="card card-shadow">
          <div className="gingham flex h-9 items-center justify-between border-b-2 border-line px-4 text-[11px] font-extrabold uppercase tracking-[0.12em] text-strong">
            <span>New scan</span><span>Local only · nothing uploaded</span>
          </div>
          <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--color-rule)] px-8 pb-6 pt-8">
            <div>
              <p className="eyebrow">Step 1</p>
              <h2 className="mt-1 text-[clamp(28px,3.4vw,44px)]">Give the monkey something to shake.</h2>
            </div>
            <div className="flex gap-2" role="tablist" aria-label="Input method">
              <button type="button" role="tab" aria-selected={mode === 'paste'} aria-pressed={mode === 'paste'} className="chip" onClick={() => setMode('paste')}><ClipboardPaste size={14} aria-hidden="true" /> Paste code</button>
              <button type="button" role="tab" aria-selected={mode === 'files'} aria-pressed={mode === 'files'} className="chip" onClick={() => setMode('files')}><FolderUp size={14} aria-hidden="true" /> Files or folder</button>
            </div>
          </div>

          {busy ? (
            <div className="flex min-h-[420px] flex-col items-center justify-center gap-5 px-8 py-12 text-center" aria-live="polite" role="status">
              <MonkeySwing size={128} label="Scanning" />
              <h3 className="text-[28px]">Shaking {progress.name}…</h3>
              <div className="w-full max-w-md">
                <div className="h-2.5 overflow-hidden rounded-full border-[1.5px] border-line bg-surface">
                  <div className="h-full bg-banana transition-[width] duration-200" style={{ width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%` }} />
                </div>
                <p className="mt-2 truncate font-mono text-[12px] text-muted">{progress.done}/{progress.total} · {progress.path}</p>
              </div>
            </div>
          ) : (
            <div
              className={`grid gap-0 transition-colors md:grid-cols-[1.25fr_.75fr] ${dragging ? 'bg-butter' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
              onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false) }}
              onDrop={onDrop}
            >
              <div className="border-b border-line p-8 md:border-b-0 md:border-r">
                {mode === 'paste' ? (
                  <>
                    <label htmlFor="filename" className="mb-1.5 block text-[13px] font-extrabold text-strong">Filename <span className="font-normal text-muted">(sets the language)</span></label>
                    <input id="filename" className="field h-10" value={filename} onChange={(e) => setFilename(e.target.value)} spellCheck={false} />
                    <div className="mb-1.5 mt-5 flex items-center justify-between">
                      <label htmlFor="code" className="text-[13px] font-extrabold text-strong">Code</label>
                      <span className="text-[11.5px] text-muted">Stays in this tab. Never saved.</span>
                    </div>
                    <textarea id="code" className="field h-[280px] resize-y leading-relaxed" value={code} onChange={(e) => setCode(e.target.value)} placeholder={PASTE_EXAMPLE} spellCheck={false} />
                  </>
                ) : (
                  <div className={`flex h-[370px] flex-col items-center justify-center rounded-xl border-2 border-dashed ${dragging ? 'border-denim' : 'border-line'} bg-code px-6 text-center`}>
                    <Upload size={34} strokeWidth={1.8} className="text-denim" aria-hidden="true" />
                    <p className="mt-3 font-display text-[22px] text-strong">Drop files or a whole folder here</p>
                    <p className="mt-1 max-w-sm text-[13.5px] text-muted">JS/TS/JSX/TSX, Python, .env, JSON, YAML, TOML, INI, SQL, shell. node_modules, .git, build output, binaries and files over 1 MB are skipped.</p>
                    <div className="mt-5 flex flex-wrap justify-center gap-3">
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => fileInput.current?.click()}><FileCode2 size={14} aria-hidden="true" /> Choose files</button>
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => dirInput.current?.click()}><FolderOpen size={14} aria-hidden="true" /> Choose folder</button>
                    </div>
                    {picked && picked.skipped.length > 0 && <p className="mt-4 font-mono text-[11.5px] text-muted">Last pick skipped {skippedSummary(picked.skipped)}</p>}
                    <input ref={fileInput} type="file" multiple hidden onChange={async (e) => { if (e.target.files) take(await readFileList(e.target.files)); e.target.value = '' }} />
                    <input ref={dirInput} type="file" hidden {...({ webkitdirectory: '', directory: '' } as Record<string, string>)} onChange={async (e) => { if (e.target.files) take(await readFileList(e.target.files)); e.target.value = '' }} />
                  </div>
                )}
                {(formError || error) && <p className="mt-3 text-[13.5px] font-extrabold text-coral-ink" role="alert">{formError || error}</p>}
                <div className="mt-5 flex flex-wrap gap-3">
                  {mode === 'paste' && <button type="button" className="btn btn-primary" onClick={scanPaste}>Scan for chaos</button>}
                  <button type="button" className="btn btn-secondary" onClick={onDemo}>Load demo project</button>
                  {mode === 'paste' && code && <button type="button" className="btn btn-quiet" onClick={() => { setCode(''); setFormError('') }}>Clear</button>}
                </div>
              </div>
              <aside className="bg-bg p-8">
                <p className="eyebrow">What happens next</p>
                <ol className="prose-steps mt-4 space-y-4 text-[14.5px]">
                  <li><strong className="text-strong">Read locally.</strong> Files are read with the browser’s File API, right here. No upload request exists.</li>
                  <li><strong className="text-strong">Scan in a worker.</strong> {RULE_META.length} transparent rules run off the main thread, so the page stays smooth.</li>
                  <li><strong className="text-strong">Mask, explain, fix.</strong> Every secret is masked before display. Each finding gets an attack story and a before/after fix.</li>
                </ol>
                {latest && (
                  <a href="#/history" className="card-thin mt-7 block rounded-md p-4 no-underline transition-transform hover:-translate-y-0.5">
                    <p className="mono-label">LAST SCAN</p>
                    <p className="mt-1 font-display text-[19px] text-strong">{latest.name}</p>
                    <p className="text-[13px]">Chaos Score <strong className="text-strong">{chaosScore(latest.findings)}</strong> · {latest.findings.length} findings · {latest.files.length} files</p>
                  </a>
                )}
              </aside>
            </div>
          )}
        </div>
      </section>

      <CableDivider className="mx-auto mt-20 max-w-[1240px] px-[3vw]" />

      {/* Field guide */}
      <section className="mx-auto grid max-w-[1240px] gap-10 px-[3vw] py-14 lg:grid-cols-[.8fr_1.2fr]">
        <div>
          <p className="eyebrow">A short field guide</p>
          <h2 className="mt-2 text-[clamp(32px,4vw,52px)]">Three kinds of chaos.</h2>
          <p className="mt-4 max-w-sm text-[16px]">Clues, not verdicts. Every rule is listed on the <a href="#/rules" className="font-extrabold text-denim">Rules</a> page with exactly what it matches, and you can switch any of them off.</p>
        </div>
        <ul className="divide-y divide-[var(--color-rule)] border-y border-line">
          {CATEGORIES.map((c) => (
            <li key={c} className="grid grid-cols-[44px_1fr_auto] items-start gap-5 py-5">
              <span className="grid h-10 w-10 place-items-center rounded-full border-[1.5px] border-line bg-surface text-strong"><CategoryIcon category={c} size={18} /></span>
              <div>
                <p className="font-display text-[20px] text-strong">{CATEGORY_LABEL[c]}</p>
                <p className="mt-1 text-[14.5px]">{CATEGORY_BLURB[c]}</p>
              </div>
              <span className="mono-label whitespace-nowrap pt-1">{RULE_META.filter((r) => r.category === c).length} rules</span>
            </li>
          ))}
        </ul>
      </section>
    </>
  )
}
