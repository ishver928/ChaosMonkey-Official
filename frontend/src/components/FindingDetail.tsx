import { useEffect, useMemo, useRef, useState } from 'react'
import { BookOpenCheck, Check, Copy, Cpu, Eye, EyeOff, Flag, ShieldCheck, Undo2 } from 'lucide-react'
import type { Dismissal, Finding, SourceFile } from '@/lib/types'
import { RULE_BY_ID } from '@/lib/rules'
import { adviceFor } from '@/lib/knowledge'
import { applyMasks } from '@/lib/redaction'
import { maskRangesFor } from '@/lib/scanner'
import { buildPrompt, streamExplanation, type OllamaStatus } from '@/lib/ollama'
import { LANGUAGE_LABEL } from '@/lib/language'
import { CodeViewer, DiffView } from './CodeViewer'
import { CategoryTag, SeverityBadge } from './Severity'

export interface LocalModel { enabled: boolean; model: string; status: OllamaStatus }

function EngineLabel({ local, model }: { local: boolean; model?: string }) {
  return local ? (
    <span className="inline-flex items-center gap-1.5 rounded-md border-[1.5px] border-denim px-2 py-0.5 font-mono text-[11px] font-semibold text-denim">
      <Cpu size={12} aria-hidden="true" /> Local model (Ollama) · {model}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 rounded-md border-[1.5px] border-line px-2 py-0.5 font-mono text-[11px] font-semibold text-strong">
      <BookOpenCheck size={12} aria-hidden="true" /> Built-in analyst
    </span>
  )
}

/** Very small renderer for model output: paragraphs, bullets and fenced code. No HTML is ever injected. */
function ModelText({ text }: { text: string }) {
  const blocks = text.split(/```/)
  return (
    <div className="space-y-2 text-[14.5px]">
      {blocks.map((b, i) =>
        i % 2 === 1 ? (
          <pre key={i} className="code overflow-x-auto rounded-md border border-[var(--color-rule)] p-3 text-[12.5px]">{b.replace(/^\w*\n/, '')}</pre>
        ) : (
          b.split('\n').filter((l) => l.trim()).map((l, j) => {
            const m = /^(WHY|FIX|STEPS):\s*(.*)$/.exec(l.trim())
            if (m) return <p key={`${i}-${j}`}><strong className="text-strong">{m[1] === 'WHY' ? 'Why: ' : m[1] === 'FIX' ? 'Fix: ' : 'Steps: '}</strong>{m[2]}</p>
            if (/^\s*[-*•]\s/.test(l)) return <p key={`${i}-${j}`} className="pl-4">• {l.replace(/^\s*[-*•]\s/, '')}</p>
            return <p key={`${i}-${j}`}>{l}</p>
          })
        ),
      )}
    </div>
  )
}

export function FindingDetail({
  finding, related, source, dismissal, onDismiss, revealed, onToggleReveal, onSelect, localModel,
}: {
  finding: Finding
  related: Finding[]
  source: SourceFile | null
  dismissal?: Dismissal
  onDismiss: (reason: Dismissal['reason'] | null) => void
  revealed: ReadonlySet<string>
  onToggleReveal: (id: string) => void
  onSelect: (id: string) => void
  localModel: LocalModel
}) {
  const rule = RULE_BY_ID[finding.ruleId]
  const isRevealed = revealed.has(finding.id)

  const maskedContent = useMemo(() => (source ? applyMasks(source.content, maskRangesFor(related, source.path, source.content)) : undefined), [source, related])
  const fullMaskedLine = maskedContent?.split('\n')[finding.line - 1]
  const advice = useMemo(() => adviceFor(finding, fullMaskedLine, maskedContent), [finding, fullMaskedLine, maskedContent])

  const localReady = localModel.enabled && localModel.status.state === 'ready' && !!localModel.model
  const [engine, setEngine] = useState<'builtin' | 'local'>('builtin')
  const [modelText, setModelText] = useState('')
  const [modelState, setModelState] = useState<'idle' | 'streaming' | 'done' | 'failed'>('idle')
  const abort = useRef<AbortController | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    abort.current?.abort()
    setModelText('')
    setModelState('idle')
    setEngine(localReady ? 'local' : 'builtin')
    setCopied(false)
  }, [finding.id, localReady])

  // Auto re-mask a revealed value after 20 seconds.
  useEffect(() => {
    if (!isRevealed) return
    const t = setTimeout(() => onToggleReveal(finding.id), 20000)
    return () => clearTimeout(t)
  }, [isRevealed, finding.id, onToggleReveal])

  const askLocal = async () => {
    if (!localReady) return
    abort.current?.abort()
    const ctrl = new AbortController()
    abort.current = ctrl
    setModelText('')
    setModelState('streaming')
    let context = finding.snippet
    if (source) {
      const masked = applyMasks(source.content, maskRangesFor(related, source.path, source.content)).split('\n')
      context = masked.slice(Math.max(0, finding.line - 4), finding.endLine + 3).join('\n')
    }
    try {
      await streamExplanation(localModel.model, buildPrompt(finding, context), (t) => setModelText((s) => s + t), ctrl.signal)
      setModelState('done')
    } catch {
      if (!ctrl.signal.aborted) setModelState('failed')
    }
  }

  useEffect(() => {
    if (engine === 'local' && modelState === 'idle' && localReady) void askLocal()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engine, modelState, localReady, finding.id])

  const copyFix = async () => {
    try {
      await navigator.clipboard.writeText(advice.fix.after)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }

  const showLocal = engine === 'local' && modelState !== 'failed'
  const fileFindings = related.filter((f) => f.file === finding.file)

  return (
    <article className="rise" aria-labelledby="finding-title">
      <header className="border-b-2 border-line px-6 pb-5 pt-6">
        <div className="flex flex-wrap items-center gap-2.5">
          <SeverityBadge severity={finding.severity} />
          <CategoryTag category={finding.category} />
          <span className="mono-label">{finding.ruleId}</span>
          {dismissal && <span className="stamp !rotate-0">{dismissal.reason === 'false-positive' ? 'FALSE POSITIVE' : 'ACCEPTED RISK'}</span>}
        </div>
        <h2 id="finding-title" className="mt-3 text-[28px]">{rule?.title ?? finding.ruleId}</h2>
        <p className="mt-1.5 font-mono text-[12.5px] text-muted">
          {finding.file}:{finding.line}:{finding.column} · {LANGUAGE_LABEL[finding.language]} · confidence {Math.round(finding.confidence * 100)}%{finding.note ? ` · ${finding.note}` : ''}
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {finding.sensitive && source && (
            <button type="button" className="btn btn-sm btn-quiet" onClick={() => onToggleReveal(finding.id)} aria-pressed={isRevealed}>
              {isRevealed ? <EyeOff size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
              {isRevealed ? 'Hide value' : 'Reveal value'}
            </button>
          )}
          {dismissal ? (
            <button type="button" className="btn btn-sm btn-quiet" onClick={() => onDismiss(null)}><Undo2 size={14} aria-hidden="true" /> Restore finding</button>
          ) : (
            <>
              <button type="button" className="btn btn-sm btn-quiet" onClick={() => onDismiss('false-positive')}><Flag size={14} aria-hidden="true" /> Mark false positive</button>
              <button type="button" className="btn btn-sm btn-quiet" onClick={() => onDismiss('accepted-risk')}><ShieldCheck size={14} aria-hidden="true" /> Accept risk</button>
            </>
          )}
        </div>
        {isRevealed && <p className="mt-2 text-[12px] font-bold text-coral-ink" role="status">Revealed in memory only. Re-masks in 20 seconds, never saved or exported.</p>}
      </header>

      <section className="border-b border-[var(--color-rule)]">
        {source ? (
          <CodeViewer content={source.content} language={finding.language} findings={fileFindings} activeId={finding.id} revealed={revealed} onSelect={onSelect} maxHeight={300} label={`Source of ${finding.file} with risky lines highlighted`} />
        ) : (
          <div className="px-6 py-4">
            <pre className="code overflow-x-auto rounded-md border border-[var(--color-rule)] px-3 py-2">{finding.snippet}</pre>
            <p className="mt-2 text-[12.5px] text-muted">File contents are never saved, so past scans only keep this masked snippet. Re-scan the project to see the full file.</p>
          </div>
        )}
      </section>

      <section className="space-y-6 px-6 py-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2" role="radiogroup" aria-label="Explanation engine">
            <button type="button" role="radio" aria-checked={engine === 'builtin'} className="chip" aria-pressed={engine === 'builtin'} onClick={() => setEngine('builtin')}>Built-in analyst</button>
            <button
              type="button" role="radio" aria-checked={engine === 'local'} className="chip" aria-pressed={engine === 'local'} disabled={!localReady}
              onClick={() => { setEngine('local'); if (modelState === 'failed') setModelState('idle') }}
              title={localReady ? `Ask ${localModel.model} on this machine` : 'Enable a local Ollama model in Settings'}
            >
              <Cpu size={13} aria-hidden="true" /> Local model{localReady ? '' : ' · off'}
            </button>
          </div>
          <EngineLabel local={showLocal} model={localModel.model} />
        </div>

        {showLocal ? (
          <div aria-live="polite">
            <p className="eyebrow mb-2">Local model says</p>
            {modelText ? <ModelText text={modelText} /> : <p className="text-[14px] text-muted">Asking {localModel.model} on 127.0.0.1… (only masked code is sent)</p>}
            {modelState === 'streaming' && <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 bg-[var(--color-line)] pulse-dot" aria-hidden="true" />}
          </div>
        ) : (
          <>
            {engine === 'local' && modelState === 'failed' && <p className="text-[12.5px] text-muted" role="status">The local model didn’t answer, so this is the built-in analyst instead.</p>}
            <div>
              <p className="eyebrow mb-2">Why this is dangerous</p>
              <p className="max-w-[62ch] text-[15.5px] leading-relaxed">{advice.why}</p>
            </div>
            <div>
              <p className="eyebrow mb-2">What to do</p>
              <ol className="prose-steps max-w-[62ch] space-y-2 text-[14.5px]">
                {advice.steps.map((s) => <li key={s} className={s.startsWith('Rotate') ? 'font-bold text-strong' : ''}>{s}</li>)}
              </ol>
            </div>
          </>
        )}

        <div>
          <div className="mb-2 flex items-center justify-between gap-3">
            <p className="eyebrow">Recommended fix · before / after</p>
            <button type="button" className="btn btn-sm btn-primary" onClick={copyFix}>
              {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}{copied ? 'Copied' : 'Copy fix'}
            </button>
          </div>
          <div className="card-thin overflow-hidden rounded-md">
            <DiffView before={advice.fix.before} after={advice.fix.after} />
          </div>
          {advice.fix.note && <p className="mt-2 text-[13px] text-muted">{advice.fix.note}</p>}
          <p className="mt-1 font-mono text-[11px] text-muted">Fix template from the built-in analyst. The before side is masked.</p>
        </div>
      </section>
    </article>
  )
}
