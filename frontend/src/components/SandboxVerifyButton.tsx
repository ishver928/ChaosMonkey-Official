import { useEffect, useRef, useState } from 'react'
import { Container, Loader2, ShieldAlert, X } from 'lucide-react'
import type { Finding, SourceFile } from '@/lib/types'
import { describeLogLine, mergeVerification, pollSandboxRun, startSandboxRun, type SandboxRunRecord } from '@/lib/sandbox'

type Phase = 'idle' | 'starting' | 'running' | 'done' | 'error'

/** A terminal-style feed of what the sandboxed probe agent is doing right now: crawling the
 * app, firing each probe, and the confirmed/not-confirmed outcome — the same narration the
 * backend streams live from inside the Docker container. Purely additive and self-contained;
 * renders nothing until a run is in progress or just finished. */
function LiveFeed({ log, status }: { log: string[]; status: SandboxRunRecord['status'] | 'idle' }) {
  const boxRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight })
  }, [log.length])

  if (log.length === 0) return null
  return (
    <div className="w-[min(92vw,420px)] overflow-hidden rounded-md border-2 border-line bg-[#14171c] shadow-[3px_3px_0_var(--color-line)]">
      <div className="flex items-center gap-2 border-b border-[#2a2f38] px-3 py-1.5">
        <span className="flex gap-1" aria-hidden="true">
          <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
        </span>
        <p className="flex-1 truncate font-mono text-[11px] text-[#9aa4b2]">chaosmonkey-sandbox-agent</p>
        {(status === 'running' || status === 'queued') && <Loader2 size={12} className="animate-spin text-[#9aa4b2]" aria-hidden="true" />}
      </div>
      <div ref={boxRef} className="max-h-[220px] overflow-y-auto px-3 py-2 font-mono text-[11.5px] leading-relaxed">
        {log.map((line, i) => {
          const d = describeLogLine(line)
          if (d.kind === 'raw') return <p key={i} className="truncate text-[#5b6472]" title={d.text}>{d.text}</p>
          const color = d.status === 'confirmed' ? 'text-[#ff8a7a]' : 'text-[#c8d0dc]'
          return <p key={i} className={color}>{d.text}</p>
        })}
      </div>
    </div>
  )
}

/** Triggers the backend's Docker sandbox verification for the current in-memory findings and
 * merges the results back in once done. Fails quietly into an inline message (never a modal or
 * blocking error) when the backend or Docker isn't available — same spirit as the Ollama
 * integration's silent fallback. */
export function SandboxVerifyButton({ files, findings, onVerified }: {
  files: SourceFile[]
  findings: Finding[]
  onVerified: (findings: Finding[]) => void
}) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [message, setMessage] = useState('')
  const [log, setLog] = useState<string[]>([])
  const [status, setStatus] = useState<SandboxRunRecord['status'] | 'idle'>('idle')
  const [dismissed, setDismissed] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const run = async () => {
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setPhase('starting')
    setMessage('')
    setLog([])
    setStatus('queued')
    setDismissed(false)
    try {
      const runId = await startSandboxRun(files, findings)
      setPhase('running')
      const rec = await pollSandboxRun(runId, ctrl.signal, (tick) => {
        setLog(tick.log)
        setStatus(tick.status)
      })
      if (ctrl.signal.aborted) return

      if (rec.status === 'docker_unavailable') {
        setPhase('error')
        setMessage(rec.error ? `Docker unavailable: ${rec.error}` : 'Docker unavailable on this machine.')
        return
      }
      if (rec.status !== 'done') {
        setPhase('error')
        setMessage(rec.error || 'Sandbox run did not finish.')
        return
      }

      onVerified(mergeVerification(findings, rec.results))
      const confirmed = rec.results.filter((r) => r.verification.status === 'confirmed').length
      setPhase('done')
      setMessage(
        rec.results.length
          ? `${confirmed} of ${rec.results.length} checked finding(s) confirmed exploitable in ${rec.stack_detected || 'the app'}.`
          : 'No testable findings in this scan.',
      )
    } catch {
      if (ctrl.signal.aborted) return
      setPhase('error')
      setMessage('Backend offline, or the sandbox run failed — the static report above is unaffected.')
    }
  }

  const busy = phase === 'starting' || phase === 'running'
  const showFeed = !dismissed && (busy || (phase !== 'idle' && log.length > 0))

  return (
    <div className="flex flex-col items-end gap-2">
      <button type="button" className="btn btn-quiet" onClick={() => void run()} disabled={busy || findings.length === 0}>
        {busy ? <Loader2 size={15} className="animate-spin" aria-hidden="true" /> : <Container size={15} aria-hidden="true" />}
        {phase === 'running' ? 'Verifying in sandbox…' : phase === 'starting' ? 'Starting sandbox…' : 'Verify in Docker sandbox'}
      </button>
      {message && (
        <p className="flex max-w-[34ch] items-start gap-1 text-right font-mono text-[11px] text-muted" role="status">
          {phase === 'error' && <ShieldAlert size={12} className="mt-0.5 shrink-0" aria-hidden="true" />}
          {message}
        </p>
      )}
      {showFeed && (
        <div className="relative">
          <LiveFeed log={log} status={status} />
          {!busy && (
            <button
              type="button"
              className="absolute -right-2 -top-2 rounded-full border border-line bg-surface p-0.5 text-muted hover:text-strong"
              onClick={() => setDismissed(true)}
              aria-label="Hide sandbox log"
            >
              <X size={13} aria-hidden="true" />
            </button>
          )}
        </div>
      )}
    </div>
  )
}
