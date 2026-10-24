import { useRef, useState } from 'react'
import { Container, Loader2 } from 'lucide-react'
import type { Finding, SourceFile } from '@/lib/types'
import { mergeVerification, pollSandboxRun, startSandboxRun } from '@/lib/sandbox'

type Phase = 'idle' | 'starting' | 'running' | 'done' | 'error'

/** Triggers the backend's Docker sandbox verification for the current in-memory findings and
 * merges the results back in once done. Fails quietly into an inline message (never a modal or
 * blocking error) when the backend or Docker isn't available — same spirit as the Ollama
 * integration's silent fallback. Additive: renders nothing that didn't exist before except
 * this one button + its own status line. */
export function SandboxVerifyButton({ files, findings, onVerified }: {
  files: SourceFile[]
  findings: Finding[]
  onVerified: (findings: Finding[]) => void
}) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [message, setMessage] = useState('')
  const abortRef = useRef<AbortController | null>(null)

  const run = async () => {
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl
    setPhase('starting')
    setMessage('')
    try {
      const runId = await startSandboxRun(files, findings)
      setPhase('running')
      const rec = await pollSandboxRun(runId, ctrl.signal)
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

  return (
    <div className="flex flex-col items-end gap-1">
      <button type="button" className="btn btn-quiet" onClick={() => void run()} disabled={busy || findings.length === 0}>
        {busy ? <Loader2 size={15} className="animate-spin" aria-hidden="true" /> : <Container size={15} aria-hidden="true" />}
        {phase === 'running' ? 'Verifying in sandbox…' : phase === 'starting' ? 'Starting sandbox…' : 'Verify in Docker sandbox'}
      </button>
      {message && (
        <p className="max-w-[34ch] text-right font-mono text-[11px] text-muted" role="status">{message}</p>
      )}
    </div>
  )
}
