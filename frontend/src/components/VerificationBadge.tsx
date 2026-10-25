import { useState } from 'react'
import { ChevronDown, ChevronUp, FlaskConical, ShieldAlert } from 'lucide-react'
import type { VerificationResult } from '@/lib/types'

/** Minimal, additive badge + evidence expander for a sandbox verification result. Renders
 * nothing when a finding was never run through the sandbox (``verification`` is undefined) —
 * this must never be read as "safe", only "not yet dynamically checked". */
export function VerificationBadge({ verification }: { verification?: VerificationResult }) {
  const [open, setOpen] = useState(false)
  if (!verification) return null

  const { status, evidence, detail, probe_id: probeId } = verification
  if (status === 'confirmed') {
    return (
      <span className="inline-flex flex-col items-start gap-1">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-md border-[1.5px] border-[var(--color-sev-critical)] bg-[var(--color-sev-critical-bg)] px-2 py-0.5 font-mono text-[11px] font-semibold text-[var(--color-sev-critical)]"
          aria-expanded={open}
        >
          <ShieldAlert size={12} aria-hidden="true" /> Confirmed in sandbox
          {open ? <ChevronUp size={12} aria-hidden="true" /> : <ChevronDown size={12} aria-hidden="true" />}
        </button>
        {open && (
          <div className="max-w-[48ch] rounded-md border border-[var(--color-rule)] bg-[var(--color-surface)] px-2.5 py-1.5 text-[12px] text-muted">
            {evidence && <p className="font-mono text-[11.5px] text-strong">{evidence}</p>}
            {detail && <p className="mt-0.5">{detail}</p>}
            {probeId && <p className="mt-0.5 font-mono text-[10.5px] text-muted">probe {probeId}</p>}
          </div>
        )}
      </span>
    )
  }

  // not_confirmed / not_testable / skipped: a quiet, explicitly-hedged chip. Never says "safe".
  const label =
    status === 'not_confirmed' ? 'Sandbox: not confirmed' :
    status === 'not_testable' ? 'Sandbox: not testable' : 'Sandbox: skipped'
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border-[1.5px] border-line px-2 py-0.5 font-mono text-[11px] font-semibold text-muted"
      title={detail || 'This probe did not reproduce the issue — that is not the same as the code being safe.'}
    >
      <FlaskConical size={12} aria-hidden="true" /> {label}
    </span>
  )
}
