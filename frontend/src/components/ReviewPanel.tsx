import { useState } from 'react'
import { CheckCircle2, Loader2, ShieldAlert, Wrench, XCircle } from 'lucide-react'
import type { Review } from '@/lib/plugin'

/**
 * The only place fixes get written to the user's project: an explicit two-step click.
 * Shows the outcome (backup folder, per-fix re-scan verification) once applied.
 */
export function ReviewPanel({ approvedCount, projectPath, review, busy, error, onApply, onDecline }: {
  approvedCount: number
  projectPath: string | null
  review: Review | null
  busy: boolean
  error: string | null
  onApply: () => void
  onDecline: () => void
}) {
  const [confirming, setConfirming] = useState(false)
  const status = review?.status ?? 'pending_review'

  if (status === 'declined') {
    return <div className="card card-shadow p-5" role="status"><p className="font-extrabold text-strong">You kept the code as is.</p><p className="mt-1 text-[14px] text-muted">No files were changed. Claude has been told.</p></div>
  }

  if (review && (status === 'applied' || status === 'rescanning' || status === 'applying' || status === 'error')) {
    return (
      <div className="card card-shadow p-5" role="status" aria-live="polite">
        <p className="flex items-center gap-2 font-extrabold text-strong">
          {status === 'applied' ? <CheckCircle2 size={17} className="text-sage-ink" aria-hidden="true" /> : status === 'error' ? <ShieldAlert size={17} aria-hidden="true" /> : <Loader2 size={17} className="animate-spin" aria-hidden="true" />}
          {status === 'applied' ? `Applied ${review.applied.length} approved fix(es)` : status === 'error' ? 'Applied, but the re-scan did not finish' : 'Applied. Re-scanning to verify…'}
        </p>
        <p className="mt-1 font-mono text-[12px] text-muted">
          Changed: {review.files_changed.join(', ')}{review.backup_dir ? ` · originals backed up in ${review.backup_dir}` : ''}
        </p>
        <ul className="mt-3 space-y-1">
          {review.applied.map((e) => (
            <li key={e.id} className="flex items-center gap-2 text-[14px]">
              {e.result === 'fix_verified' ? <CheckCircle2 size={14} className="shrink-0 text-sage-ink" aria-hidden="true" /> : e.result === 'fix_failed' ? <XCircle size={14} className="shrink-0 text-coral-ink" aria-hidden="true" /> : <Loader2 size={14} className="shrink-0 animate-spin" aria-hidden="true" />}
              <span><strong>{e.result === 'fix_verified' ? 'Verified' : e.result === 'fix_failed' ? 'Still flagged' : 'Checking'}</strong> · {e.title} <span className="font-mono text-[12px] text-muted">{e.location}</span></span>
            </li>
          ))}
        </ul>
        {review.rescan && <p className="mt-3 text-[14px]">After fixes: security score <strong>{review.rescan.security_score}/100</strong>, {review.rescan.total_findings} finding(s) left.</p>}
        {review.rescan_scan_id && status === 'applied' && <a className="btn btn-secondary btn-sm mt-3" href={`#/report/${review.rescan_scan_id}`}>Open the re-scan report</a>}
      </div>
    )
  }

  return (
    <div className="card card-shadow p-5">
      <p className="flex items-center gap-2 font-extrabold text-strong"><Wrench size={16} aria-hidden="true" /> Review fixes</p>
      <p className="mt-1 text-[14px]">
        Tick <strong>Approve fix</strong> on the findings you want fixed. Nothing is written until you click apply.
        {projectPath ? <> Files are backed up to <span className="font-mono text-[12.5px]">.chaosmonkey/backups/</span> first.</> : ' This scan is not linked to a connected project, so fixes cannot be applied from here.'}
      </p>
      {error && <p className="mt-2 flex items-start gap-1 text-[13.5px] text-coral-ink" role="alert"><ShieldAlert size={14} className="mt-0.5 shrink-0" aria-hidden="true" />{error}</p>}
      <div className="mt-4 flex flex-wrap gap-3">
        {!confirming ? (
          <button type="button" className="btn btn-primary" disabled={!projectPath || approvedCount === 0 || busy} onClick={() => setConfirming(true)}>
            Apply {approvedCount} approved {approvedCount === 1 ? 'fix' : 'fixes'} to my project
          </button>
        ) : (
          <>
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => { setConfirming(false); onApply() }}>
              {busy ? <Loader2 size={15} className="animate-spin" aria-hidden="true" /> : null} Yes, write {approvedCount} {approvedCount === 1 ? 'fix' : 'fixes'} to {projectPath?.split(/[\\/]/).pop()}
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => setConfirming(false)}>Cancel</button>
          </>
        )}
        {!confirming && projectPath && (
          <button type="button" className="btn btn-quiet" disabled={busy} onClick={onDecline}>Keep my code as is</button>
        )}
      </div>
    </div>
  )
}
