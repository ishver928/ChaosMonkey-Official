import type { Finding, SourceFile, VerificationResult } from './types'

/*
 * Optional Docker sandbox verification, via the backend at the same origin (proxied to
 * 127.0.0.1:8000 in dev, see vite.config.ts). The frontend scans entirely client-side, so it
 * has files/findings in memory already and posts them directly — no server-side scan_id needed.
 * If the backend or Docker isn't available we fail quietly, same as the Ollama integration.
 */

export interface SandboxFindingResult {
  finding_id: string
  ruleId: string
  file: string
  verification: VerificationResult
}

export interface SandboxRunRecord {
  id: string
  scan_id: string
  status: 'queued' | 'running' | 'done' | 'error' | 'docker_unavailable'
  docker_available: boolean
  gvisor: boolean
  stack_detected: string
  error: string
  results: SandboxFindingResult[]
  canary_tag: string
  requests_sent: number
  /** Growing transcript: setup commands plus the probe agent's live narration. */
  log: string[]
}

async function postJson<T>(path: string, body: unknown, timeoutMs: number): Promise<T> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    })
    if (!res.ok) throw new Error(`${path} → ${res.status}`)
    return (await res.json()) as T
  } finally {
    clearTimeout(timer)
  }
}

async function getJson<T>(path: string, signal: AbortSignal): Promise<T> {
  const res = await fetch(path, { signal })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return (await res.json()) as T
}

/** Starts a sandbox run for the given in-memory files/findings. Throws on any failure
 * (backend offline, network error, bad request) — callers should catch and show a quiet,
 * non-blocking message, exactly like the Ollama fallback. */
export async function startSandboxRun(files: SourceFile[], findings: Finding[], findingIds?: string[]): Promise<string> {
  const resp = await postJson<{ sandbox_run_id: string }>('/api/sandbox/run-adhoc', {
    files: files.map((f) => ({ path: f.path, content: f.content })),
    findings,
    finding_ids: findingIds ?? null,
  }, 10_000)
  return resp.sandbox_run_id
}

/** Polls GET /api/sandbox/{id} until it leaves queued/running, a timeout elapses, or
 * ``signal`` aborts. Resolves with whatever the last poll returned (which may still be
 * queued/running if it timed out — callers should check ``status``).
 *
 * ``onTick`` fires on *every* poll, including while still queued/running — the record's
 * ``log`` grows in near real time as the sandboxed probe agent narrates what it's doing, so a
 * caller can render that as a live feed instead of only seeing output once the whole run ends. */
export async function pollSandboxRun(
  runId: string, signal: AbortSignal, onTick?: (rec: SandboxRunRecord) => void, maxWaitMs = 90_000,
): Promise<SandboxRunRecord> {
  const deadline = Date.now() + maxWaitMs
  let last: SandboxRunRecord | null = null
  while (Date.now() < deadline) {
    if (signal.aborted) throw new DOMException('aborted', 'AbortError')
    last = await getJson<SandboxRunRecord>(`/api/sandbox/${runId}`, signal)
    onTick?.(last)
    if (last.status !== 'queued' && last.status !== 'running') return last
    await new Promise((resolve, reject) => {
      const t = setTimeout(resolve, 900)
      signal.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('aborted', 'AbortError')) }, { once: true })
    })
  }
  if (last) return last
  throw new Error('Sandbox run timed out before the backend responded even once')
}

/** Turns one raw ``SandboxRunRecord.log`` line into something readable: the agent emits JSON
 * progress events (``{"event": "...", "message": "..."}``); the setup phase emits raw ``$
 * docker ...`` command lines. Both are shown, styled differently by the caller via ``kind``. */
export function describeLogLine(line: string): { kind: 'event' | 'raw'; text: string; status?: string } {
  if (line.startsWith('$ ')) return { kind: 'raw', text: line }
  try {
    const parsed = JSON.parse(line) as { event?: string; message?: string; status?: string }
    if (parsed.event && parsed.message) return { kind: 'event', text: parsed.message, status: parsed.status }
  } catch {
    // not JSON — fall through
  }
  return { kind: 'raw', text: line }
}

/** Merges verification results onto a findings array by finding id. Findings with no matching
 * result are left untouched (their ``verification`` stays whatever it was, usually undefined —
 * never treat an untouched finding as "safe"). */
export function mergeVerification(findings: Finding[], results: SandboxFindingResult[]): Finding[] {
  const byId = new Map(results.map((r) => [r.finding_id, r.verification]))
  return findings.map((f) => (byId.has(f.id) ? { ...f, verification: byId.get(f.id) } : f))
}
