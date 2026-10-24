/// <reference lib="webworker" />
import { scanProject } from '@/lib/scanner'
import type { Finding, SourceFile } from '@/lib/types'

export type ScanRequest = { type: 'scan'; jobId: number; files: SourceFile[]; enabledRuleIds: string[] }
export type ScanResponse =
  | { type: 'progress'; jobId: number; done: number; total: number; path: string }
  | { type: 'result'; jobId: number; findings: Finding[]; durationMs: number }
  | { type: 'error'; jobId: number; message: string }

const ctx = self as unknown as DedicatedWorkerGlobalScope

ctx.onmessage = (event: MessageEvent<ScanRequest>) => {
  const { jobId, files, enabledRuleIds } = event.data
  const started = performance.now()
  try {
    let lastPost = 0
    const findings = scanProject(files, enabledRuleIds, (done, total, path) => {
      const now = performance.now()
      if (now - lastPost > 30 || done === total) {
        lastPost = now
        ctx.postMessage({ type: 'progress', jobId, done, total, path } satisfies ScanResponse)
      }
    })
    ctx.postMessage({ type: 'result', jobId, findings, durationMs: Math.round(performance.now() - started) } satisfies ScanResponse)
  } catch (err) {
    ctx.postMessage({ type: 'error', jobId, message: err instanceof Error ? err.message : 'Scan failed' } satisfies ScanResponse)
  }
}
