import type { ScanRequest, ScanResponse } from '@/workers/scan.worker'
import type { Finding, SourceFile } from './types'
import { scanProject } from './scanner'

let worker: Worker | null = null
let nextJob = 1

function getWorker(): Worker | null {
  if (worker) return worker
  try {
    worker = new Worker(new URL('../workers/scan.worker.ts', import.meta.url), { type: 'module' })
  } catch {
    worker = null
  }
  return worker
}

/** Scan in a Web Worker so the UI stays responsive. Falls back to the main thread if workers are unavailable. */
export function scanInWorker(
  files: SourceFile[],
  enabledRuleIds: string[],
  onProgress?: (done: number, total: number, path: string) => void,
): Promise<{ findings: Finding[]; durationMs: number }> {
  const w = getWorker()
  if (!w) {
    const t = performance.now()
    const findings = scanProject(files, enabledRuleIds, onProgress)
    return Promise.resolve({ findings, durationMs: Math.round(performance.now() - t) })
  }
  const jobId = nextJob++
  return new Promise((resolve, reject) => {
    const onMessage = (e: MessageEvent<ScanResponse>) => {
      const msg = e.data
      if (msg.jobId !== jobId) return
      if (msg.type === 'progress') onProgress?.(msg.done, msg.total, msg.path)
      else {
        w.removeEventListener('message', onMessage)
        if (msg.type === 'result') resolve({ findings: msg.findings, durationMs: msg.durationMs })
        else reject(new Error(msg.message))
      }
    }
    w.addEventListener('message', onMessage)
    w.postMessage({ type: 'scan', jobId, files, enabledRuleIds } satisfies ScanRequest)
  })
}
