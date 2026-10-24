import type { Finding } from './types'
import { RULE_BY_ID } from './rules'
import { scrub } from './redaction'

/*
 * Optional local model via Ollama on this machine. Only masked snippets and a few masked
 * surrounding lines are ever sent, and only to 127.0.0.1. If Ollama isn't running we stay quiet
 * and the built-in analyst is used.
 */

export const OLLAMA_URL = 'http://127.0.0.1:11434'

export interface OllamaModel { name: string; size: number }
export type OllamaStatus = { state: 'checking' } | { state: 'offline' } | { state: 'ready'; models: OllamaModel[] }

export async function detectOllama(timeoutMs = 1500): Promise<OllamaStatus> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: ctrl.signal })
    if (!res.ok) return { state: 'offline' }
    const data = (await res.json()) as { models?: { name: string; size: number }[] }
    return { state: 'ready', models: (data.models ?? []).map((m) => ({ name: m.name, size: m.size })) }
  } catch {
    return { state: 'offline' }
  } finally {
    clearTimeout(timer)
  }
}

export function buildPrompt(f: Finding, maskedContext: string): string {
  const rule = RULE_BY_ID[f.ruleId]
  return scrub(`A local static scanner flagged this in ${f.file} (line ${f.line}).
Rule: ${f.ruleId} ${rule?.title ?? ''} (severity: ${f.severity}, category: ${f.category})${f.note ? `\nDetail: ${f.note}` : ''}
Sensitive values are masked with bullets; never ask for or guess them.

Code (masked):
\`\`\`
${maskedContext}
\`\`\`

Reply in this exact format, under 180 words:
WHY: two or three sentences describing a realistic attack.
FIX: a short corrected version of the flagged line(s) in a fenced code block.
STEPS: up to three short bullet points.`)
}

const SYSTEM = 'You are a pragmatic application-security reviewer helping a developer fix code written with an AI assistant. Be concrete and brief. Never reproduce masked values.'

/** Stream a chat completion from Ollama. Calls onToken for each chunk; resolves with the full text. */
export async function streamExplanation(model: string, prompt: string, onToken: (t: string) => void, signal?: AbortSignal): Promise<string> {
  const res = await fetch(`${OLLAMA_URL}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, stream: true, options: { temperature: 0.2 }, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: prompt }] }),
    signal,
  })
  if (!res.ok || !res.body) throw new Error(`Ollama returned ${res.status}`)
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let full = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (!line.trim()) continue
      try {
        const chunk = JSON.parse(line) as { message?: { content?: string }; done?: boolean }
        const t = chunk.message?.content ?? ''
        if (t) { full += t; onToken(t) }
      } catch {
        /* partial line; ignore */
      }
    }
  }
  return full
}
