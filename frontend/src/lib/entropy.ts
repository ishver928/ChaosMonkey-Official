/** Shannon entropy in bits per character. Random base64 secrets sit around 4.5-6; English words ~3. */
export function shannonEntropy(value: string): number {
  if (!value) return 0
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const n of counts.values()) {
    const p = n / value.length
    h -= p * Math.log2(p)
  }
  return h
}

const PLACEHOLDER = /^(?:<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%|x{3,}|\*{3,}|\.{3,}|-+|_+)$|your[_\- ]?|changeme|change[_\- ]me|replace[_\- ]?me|placeholder|example|dummy|sample|redacted|insert[_\- ]|todo|fixme|^test$|^password$|^secret$|^null$|^none$|^undefined$|^true$|^false$|process\.env|import\.meta|os\.environ|getenv/i

/** True for values like YOUR_API_KEY, "changeme", "<token>", ${SECRET} that are obviously not real. */
export function isPlaceholder(value: string): boolean {
  const v = value.trim()
  if (v.length < 4) return true
  if (/^(.)\1+$/.test(v)) return true
  return PLACEHOLDER.test(v)
}
