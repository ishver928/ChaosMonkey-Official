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

const TEMPLATE = /x{4,}|your[_\- ]?|changeme|change[_\- ]me|replace[_\- ]?me|placeholder|dummy|redacted|insert[_\- ]|<[^>]*>|\$\{|\{\{|\.\.\./i

/**
 * Obvious template values (YOUR_KEY, xxxx, <token>, ${X}, changeme) inside a known key format.
 * Unlike isPlaceholder, "example" is not treated as a placeholder: vendors publish structurally
 * valid example keys (AWS AKIAIOSFODNN7EXAMPLE) that the bundled demo intentionally uses.
 */
export function isTemplatePlaceholder(value: string): boolean {
  const body = value.replace(/^[A-Za-z]+[_-](?:live_|proj-|svcacct-|ant-)?/, '')
  if (new Set(body.toLowerCase()).size <= 2) return true
  return TEMPLATE.test(value)
}

/** A value that is itself an environment-variable name, e.g. "GITHUB_TOKEN". */
export const isEnvVarName = (value: string) => /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)

/** snake/kebab-case lowercase words such as "token_expired" or "password-input". */
export const isWordIdentifier = (value: string) => /^[a-z]+(?:[_\-.][a-z]+)+$/.test(value)
