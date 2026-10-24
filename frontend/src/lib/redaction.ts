/** Masking helpers. Raw values pass through here and only masked strings come out. */

export const BULLETS = '••••••••'

const KNOWN_PREFIX = /^(sk_live_|rk_live_|sk-ant-(?:api|admin)\d\d-|sk-ant-|sk-proj-|sk-svcacct-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[a-z]-|AKIA|ASIA|ABIA|ACCA|AIza|eyJ)/

function maskEmail(v: string): string {
  const [local = '', domain = ''] = v.split('@')
  const parts = domain.split('.')
  const tld = parts.length > 1 ? parts.pop() : ''
  const host = parts.join('.')
  return `${local.slice(0, 1)}•••@${host.slice(0, 1)}•••${tld ? `.${tld}` : ''}`
}

function maskPem(v: string): string {
  const all = v.split('\n')
  const head = all[0] ?? ''
  const foot = all[all.length - 1] ?? ''
  const body = all.slice(1, -1).map(() => '••••••••••••••••••••••••••••••••')
  return [head, ...body, foot].join('\n')
}

/** Mask a raw sensitive value for display. Multi-line values keep their line count so code stays aligned. */
export function maskValue(raw: string, ruleId: string, name?: string): string {
  const v = raw
  switch (ruleId) {
    case 'CM-S009': return maskPem(v)
    case 'CM-P001': return maskEmail(v)
    case 'CM-P003': return `•••-••-${v.slice(-4)}`
    case 'CM-P004': return `•••• •••• •••• ${v.replace(/\D/g, '').slice(-4)}`
    case 'CM-P002': return `(•••) •••-••${v.replace(/\D/g, '').slice(-2)}`
    case 'CM-P005': return '••••-••-••'
    default: break
  }
  if (name && /(passw|pwd|passphrase)/i.test(name)) return BULLETS
  if (v.includes('\n')) return v.split('\n').map((l) => '•'.repeat(Math.min(32, l.length))).join('\n')
  const prefix = KNOWN_PREFIX.exec(v)?.[0] ?? ''
  if (prefix) return `${prefix}${BULLETS}${v.slice(-4)}`
  if (v.length <= 16) return `${v.slice(0, 1)}${BULLETS}`
  return `${v.slice(0, 2)}${BULLETS}${v.slice(-2)}`
}

export interface MaskRange { start: number; end: number; mask: string }

/**
 * Replace absolute ranges in `text` with their masks. Masks keep the same number of newlines as the
 * value they replace, so line numbers in the masked text match the original.
 */
export function applyMasks(text: string, ranges: MaskRange[]): string {
  const sorted = [...ranges].sort((a, b) => a.start - b.start)
  let out = ''
  let cursor = 0
  for (const r of sorted) {
    if (r.start < cursor) continue
    out += text.slice(cursor, r.start) + r.mask
    cursor = r.end
  }
  return out + text.slice(cursor)
}

/** Defense in depth: blanks anything that still looks like a live credential before it hits storage or an export. */
const LAST_RESORT = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{50,}/g,
  /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}/g,
  /sk-ant-[A-Za-z0-9_\-]{20,}/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}/g,
  /\bAIza[0-9A-Za-z_\-]{35}/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{16}[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
]

export function scrub(text: string): string {
  return LAST_RESORT.reduce((acc, re) => acc.replace(re, '[redacted]'), text)
}

export function containsUnmaskedSecret(text: string): boolean {
  return LAST_RESORT.some((re) => { re.lastIndex = 0; return re.test(text) })
}
