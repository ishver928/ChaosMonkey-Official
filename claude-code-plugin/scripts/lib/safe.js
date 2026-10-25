'use strict'
/**
 * Everything an MCP tool returns enters Claude's context, so tool output is built ONLY from an
 * allowlist of metadata fields (counts, severities, static rule titles, file:line), each checked
 * against a strict shape. Anything unexpected is dropped, then a last-resort redaction pass
 * (mirroring backend/app/detectors/masking.py scrub) runs over the final text.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const MODES = {
  full: 'full (local Ollama model + CWE knowledge base + detectors)',
  mock: 'mock (recorded local-model responses + CWE knowledge base + detectors; no live LLM)',
  'detector-only': 'detector-only (Ollama not available; deterministic detectors + CWE knowledge base)',
}

const LAST_RESORT = [
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{50,}/g,
  /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}/g,
  /sk-ant-[A-Za-z0-9_-]{20,}/g,
  /\bsk-(?:ant-|proj-|svcacct-|fake-)?[A-Za-z0-9_-]{16,}/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g,
  /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g,
]

function redact(text) {
  let out = String(text)
  for (const rx of LAST_RESORT) out = out.replace(rx, '[redacted]')
  return out
}

const str = (v, max = 160) => (typeof v === 'string' ? v.slice(0, max) : '')
const int = (v) => (Number.isFinite(v) ? Math.trunc(v) : 0)

function safeTitle(v) {
  // Static rule titles / CWE names only: letters, digits, punctuation commonly used in titles.
  return str(v, 120).replace(/[^\w\s.,:;()/'&+-]/g, '').trim() || 'Security finding'
}

function safeLocation(v) {
  const s = str(v, 260)
  return /^[\w./\-@+ ()[\]]+:\d+$/.test(s) ? s : 'unknown location'
}

function pickFinding(f) {
  if (!f || typeof f !== 'object') return null
  return {
    id: /^[0-9a-f]{6,64}$/.test(f.id) ? f.id : '',
    rule_id: /^CM-[A-Z]\d{3}$/.test(f.rule_id) ? f.rule_id : '',
    cwe_id: /^CWE-\d{1,5}$/.test(f.cwe_id) ? f.cwe_id : '',
    title: safeTitle(f.title),
    severity: SEVERITIES.includes(f.severity) ? f.severity : 'info',
    location: safeLocation(f.location),
    fix_available: f.fix_available === true,
    fix_verified: f.fix_verified === true,
  }
}

function pickSummary(s) {
  if (!s || typeof s !== 'object') return null
  const counts = {}
  for (const sev of SEVERITIES) counts[sev] = int(s.counts_by_severity && s.counts_by_severity[sev])
  return {
    security_score: int(s.security_score),
    counts_by_severity: counts,
    total_findings: int(s.total_findings),
    files_scanned: int(s.files_scanned),
    files_skipped: int(s.files_skipped),
    llm_mock: s.llm_mock === true,
    data_leaves_machine: s.data_leaves_machine === true,
    findings: Array.isArray(s.findings) ? s.findings.map(pickFinding).filter(Boolean) : [],
  }
}

function modeLabel(mode) {
  return MODES[mode] || 'unknown'
}

function countsLine(counts) {
  const parts = SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`)
  return parts.length ? parts.join(', ') : 'none'
}

module.exports = { SEVERITIES, redact, pickFinding, pickSummary, modeLabel, countsLine, safeLocation, safeTitle }
