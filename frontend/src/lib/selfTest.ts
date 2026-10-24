import { SEED_FILES } from '@/data/seedProject'
import { scanProject } from './scanner'
import { containsUnmaskedSecret } from './redaction'
import { CATEGORIES } from './severity'
import type { Finding } from './types'

export interface SelfTestCase { name: string; pass: boolean; detail: string }

/** Findings the seed project must produce: [ruleId, file suffix, line]. */
const EXPECTED: [string, string, number][] = [
  ['CM-S013', '/.env', 2],
  ['CM-D008', '/.env', 1],
  ['CM-S004', 'server/billing.js', 4],
  ['CM-S004', '/.env', 5],
  ['CM-S011', 'server/db.js', 4],
  ['CM-S001', 'scripts/backup_to_s3.py', 7],
  ['CM-S002', 'scripts/backup_to_s3.py', 8],
  ['CM-S003', 'scripts/deploy.sh', 5],
  ['CM-S006', 'scripts/assistant.py', 3],
  ['CM-S007', 'src/config.ts', 4],
  ['CM-S008', 'scripts/deploy.sh', 6],
  ['CM-S009', 'server/sso.js', 3],
  ['CM-S010', 'src/components/AdminPanel.tsx', 4],
  ['CM-D002', 'server/auth.js', 10],
  ['CM-D004', 'server/auth.js', 6],
  ['CM-D004', 'server/index.js', 12],
  ['CM-D001', 'src/api.ts', 8],
  ['CM-D005', 'server/auth.js', 27],
  ['CM-D007', 'server/db.js', 5],
  ['CM-D007', 'scripts/backup_to_s3.py', 25],
  ['CM-P006', 'server/logger.js', 13],
  ['CM-P006', 'scripts/backup_to_s3.py', 21],
  ['CM-P003', 'seed/users.json', 7],
  ['CM-P004', 'seed/users.json', 17],
  ['CM-P005', 'seed/users.json', 8],
  ['CM-P007', 'src/api.ts', 4],
]

/** Raw values that must never show up in any finding's snippet or masked value. */
const RAW_CANARIES = [
  ['sk', 'live', '51DemoOnlyNotARealStripeKey00a91f'].join('_'),
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'Gr33nBanana-prod-2026',
  'todo-app-super-secret-2026',
  '219-09-9999',
  '4111 1111 1111 1111',
  'maya.okafor@example.com',
  'xoxb-not-a-real-token-this-will-not-work',
]

export function runSelfTest(findings: Finding[] = scanProject(SEED_FILES)): SelfTestCase[] {
  const cases: SelfTestCase[] = EXPECTED.map(([ruleId, suffix, line]) => {
    const hit = findings.some((f) => f.ruleId === ruleId && f.file.endsWith(suffix) && f.line === line)
    return { name: `${ruleId} fires in ${suffix.replace(/^\//, '')}:${line}`, pass: hit, detail: hit ? 'found' : 'missing' }
  })
  for (const c of CATEGORIES) {
    const n = findings.filter((f) => f.category === c).length
    cases.push({ name: `category "${c}" has findings`, pass: n > 0, detail: `${n} findings` })
  }
  const templateHits = findings.filter((f) => f.file.endsWith('.env.example')).length
  cases.push({ name: '.env.example placeholders are ignored', pass: templateHits === 0, detail: `${templateHits} findings` })
  const serialized = JSON.stringify(findings.map(({ snippet, maskedValue, note }) => ({ snippet, maskedValue, note })))
  const leaked = RAW_CANARIES.filter((c) => serialized.includes(c))
  cases.push({ name: 'no raw secret or PII in snippets', pass: leaked.length === 0 && !containsUnmaskedSecret(serialized), detail: leaked.length ? `${leaked.length} leaked` : 'all masked' })
  return cases
}
