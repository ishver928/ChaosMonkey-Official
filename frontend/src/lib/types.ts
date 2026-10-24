export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Category = 'secrets' | 'pii' | 'storage' | 'code'
export type Language = 'javascript' | 'typescript' | 'python' | 'env' | 'json' | 'yaml' | 'toml' | 'ini' | 'sql' | 'shell' | 'text'

export interface SourceFile {
  path: string
  content: string
}

/** A raw detector hit, in absolute character offsets. Never leaves the worker without being masked. */
export interface RawMatch {
  start: number
  end: number
  /** Whether [start, end) holds a sensitive value that must be masked before display or storage. */
  sensitive: boolean
  confidence: number
  /** Optional rule-specific note, e.g. which cookie flags are missing. Must never contain raw values. */
  note?: string
  /** Optional variable/key name the value was assigned to, used for fix templates. */
  name?: string
}

export interface DetectContext {
  path: string
  fileName: string
  language: Language
  content: string
  /** Every file in the scan, for project-level rules (e.g. .gitignore coverage). */
  project: readonly SourceFile[]
}

export interface Rule {
  id: string
  title: string
  category: Category
  severity: Severity
  description: string
  detect: (ctx: DetectContext) => RawMatch[]
  /** Generic rules are dropped when they overlap a hit from a more specific rule. */
  generic?: boolean
  /** CWE id from rules/catalog.json. */
  cwe?: string
  /** Drop this rule's hit when one of these rules fires on the same line. */
  supersededBy?: string[]
}

export type RuleMeta = Omit<Rule, 'detect'>

export interface Finding {
  id: string
  fingerprint: string
  ruleId: string
  category: Category
  severity: Severity
  file: string
  language: Language
  line: number
  column: number
  endLine: number
  endColumn: number
  /** Absolute offsets into the in-memory file, so the viewer can mask/reveal. Meaningless without the file. */
  start: number
  end: number
  sensitive: boolean
  maskedValue: string
  /** The finding's line with every sensitive range on it masked. */
  snippet: string
  confidence: number
  note?: string
  name?: string
  /** CWE id of the rule (from rules/catalog.json). */
  cwe?: string
}

export interface FileSummary {
  path: string
  language: Language
  lines: number
  bytes: number
}

export interface SkippedFile {
  path: string
  reason: 'too-large' | 'unsupported' | 'binary' | 'ignored-dir' | 'test-or-generated'
}

export interface ScanReport {
  id: string
  name: string
  createdAt: number
  durationMs: number
  files: FileSummary[]
  skipped: SkippedFile[]
  findings: Finding[]
  rulesRun: number
  /** Present when the report came from the bundled demo, so its sources can be re-hydrated. */
  seedId?: string
}

export type Dismissal = { reason: 'false-positive' | 'accepted-risk'; at: number }
