import data from '../../../rules/catalog.json'
import type { Category, Severity } from './types'

/*
 * rules/catalog.json is the single source of truth for rule metadata (title, category,
 * severity, CWE, explanation, remediation steps, fix examples). The backend reads the same
 * file. Detection code lives in rules.ts / codeRules.ts.
 */

export interface CatalogRule {
  id: string
  title: string
  category: Category
  severity: Severity
  cwe: string
  description: string
  generic: boolean
  explanation: string
  steps: string[]
  fix: Record<string, string>
  languages?: string[]
  superseded_by?: string[]
}

export const CATALOG: Record<string, CatalogRule> = Object.fromEntries(
  (data.rules as unknown as CatalogRule[]).map((r) => [r.id, r]),
)

export function catalogRule(id: string): CatalogRule {
  const r = CATALOG[id]
  if (!r) throw new Error(`Rule ${id} is missing from rules/catalog.json`)
  return r
}

/** Catalog fix example for a file language (TS uses the JS example). */
export function fixExample(id: string, language: string): { code: string; language: string } | undefined {
  const fix = CATALOG[id]?.fix ?? {}
  const key = language === 'typescript' ? 'javascript' : language
  if (fix[key]) return { code: fix[key]!, language: key }
  for (const k of ['python', 'javascript', ...Object.keys(fix)]) if (fix[k]) return { code: fix[k]!, language: k }
  return undefined
}
