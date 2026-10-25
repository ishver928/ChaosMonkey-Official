import type { DetectContext, RawMatch } from './types'

/*
 * Browser ports of the backend's code rules (backend/app/detectors/python_ast.py, js_rules.py,
 * code_rules.py). Python rules run on a line model with indentation-based function scopes,
 * which mirrors the backend's AST + per-function taint tracking for ordinary code. Metadata
 * (title, severity, CWE) comes from rules/catalog.json via rules.ts. The parity test runs both
 * engines over eval/corpus, so keep the regexes here and in the backend in sync.
 */

export type Detector = { id: string; detect: (ctx: DetectContext) => RawMatch[] }

const hit = (start: number, end: number, confidence: number, note?: string): RawMatch => ({ start, end, sensitive: false, confidence, note })

interface Line { text: string; start: number; index: number }
function lineList(content: string): Line[] {
  const out: Line[] = []
  let start = 0
  content.split('\n').forEach((text, index) => {
    out.push({ text, start, index })
    start += text.length + 1
  })
  return out
}
const lineOf = (content: string, pos: number) => content.slice(0, pos).split('\n').length - 1

/** Offset just past the `)` matching content[open] (string-aware, bounded). Mirrors call_end(). */
export function callEnd(content: string, open: number, limit = 600): number {
  let depth = 0
  let quote = ''
  const stop = Math.min(content.length, open + limit)
  for (let i = open; i < stop; i++) {
    const ch = content[i]!
    if (quote) {
      if (ch === '\\') { i++; continue }
      if (ch === quote) quote = ''
    } else if (ch === '"' || ch === "'" || ch === '`') quote = ch
    else if (ch === '(') depth++
    else if (ch === ')') {
      depth--
      if (depth === 0) return i + 1
    }
  }
  return stop
}

/** Split on a separator at bracket depth 0, outside string literals. */
function splitTop(expr: string, sep: string): string[] {
  const out: string[] = []
  let depth = 0
  let quote = ''
  let cur = ''
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!
    if (quote) {
      cur += ch
      if (ch === '\\') { cur += expr[i + 1] ?? ''; i++; continue }
      if (ch === quote) quote = ''
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue }
    if ('([{'.includes(ch)) depth++
    if (')]}'.includes(ch)) depth--
    if (depth === 0 && sep.includes(ch)) { out.push(cur); cur = ''; continue }
    cur += ch
  }
  out.push(cur)
  return out
}

/** Arguments of the call whose `(` is at `open`. */
function callArgs(content: string, open: number): string[] {
  const end = callEnd(content, open)
  return splitTop(content.slice(open + 1, end - 1), ',').map((a) => a.trim()).filter((a) => a.length > 0)
}

const UPPER = /^\s*[A-Z][A-Z0-9_]*\s*$/
const isUpper = (e: string) => UPPER.test(e) && e.trim().length > 1
const PY_STR = /^[rRbBuU]{0,2}(["'])(?:\\.|(?!\1).)*\1$/
const PY_FSTR = /^[rRbB]?[fF][rRbB]?(["'])((?:\\.|(?!\1).)*)\1$/
const NUM = /^-?\d+(\.\d+)?$/

function fstringParts(expr: string): string[] | null {
  const m = PY_FSTR.exec(expr.trim())
  if (!m) return null
  return [...m[2]!.replace(/\{\{|\}\}/g, '').matchAll(/\{([^{}]*)\}/g)].map((x) => x[1]!.split(/[!:]/)[0]!)
}

/** String-literal text in a Python expression, f-string literal parts included. */
function pyStrConsts(expr: string): string {
  const out: string[] = []
  for (const m of expr.matchAll(/(?:[rRbBuU]{0,2}|[rRbB]?[fF][rRbB]?)(["'])((?:\\.|(?!\1).)*)\1/g)) {
    out.push(m[0].match(/^[rRbB]?[fF]/) ? m[2]!.replace(/\{[^{}]*\}/g, ' ') : m[2]!)
  }
  return out.join(' ')
}

/** Code parts of a Python/JS expression: string contents removed, f-string/${} interpolations kept. */
function codeOnly(expr: string): string {
  const interp: string[] = []
  expr.replace(/\$\{([^}]*)\}/g, (_m, inner: string) => { interp.push(inner); return '' })
  expr.replace(/\b[rRbB]?[fF][rRbB]?(["'])((?:\\.|(?!\1).)*)\1/g, (_m, _q: string, body: string) => {
    body.replace(/\{([^{}]*)\}/g, (_x, inner: string) => { interp.push(inner); return '' })
    return ''
  })
  return `${expr.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, ' ')} ${interp.join(' ')}`
}

/** Mirror of python_ast._is_dynamic_str. */
function isDynamicPyStr(raw: string): boolean {
  const expr = raw.trim()
  const fparts = fstringParts(expr)
  if (fparts) return fparts.length > 0 && !fparts.every(isUpper)
  const fmt = /^([rRbBuU]{0,2}(["'])(?:\\.|(?!\2).)*\2)\.format\(([\s\S]*)\)$/.exec(expr)
  if (fmt) {
    const args = splitTop(fmt[3]!, ',').map((a) => a.replace(/^\s*\w+\s*=/, '').trim()).filter(Boolean)
    return args.some((a) => !PY_STR.test(a) && !NUM.test(a) && !isUpper(a))
  }
  const plus = splitTop(expr, '+')
  const mod = plus.length === 1 ? splitTop(expr, '%') : []
  const operands = (plus.length > 1 ? plus : mod).map((o) => o.trim())
  if (operands.length < 2) return false
  const hasStr = operands.some((o) => PY_STR.test(o) || PY_FSTR.test(o))
  let dynamic = operands.filter((o) => !PY_STR.test(o) && !NUM.test(o) && !isUpper(o))
  const last = operands[operands.length - 1]!
  if (mod.length > 1 && /^\(.*\)$/.test(last)) {
    dynamic = splitTop(last.slice(1, -1), ',').map((e) => e.trim()).filter((e) => e && !PY_STR.test(e) && !NUM.test(e) && !isUpper(e))
  }
  return hasStr && dynamic.length > 0
}

// ---------------------------------------------------------------------------
// Python line model: scopes, taint
// ---------------------------------------------------------------------------

const REQUEST_EXPR = /\brequest\.(?:args|form|values|cookies|headers|json|data|files|get_json|query_params|path_params)\b/
const ESCAPE_CALL = /(?<![\w.])(?:escape|quote|conditional_escape|int|float|len|bool|secure_filename)\s*\(|\b(?:html|markupsafe)\.escape\s*\(|\bbleach\.clean\s*\(/g
const PATH_STOP_CALL = /(?:(?<![\w.])|\.)(?:basename|secure_filename)\s*\(/g
const HTML_TAG = /<\s*[a-zA-Z/!]/
const SQL_WORDS = /\b(select|insert|update|delete|replace|create|drop|alter|where|from)\b/i

/** Remove calls matched by `re` (through their closing paren). */
function stripCalls(expr: string, re: RegExp): string {
  let out = expr
  for (let guard = 0; guard < 20; guard++) {
    re.lastIndex = 0
    const m = re.exec(out)
    if (!m) break
    const open = out.indexOf('(', m.index + m[0].length - 1)
    out = `${out.slice(0, m.index)} _ ${out.slice(callEnd(out, open))}`
  }
  return out
}

function usesName(code: string, names: Set<string>): boolean {
  for (const n of names) if (new RegExp(`(?<![\\w.])${n}(?![\\w])`).test(code)) return true
  return false
}

function taintedExpr(expr: string, tainted: Set<string>, stop: RegExp): boolean {
  const code = codeOnly(stripCalls(expr, stop))
  return REQUEST_EXPR.test(code) || usesName(code, tainted)
}
const unescapedTaint = (expr: string, tainted: Set<string>) => taintedExpr(expr, tainted, ESCAPE_CALL)

interface PyModel {
  lines: Line[]
  scopeOf: number[]
  tainted: Map<number, Set<string>>
  html: Map<number, Set<string>>
  sqlAssigns: Map<string, { line: number; dyn: boolean }[]>
  guarded: Map<number, Set<string>>
}

const indentOf = (s: string) => s.length - s.trimStart().length

/** Strip a trailing `# comment` that is outside string literals. */
function stripPyComment(text: string): string {
  let quote = ''
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (quote) {
      if (ch === '\\') { i++; continue }
      if (ch === quote) quote = ''
    } else if (ch === '"' || ch === "'") quote = ch
    else if (ch === '#') return text.slice(0, i)
  }
  return text
}

function pyModel(content: string): PyModel {
  const lines = lineList(content)
  const scopeOf: number[] = []
  const stack: { line: number; indent: number }[] = []
  for (const l of lines) {
    if (l.text.trim() && !l.text.trim().startsWith('#')) {
      const ind = indentOf(l.text)
      while (stack.length && ind <= stack[stack.length - 1]!.indent) stack.pop()
    }
    scopeOf.push(stack.length ? stack[stack.length - 1]!.line : -1)
    const def = /^(\s*)(?:async\s+)?def\s+\w+/.exec(l.text)
    if (def) stack.push({ line: l.index, indent: def[1]!.length })
  }
  // Taint flows through assignments in source order; sinks use each scope's final sets (as the AST engine does).
  const taintNow = new Map<number, Set<string>>()
  const htmlNow = new Map<number, Set<string>>()
  const sqlAssigns = new Map<string, { line: number; dyn: boolean }[]>()
  const guarded = new Map<number, Set<string>>()
  for (const l of lines) {
    const scope = scopeOf[l.index]!
    const t = taintNow.get(scope) ?? new Set<string>()
    const h = htmlNow.get(scope) ?? new Set<string>()
    const code = stripPyComment(l.text)
    const a = /^\s*([A-Za-z_]\w*)\s*(\+?=)(?!=)\s*(.+)$/.exec(code)
    if (a && !/^\s*(?:if|elif|while|return|assert|with|for)\b/.test(code)) {
      const [, name, op, value] = a as unknown as [string, string, string, string]
      const isT = unescapedTaint(value, t)
      const buildsHtml = HTML_TAG.test(pyStrConsts(value)) && isT
      if (isT) t.add(name)
      if (buildsHtml || (op === '+=' && h.has(name))) h.add(name)
      const key = `${scope}:${name}`
      const list = sqlAssigns.get(key) ?? []
      if (op === '=') list.push({ line: l.index, dyn: isDynamicPyStr(value) && SQL_WORDS.test(pyStrConsts(value)) })
      else if (list.length && !PY_STR.test(value.trim()) && !NUM.test(value.trim())) list.push({ line: l.index, dyn: list.some((x) => x.dyn) })
      sqlAssigns.set(key, list)
    }
    for (const g of code.matchAll(/\b([A-Za-z_]\w*)\.(?:startswith|is_relative_to|relative_to)\s*\(/g)) {
      const set = guarded.get(scope) ?? new Set<string>()
      set.add(g[1]!)
      guarded.set(scope, set)
    }
    for (const g of code.matchAll(/\bcommonpath\s*\(([^\n]*)/g)) {
      const set = guarded.get(scope) ?? new Set<string>()
      for (const n of codeOnly(g[1]!).matchAll(/[A-Za-z_]\w*/g)) set.add(n[0])
      guarded.set(scope, set)
    }
    taintNow.set(scope, t)
    htmlNow.set(scope, h)
  }
  return { lines, scopeOf, tainted: taintNow, html: htmlNow, sqlAssigns, guarded }
}

function builtSql(model: PyModel, scope: number, name: string, line: number): boolean {
  const prior = (model.sqlAssigns.get(`${scope}:${name}`) ?? []).filter((x) => x.line <= line)
  return prior.length > 0 && prior[prior.length - 1]!.dyn
}

function buildsTaintedHtml(expr: string, tainted: Set<string>): boolean {
  const e = expr.trim()
  const isStrExpr = PY_FSTR.test(e) || splitTop(e, '+').length > 1 || splitTop(e, '%').length > 1 || /\.format\(/.test(e)
  if (!isStrExpr || (/^[\w.]+\(/.test(e) && !/^([rRbBuU]{0,2}(["'])(?:\\.|(?!\2).)*\2)\.format\(/.test(e))) return false
  return HTML_TAG.test(pyStrConsts(e)) && unescapedTaint(e, tainted)
}

/** Each call on Python code lines: [name, offset of name, offset of '('] (comments ignored). */
function* pyCalls(model: PyModel, re: RegExp): Generator<{ l: Line; m: RegExpExecArray; open: number; scope: number }> {
  for (const l of model.lines) {
    const code = stripPyComment(l.text)
    re.lastIndex = 0
    for (const m of code.matchAll(re) as IterableIterator<RegExpExecArray>) {
      const open = l.start + (m.index ?? 0) + m[0].length - 1
      yield { l, m, open, scope: model.scopeOf[l.index]! }
    }
  }
}

const PY_SQL_SINK = /(?<![\w])(execute|executemany|executescript|read_sql|read_sql_query|raw)\s*\(/g

function pythonRules(ctx: DetectContext): { id: string; m: RawMatch }[] {
  if (ctx.language !== 'python') return []
  const c = ctx.content
  const model = pyModel(c)
  const out: { id: string; m: RawMatch }[] = []
  const add = (id: string, start: number, end: number, conf: number, note?: string) => out.push({ id, m: hit(start, end, conf, note) })
  const tAt = (_line: number, scope: number) => model.tainted.get(scope) ?? new Set<string>()
  const hAt = (_line: number, scope: number) => model.html.get(scope) ?? new Set<string>()

  // CM-A001 SQL injection
  for (const { l, m, open, scope } of pyCalls(model, PY_SQL_SINK)) {
    const args = callArgs(c, open)
    const a0 = args[0]
    if (!a0) continue
    const sink = m[1]!
    if (isDynamicPyStr(a0) && (sink.startsWith('execute') || SQL_WORDS.test(pyStrConsts(a0)))) add('CM-A001', l.start + (m.index ?? 0), callEnd(c, open), 0.9, 'dynamic SQL string in query call')
    else if (/^[A-Za-z_]\w*$/.test(a0) && builtSql(model, scope, a0, l.index)) add('CM-A001', l.start + (m.index ?? 0), callEnd(c, open), 0.85, `query string \`${a0}\` built dynamically`)
  }
  for (const { l, m, open } of pyCalls(model, /(?<![\w.])text\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (a0 && isDynamicPyStr(a0) && SQL_WORDS.test(pyStrConsts(a0))) add('CM-A001', l.start + (m.index ?? 0), callEnd(c, open), 0.85, 'dynamic SQL passed to text()')
  }

  // CM-A002 shell injection
  for (const { l, m, open } of pyCalls(model, /\bos\.(?:system|popen)\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (!a0 || PY_STR.test(a0)) continue
    const dyn = isDynamicPyStr(a0)
    if (dyn || !isUpper(a0)) add('CM-A002', l.start + (m.index ?? 0), callEnd(c, open), dyn ? 0.9 : 0.75, dyn ? 'os.system with built command' : 'os.system with variable command')
  }
  for (const { l, m, open } of pyCalls(model, /(?:\bsubprocess\.\w+|(?<![\w.])(?:Popen|run|call|check_output|check_call))\s*\(/g)) {
    const args = callArgs(c, open)
    const a0 = args[0]
    if (!a0 || !args.some((a) => /^shell\s*=\s*True$/.test(a))) continue
    if (!PY_STR.test(a0) && !isUpper(a0) && !/^\w+\s*=/.test(a0)) add('CM-A002', l.start + (m.index ?? 0), callEnd(c, open), 0.9, 'subprocess with shell=True and a non-constant command')
  }

  // CM-A003 eval/exec
  for (const { l, m, open } of pyCalls(model, /(?<![\w.])(eval|exec)\s*\(/g)) {
    if (/\bdef\s+$/.test(stripPyComment(l.text).slice(0, m.index))) continue
    const a0 = callArgs(c, open)[0]
    if (a0 && !PY_STR.test(a0) && !NUM.test(a0)) add('CM-A003', l.start + (m.index ?? 0), callEnd(c, open), 0.85, `${m[1]}() on non-literal`)
  }

  // CM-A004 unsafe deserialization
  for (const { l, m, open } of pyCalls(model, /(?<![\w.])(?:(?:pickle|cPickle|dill|marshal)\.(?:load|loads)|pickle\.Unpickler|jsonpickle\.decode|yaml\.unsafe_load|shelve\.open)\s*\(/g)) {
    add('CM-A004', l.start + (m.index ?? 0), callEnd(c, open), 0.85, 'deserialization of untrusted data')
  }
  for (const { l, m, open } of pyCalls(model, /(?<![\w.])yaml\.load(?:_all)?\s*\(/g)) {
    const args = callArgs(c, open)
    const loader = args.find((a) => /^Loader\s*=/.test(a)) ?? (args[1] && !/^\w+\s*=/.test(args[1]) ? args[1] : '')
    if (!/Safe/.test(loader)) add('CM-A004', l.start + (m.index ?? 0), callEnd(c, open), 0.85, 'yaml.load without SafeLoader')
  }

  // CM-A005 Flask debug=True
  for (const { l, m, open } of pyCalls(model, /(?:\.|(?<![\w.]))run\s*\(/g)) {
    if (callArgs(c, open).some((a) => /^debug\s*=\s*True$/.test(a))) {
      const start = l.start + (m.index ?? 0)
      const before = c.slice(l.start, start)
      const recv = /([\w.()]+)$/.exec(before)?.[1] ?? ''
      add('CM-A005', start - recv.length, callEnd(c, open), 0.85, 'debug=True')
    }
  }

  // CM-A006 requests verify=False
  for (const { l, m, open } of pyCalls(model, /(?:\b(?:requests|httpx)\.[\w.]+|(?<![\w.])(?:get|post|put|delete|patch|request))\s*\(/g)) {
    if (callArgs(c, open).some((a) => /^verify\s*=\s*False$/.test(a))) add('CM-A006', l.start + (m.index ?? 0), callEnd(c, open), 0.85, 'verify=False')
  }

  // CM-A007 path traversal
  for (const { l, m, open, scope } of pyCalls(model, /(?:(?<![\w.])(?:open|send_file)|\bio\.open)\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (!a0 || PY_STR.test(a0)) continue
    const guarded = /^[A-Za-z_]\w*$/.test(a0) && (model.guarded.get(scope)?.has(a0) ?? false)
    if (!guarded && taintedExpr(a0, tAt(l.index, scope), PATH_STOP_CALL)) add('CM-A007', l.start + (m.index ?? 0), callEnd(c, open), 0.75, 'open() on user-controlled path')
  }

  // CM-A008 reflected XSS
  for (const l of model.lines) {
    const scope = model.scopeOf[l.index]!
    const code = stripPyComment(l.text)
    const r = /^(\s*)return\s+(.+?)\s*$/.exec(code)
    if (!r) continue
    const v = splitTop(r[2]!, ',')[0]!.trim()
    if (buildsTaintedHtml(v, tAt(l.index, scope)) || (/^[A-Za-z_]\w*$/.test(v) && hAt(l.index, scope).has(v))) {
      const start = l.start + code.indexOf(v, r[1]!.length + 6)
      add('CM-A008', start, start + v.length, 0.8, 'request data returned in HTML unescaped')
    }
  }
  for (const { l, m, open, scope } of pyCalls(model, /(?<![\w])render_template_string\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (a0 && (isDynamicPyStr(a0) || unescapedTaint(a0, tAt(l.index, scope)))) add('CM-A008', l.start + (m.index ?? 0), callEnd(c, open), 0.85, 'render_template_string with request data')
  }
  for (const { l, m, open, scope } of pyCalls(model, /(?<![\w])(Markup|mark_safe)\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (a0 && unescapedTaint(a0, tAt(l.index, scope))) add('CM-A008', l.start + (m.index ?? 0), callEnd(c, open), 0.8, `${m[1]}() on request data`)
  }
  for (const { l, m, open, scope } of pyCalls(model, /(?<![\w])(Response|make_response|HTMLResponse)\s*\(/g)) {
    const a0 = callArgs(c, open)[0]
    if (a0 && (buildsTaintedHtml(a0, tAt(l.index, scope)) || (/^[A-Za-z_]\w*$/.test(a0) && hAt(l.index, scope).has(a0)))) add('CM-A008', l.start + (m.index ?? 0), callEnd(c, open), 0.8, `${m[1]}() with HTML built from request data`)
  }
  return out
}

// ---------------------------------------------------------------------------
// JS/TS rules (mirror js_rules.py)
// ---------------------------------------------------------------------------

const SANITIZED = /DOMPurify\.sanitize|\bsanitize\w*\(|\bescape\w*\(|\bencode\w*\(|\bxss\(|\bpurify\(|\bhe\.encode\(/i
const SQL_STMT = /\b(?:select\b[\s\S]*?\bfrom|insert\s+into|update\s+[\w.`"[\]]+\s+set|delete\s+from|replace\s+into)\b/i
const SQL_SINK = String.raw`(?:query|execute|raw|run|all|prepare|queryRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)`
const REQ_SOURCE = /\breq(?:uest)?\.(?:query|params|body|cookies|headers)\b/
const UPPER_ONLY = /^\s*[A-Z][A-Z0-9_]*\s*$/

const interpolations = (t: string) => [...t.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]!)
const allUpper = (parts: string[]) => parts.length > 0 && parts.every((p) => UPPER_ONLY.test(p))

export function unsafeHtmlValue(value: string): boolean {
  const v = value.trim().replace(/;$/, '').trim()
  if (!v || SANITIZED.test(v)) return false
  if (/^(["'])(?:\\.|(?!\1).)*\1$/.test(v)) return false
  if (/^`[^`]*`$/.test(v) && !v.includes('${')) return false
  if (/^(?:-?\d+(\.\d+)?|null|undefined|true|false)$/.test(v)) return false
  return true
}

function j001(c: string): RawMatch[] {
  const out: RawMatch[] = []
  const sinks: [RegExp, string][] = [
    [/\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*([^;\n]+)/g, 'innerHTML'],
    [/\.insertAdjacentHTML\s*\(\s*[^,\n]+,([^\n]*)\)/g, 'insertAdjacentHTML'],
    [/\bdocument\.write(?:ln)?\s*\(([^\n]*)\)/g, 'document.write'],
    [/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}\n]+)\}\}/g, 'dangerouslySetInnerHTML'],
    [/\$\([^)\n]*\)\.html\(\s*([^)\n]+)\)/g, 'jQuery .html()'],
  ]
  for (const [re, label] of sinks) {
    for (const m of c.matchAll(re)) if (unsafeHtmlValue(m[1]!)) out.push(hit(m.index!, m.index! + m[0].length, 0.8, label))
  }
  return out
}

function j002(c: string): RawMatch[] {
  if (!/child_process/.test(c)) return []
  const out: RawMatch[] = []
  const re = /(?<![\w.$])(?:(?:child_process|cp|childProcess)\.)?(?:exec|execSync)\s*\(\s*(`[^`]*\$\{[^`]*`|["'][^"'\n]*["']\s*\+|[A-Za-z_$][\w$.]*\s*\+)/g
  for (const m of c.matchAll(re)) {
    const arg = m[1]!
    if (arg.startsWith('`') && allUpper(interpolations(arg))) continue
    out.push(hit(m.index!, m.index! + m[0].length, 0.85, 'shell command built from variables'))
  }
  for (const m of c.matchAll(/\bspawn(?:Sync)?\s*\(\s*(`[^`]*\$\{[^`]*`|["'][^"'\n]*["']\s*\+)[^\n]*\bshell\s*:\s*true/g)) {
    out.push(hit(m.index!, m.index! + m[0].length, 0.85, 'spawn with shell: true'))
  }
  return out
}

function j003(c: string): RawMatch[] {
  const out: RawMatch[] = []
  for (const m of c.matchAll(new RegExp(String.raw`\b${SQL_SINK}\s*\(\s*(\`[^\`]*\`)`, 'g'))) {
    const t = m[1]!
    const parts = interpolations(t)
    if (parts.length && SQL_STMT.test(t) && !allUpper(parts)) out.push(hit(m.index!, m.index! + m[0].length, 0.85, 'interpolated SQL'))
  }
  for (const m of c.matchAll(new RegExp(String.raw`\b${SQL_SINK}\s*\(\s*(["'])((?:(?!\1)[^\n])*)\1\s*\+\s*([A-Za-z_$][\w$.\[\]'"]*)`, 'g'))) {
    if (SQL_STMT.test(m[2]!) && !UPPER_ONLY.test(m[3]!)) out.push(hit(m.index!, m.index! + m[0].length, 0.85, 'concatenated SQL'))
  }
  const built = new Map<string, number>()
  for (const m of c.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(`[^`]*`|(["'])[^\n]*?\3\s*\+[^\n;]*)/g)) {
    const val = m[2]!
    if (!SQL_STMT.test(val)) continue
    if (val.startsWith('`')) {
      const parts = interpolations(val)
      if (!parts.length || allUpper(parts)) continue
    } else {
      const operands = val.replace(/(["'])(?:\\.|(?!\1).)*\1/g, "''").split('+').map((o) => o.trim())
      if (operands.every((o) => o === "''" || o === '' || UPPER_ONLY.test(o))) continue
    }
    built.set(m[1]!, m.index!)
  }
  for (const [name, pos] of built) {
    const esc = name.replace(/[$]/g, '\\$')
    for (const m of c.matchAll(new RegExp(String.raw`\b${SQL_SINK}\s*\(\s*${esc}\s*[,)]`, 'g'))) {
      if (m.index! > pos) out.push(hit(m.index!, m.index! + m[0].length, 0.8, `query text \`${name}\` built dynamically`))
    }
  }
  return out
}

const ANY_ORIGIN_JS = /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|\borigin\s*:\s*(?:["']\*["']|true\b)|\bcors\(\s*\)/gi
const ANY_ORIGIN_PY = /allow_origins\s*=\s*\[\s*["']\*["']\s*\]|\borigins\s*=\s*["']\*["']|["']origins["']\s*:\s*["']\*["']|\bCORS\(\s*\w+\s*(?:\)|,(?![^)\n]*\borigins\s*=))|Access-Control-Allow-Origin["']?\s*[\],:]\s*=?\s*["']\*["']/g
const CREDS_JS = /credentials\s*:\s*true|Access-Control-Allow-Credentials["']?\s*[:,]\s*["']?true/i
const CREDS_PY = /allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|Access-Control-Allow-Credentials["']?\s*[\],:]\s*=?\s*["']true/i

const anyOrigin = (c: string, language: string) => [...c.matchAll(language === 'python' ? ANY_ORIGIN_PY : ANY_ORIGIN_JS)]
const hasCreds = (c: string, language: string) => (language === 'python' ? CREDS_PY : CREDS_JS).test(c)

function j004(c: string, language: string): RawMatch[] {
  if (!hasCreds(c, language)) return []
  return anyOrigin(c, language).map((m) => hit(m.index!, m.index! + m[0].length, 0.85, 'any origin with credentials'))
}

function j005(c: string): RawMatch[] {
  const out: RawMatch[] = []
  for (const m of c.matchAll(/jwt\.decode\s*\([^)]*\)/g)) {
    const tail = c.slice(m.index! + m[0].length).split(/[;\n]/, 1)[0] ?? ''
    if (!tail.includes('verify')) out.push(hit(m.index!, m.index! + m[0].length, 0.7, 'jwt.decode without verify'))
  }
  for (const m of c.matchAll(/algorithms?\s*:\s*\[[^\]]*["']none["']/gi)) out.push(hit(m.index!, m.index! + m[0].length, 0.9, 'accepts alg:none'))
  return out
}

function taintedJs(c: string): Set<string> {
  const names = new Set<string>()
  for (const m of c.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g)) if (REQ_SOURCE.test(m[2]!)) names.add(m[1]!)
  for (const m of c.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\.(?:query|params|body|cookies)\b/g)) {
    for (const part of m[1]!.split(',')) {
      const name = (part.split(':').pop() ?? '').split('=')[0]!.trim()
      if (name) names.add(name)
    }
  }
  return names
}

function exprTainted(expr: string, tainted: Set<string>): boolean {
  const e = expr.trim()
  if (/^(?:escapeHtml|escape|encode\w*|sanitize\w*|DOMPurify\.sanitize|he\.encode|validator\.escape|Number|parseInt|parseFloat)\s*\(/.test(e)) return false
  if (REQ_SOURCE.test(e)) return true
  for (const t of tainted) if (new RegExp(`(?<![\\w$.])${t.replace(/[$]/g, '\\$')}(?![\\w$])`).test(e)) return true
  return false
}

function j006(c: string): RawMatch[] {
  const out: RawMatch[] = []
  const tainted = taintedJs(c)
  for (const m of c.matchAll(/\bres\.(?:send|write|end)\s*\(([^\n]*)/g)) {
    const arg = m[1]!
    let flagged = false
    if (arg.trimStart().startsWith('`')) {
      const t = (arg.match(/`/g) ?? []).length >= 2 ? arg.slice(0, arg.lastIndexOf('`') + 1) : arg
      if (HTML_TAG.test(t.replace(/\$\{[^}]*\}/g, ''))) flagged = interpolations(t).some((p) => exprTainted(p, tainted))
    } else if (/^\s*["']/.test(arg) && arg.includes('+')) {
      const strings = [...arg.matchAll(/(["'])((?:(?!\1).)*)\1/g)].map((x) => x[2]).join(' ')
      if (HTML_TAG.test(strings)) {
        const operands = arg.trimEnd().replace(/;$/, '').replace(/\)$/, '').replace(/(["'])(?:\\.|(?!\1).)*\1/g, "''").split('+')
        flagged = operands.some((o) => !["''", ''].includes(o.trim()) && exprTainted(o, tainted))
      }
    } else {
      const first = arg.split(/[,)]/, 1)[0] ?? ''
      flagged = first.trim().length > 0 && exprTainted(first, tainted) && !/^\s*\{/.test(first)
    }
    if (flagged) {
      const end = c.indexOf('\n', m.index!)
      out.push(hit(m.index!, end < 0 ? c.length : end, 0.8, 'request data in HTML response'))
    }
  }
  return out
}

function j007(c: string): RawMatch[] {
  if (!/node-serialize|serialize-to-js|funcster/.test(c)) return []
  return [...c.matchAll(/(?<![\w$])(?:[A-Za-z_$][\w$]*\.)?(?:unserialize|deserialize)\s*\(/g)].map((m) => hit(m.index!, m.index! + m[0].length, 0.9, 'unserialize() evaluates embedded functions'))
}

// ---------------------------------------------------------------------------
// Cross-language rules (mirror code_rules.py)
// ---------------------------------------------------------------------------

const WEAK_CIPHER_PY = /\b(?:DES|DES3|ARC4|ARC2|Blowfish|CAST)\.new\s*\(|\bMODE_ECB\b|\bmodes\.ECB\s*\(|\balgorithms\.(?:TripleDES|ARC4|Blowfish|IDEA|CAST5|SEED)\s*\(/g
const WEAK_CIPHER_JS = /\bcreateCipher\s*\(|\bcreateDecipher\s*\(|\bcreateCipheriv\s*\(\s*["'](?:des[\w-]*|rc4[\w-]*|rc2[\w-]*|bf[\w-]*|blowfish[\w-]*|aes-\d+-ecb)["']|\bCryptoJS\.(?:DES|TripleDES|RC4|RC4Drop|Rabbit)\.(?:encrypt|decrypt)\b|\bCryptoJS\.mode\.ECB\b/gi
const RANDOM_PY = /(?<![\w.])random\.(?:random|randint|randrange|choice|choices|sample|getrandbits|uniform)\s*\(/g
const RANDOM_JS = /\bMath\.random\s*\(\s*\)/g
const SECURITY_WORD = /token|secret|passw|\botp\b|nonce|salt|session_?id|sessionid|api_?key|apikey|csrf|verification|reset_?code|auth_?code|invite_?code/i
const DEBUG_PY = /^[ \t]*DEBUG\s*=\s*True\b|\bFastAPI\([^)\n]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True\b|\.config\[\s*["']DEBUG["']\s*\]\s*=\s*True\b|\.config\.update\([^)\n]*\bDEBUG\s*=\s*True/gm

const SENSITIVE_FIELD = String.raw`(?:ssn|social_?security(?:_?number)?|date_?of_?birth|dob|birth_?date|passport(?:_?(?:number|no))?|tax_?id|national_?id|card_?number|credit_?card(?:_?number)?)`
const PROTECTED = /encrypt|cipher|EncryptedType|hash|fernet|_enc\b|masked|redact/i
const PII_COLUMN_DEF = new RegExp(String.raw`\b(${SENSITIVE_FIELD})\s+(?:VARCHAR|NVARCHAR|TEXT|CHAR|DATE|INTEGER|INT|STRING|BIGINT)\b`, 'gi')
const PII_INSERT = /\b(?:INSERT\s+INTO|REPLACE\s+INTO)\s+[\w.`"[\]]+\s*\(([^)]*)\)/gi
const PII_UPDATE = new RegExp(String.raw`\bUPDATE\s+[\w.\`"[\]]+\s+SET\s+[^\n]*?\b(${SENSITIVE_FIELD})\s*=`, 'gi')
const PII_ORM_PY = new RegExp(String.raw`^[ \t]*(${SENSITIVE_FIELD})\s*(?::\s*[\w[\], |]+)?=\s*(?:\w+\.)?(?:Column|mapped_column|CharField|TextField|DateField|StringField)\s*\(`, 'gim')
const PII_ORM_JS = new RegExp(String.raw`\b(${SENSITIVE_FIELD})\s*:\s*(?:\{\s*type\s*:\s*)?(?:String|Date|DataTypes\.(?:STRING|DATE|DATEONLY|TEXT)|Sequelize\.(?:STRING|DATE|TEXT))\b`, 'gi')
const SENSITIVE_NAME = new RegExp(String.raw`^${SENSITIVE_FIELD}$`, 'i')

function c001(ctx: DetectContext): RawMatch[] {
  const re = ctx.language === 'python' ? WEAK_CIPHER_PY : WEAK_CIPHER_JS
  return [...ctx.content.matchAll(re)].map((m) => hit(m.index!, m.index! + m[0].length, 0.85, 'broken cipher or mode'))
}

function c002(ctx: DetectContext): RawMatch[] {
  const c = ctx.content
  let re = RANDOM_JS
  if (ctx.language === 'python') {
    if (/\brandom\s*=\s*(?:secrets\.)?SystemRandom\(/.test(c)) return []
    re = RANDOM_PY
  }
  const rows = c.split('\n')
  const out: RawMatch[] = []
  for (const m of c.matchAll(re)) {
    const idx = lineOf(c, m.index!)
    const w = SECURITY_WORD.exec(rows.slice(Math.max(0, idx - 2), idx + 1).join('\n'))
    if (w) out.push(hit(m.index!, m.index! + m[0].length, 0.75, `used for \`${w[0]}\``))
  }
  return out
}

function c003(ctx: DetectContext): RawMatch[] {
  if (ctx.language !== 'python') return []
  return [...ctx.content.matchAll(DEBUG_PY)].map((m) => {
    const start = m.index! + (m[0].length - m[0].trimStart().length)
    return hit(start, m.index! + m[0].length, 0.8, 'debug flag hardcoded on')
  })
}

function c004(ctx: DetectContext): RawMatch[] {
  return anyOrigin(ctx.content, ctx.language).map((m) => hit(m.index!, m.index! + m[0].length, 0.75, 'any origin allowed'))
}

function p008(ctx: DetectContext): RawMatch[] {
  const c = ctx.content
  const out: RawMatch[] = []
  const add = (start: number, end: number, field: string) => {
    const ls = c.lastIndexOf('\n', start - 1) + 1
    const le = c.indexOf('\n', start)
    if (PROTECTED.test(c.slice(ls, le < 0 ? c.length : le))) return
    out.push(hit(start, end, 0.75, `\`${field}\` stored unencrypted`))
  }
  for (const m of c.matchAll(PII_COLUMN_DEF)) add(m.index!, m.index! + m[0].length, m[1]!)
  for (const m of c.matchAll(PII_INSERT)) {
    const cols = m[1]!.split(',').map((x) => x.trim().replace(/^[`"[]+|[`"\]]+$/g, ''))
    const hits = cols.filter((col) => SENSITIVE_NAME.test(col))
    if (hits.length) add(m.index!, m.index! + m[0].length, hits[0]!)
  }
  for (const m of c.matchAll(PII_UPDATE)) add(m.index!, m.index! + m[0].length, m[1]!)
  if (ctx.language === 'python') {
    for (const m of c.matchAll(PII_ORM_PY)) {
      const start = m.index! + m[0].indexOf(m[1]!)
      add(start, m.index! + m[0].length, m[1]!)
    }
  } else if (ctx.language === 'javascript' || ctx.language === 'typescript') {
    // Schema type tokens are case-sensitive: `ssn: string` is a TS annotation, not a column.
    for (const m of c.matchAll(PII_ORM_JS)) if (/\b(?:String|Date|DataTypes|Sequelize)\b/.test(m[0])) add(m.index!, m.index! + m[0].length, m[1]!)
  }
  return out
}

const isJs = (ctx: DetectContext) => ctx.language === 'javascript' || ctx.language === 'typescript'
const isCode = (ctx: DetectContext) => isJs(ctx) || ctx.language === 'python'

// The Python rules share one parse of the file per scan; cache by content identity.
let pyCache: { content: string; out: { id: string; m: RawMatch }[] } | null = null
function pyHits(ctx: DetectContext, id: string): RawMatch[] {
  if (ctx.language !== 'python') return []
  if (!pyCache || pyCache.content !== ctx.content) pyCache = { content: ctx.content, out: pythonRules(ctx) }
  return pyCache.out.filter((h) => h.id === id).map((h) => h.m)
}

export const CODE_DETECTORS: Detector[] = [
  { id: 'CM-A001', detect: (ctx) => pyHits(ctx, 'CM-A001') },
  { id: 'CM-J003', detect: (ctx) => (isJs(ctx) ? j003(ctx.content) : []) },
  { id: 'CM-A002', detect: (ctx) => pyHits(ctx, 'CM-A002') },
  { id: 'CM-J002', detect: (ctx) => (isJs(ctx) ? j002(ctx.content) : []) },
  { id: 'CM-A003', detect: (ctx) => pyHits(ctx, 'CM-A003') },
  { id: 'CM-A004', detect: (ctx) => pyHits(ctx, 'CM-A004') },
  { id: 'CM-J007', detect: (ctx) => (isJs(ctx) ? j007(ctx.content) : []) },
  { id: 'CM-A005', detect: (ctx) => pyHits(ctx, 'CM-A005') },
  { id: 'CM-A006', detect: (ctx) => pyHits(ctx, 'CM-A006') },
  { id: 'CM-A007', detect: (ctx) => pyHits(ctx, 'CM-A007') },
  { id: 'CM-A008', detect: (ctx) => pyHits(ctx, 'CM-A008') },
  { id: 'CM-J001', detect: (ctx) => (isJs(ctx) ? j001(ctx.content) : []) },
  { id: 'CM-J006', detect: (ctx) => (isJs(ctx) ? j006(ctx.content) : []) },
  { id: 'CM-J004', detect: (ctx) => (isCode(ctx) ? j004(ctx.content, ctx.language) : []) },
  { id: 'CM-C004', detect: (ctx) => (isCode(ctx) ? c004(ctx) : []) },
  { id: 'CM-J005', detect: (ctx) => (isJs(ctx) ? j005(ctx.content) : []) },
  { id: 'CM-C001', detect: (ctx) => (isCode(ctx) ? c001(ctx) : []) },
  { id: 'CM-C002', detect: (ctx) => (isCode(ctx) ? c002(ctx) : []) },
  { id: 'CM-C003', detect: (ctx) => c003(ctx) },
  { id: 'CM-P008', detect: (ctx) => (isCode(ctx) || ctx.language === 'sql' ? p008(ctx) : []) },
]
