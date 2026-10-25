import type { Finding } from './types'
import { CATALOG, fixExample } from './catalog'

/*
 * The "Built-in analyst": the explanation and steps for each rule (from rules/catalog.json) plus
 * fix templates that rewrite the finding's (masked) line into a safer version. Deterministic and
 * fully offline. Every template is syntax-checked in context by backend/tests/test_fix_syntax.py.
 */

export interface Fix {
  before: string
  /** What the UI shows: any needed imports, then the replacement code. */
  after: string
  language: string
  note?: string
  /** A reference example to adapt, not a drop-in replacement for the flagged line. */
  standalone?: boolean
  /** Import lines the replacement needs (already shown at the top of `after`). */
  imports?: string[]
  /** Line edits (1-based, inclusive) that apply this fix in place. Defaults to replacing the flagged line with `after`. */
  replace?: { from: number; to: number; text: string }[]
}
export interface Advice { why: string; steps: string[]; fix: Fix }

export const ROTATE_STEP = 'Rotate this credential now. Deleting it from code doesn’t un-leak it: it’s already in git history, CI logs, and any clone or AI context window that saw it.'

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function isPython(f: Finding) { return f.language === 'python' }
function isJs(f: Finding) { return f.language === 'javascript' || f.language === 'typescript' }
function isFrontend(f: Finding) { return /\.(tsx|jsx)$/.test(f.file) || /(^|\/)(src\/components|public|client|web)\//.test(f.file) }
function fileLang(f: Finding): string {
  if (f.language === 'env') return 'dotenv'
  return f.language
}
const indentOf = (line: string) => line.slice(0, line.length - line.trimStart().length)
const isEsm = (content: string) => /^\s*(?:import\s.+from\s|import\s*['"]|export\s)/m.test(content)
const jsImport = (content: string | undefined, name: string, mod: string) => (content && isEsm(content) ? `import ${name} from '${mod}'` : `const ${name} = require('${mod}')`)

/** A fix that replaces lines in place and needs some imports at the top of the file. */
function inPlace(f: Finding, line: string, replacement: string, imports: string[] = [], note?: string, extra: { from: number; to: number; text: string }[] = []): Fix {
  return {
    language: fileLang(f), before: line,
    after: imports.length ? `${imports.join('\n')}\n\n${replacement}` : replacement,
    imports: imports.length ? imports : undefined,
    replace: [{ from: f.line, to: f.line, text: replacement }, ...extra],
    note,
  }
}

/** The reviewed example from rules/catalog.json, shown as a pattern to adapt. */
function example(f: Finding, line: string, note?: string): Fix {
  const ex = fixExample(f.ruleId, f.language)
  return { language: ex?.language ?? fileLang(f), before: line, after: ex?.code.trimEnd() ?? '// Review and remediate manually.', standalone: true, note }
}

function toEnvName(raw: string | undefined, fallback: string): string {
  if (!raw) return fallback
  const name = raw.replace(/["'\]]/g, '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '').toUpperCase()
  return name.length >= 3 ? name : fallback
}

/** Name the value was assigned to, from the rule hit or the line itself. */
function assignedName(f: Finding, line: string): string | undefined {
  if (f.name) return f.name
  const m = /(?:const|let|var|export)?\s*([A-Za-z_][\w.]*)["']?\s*(?:=|:)(?!=)/.exec(line)
  return m?.[1]?.split('.').pop()
}

function envRef(f: Finding, name: string): string {
  return isPython(f) ? `os.environ["${name}"]` : `process.env.${name}`
}

/** Replace the quoted literal that contains `needle` with `replacement`. */
function replaceLiteral(line: string, needle: string, replacement: string): string {
  if (!needle) return line
  const re = new RegExp(`(["'\`])[^"'\`]*?${esc(needle)}[^"'\`]*?\\1`)
  if (re.test(line)) return line.replace(re, replacement)
  return line.replace(needle, replacement)
}

const SECRET_DEFAULT_ENV: Record<string, string> = {
  'CM-S001': 'AWS_ACCESS_KEY_ID', 'CM-S002': 'AWS_SECRET_ACCESS_KEY', 'CM-S003': 'GITHUB_TOKEN', 'CM-S004': 'STRIPE_SECRET_KEY',
  'CM-S005': 'OPENAI_API_KEY', 'CM-S006': 'ANTHROPIC_API_KEY', 'CM-S007': 'GOOGLE_API_KEY', 'CM-S008': 'SLACK_BOT_TOKEN',
  'CM-S009': 'PRIVATE_KEY', 'CM-S010': 'SERVICE_TOKEN', 'CM-S011': 'DATABASE_URL', 'CM-S012': 'API_TOKEN', 'CM-S014': 'API_SECRET',
  'CM-D004': 'JWT_SECRET',
}

function secretFix(f: Finding, line: string, content?: string): Fix {
  const name = toEnvName(assignedName(f, line), SECRET_DEFAULT_ENV[f.ruleId] ?? 'API_SECRET')
  const envName = f.ruleId === 'CM-S011' ? 'DATABASE_URL' : /^(CONFIG|KEY|TOKEN|SECRET|STRIPE|CLIENT|HEADERS)$/.test(name) ? (SECRET_DEFAULT_ENV[f.ruleId] ?? name) : name
  if (f.language === 'env') {
    return {
      language: 'dotenv', before: line,
      after: `${envName}=            # value lives in your host's secret manager, not in git\n\n# and in .env.example (committed):\n${envName}=your_value_here`,
      note: 'Keep real values out of the repo entirely. Commit a .env.example with blanks.',
    }
  }
  if (f.language === 'shell') {
    return { language: 'shell', before: line, after: `: "\${${envName}:?set ${envName} in your CI secret store}"`, note: 'Fail fast if the secret is missing instead of shipping a default.' }
  }
  if (!isPython(f) && !isJs(f)) return { language: fileLang(f), before: line, after: `# Move this value to your secret store and reference ${envName} instead.`, standalone: true }
  if (f.ruleId === 'CM-S009') {
    const decl = /^(\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*|\s*[A-Za-z_]\w*\s*=\s*)/.exec(line)?.[1] ?? (isPython(f) ? 'PRIVATE_KEY = ' : 'const privateKey = ')
    const text = isPython(f) ? `${decl}open(os.environ["PRIVATE_KEY_PATH"], encoding="utf-8").read()` : `${decl}fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8')`
    const imports = [isPython(f) ? 'import os' : jsImport(content, 'fs', 'fs')]
    return { ...inPlace(f, line, text, imports, 'Mount the key from a secret manager or a file outside the repo.'), replace: [{ from: f.line, to: f.endLine, text }] }
  }
  if (f.ruleId === 'CM-S011') {
    const after = line.replace(/\s*\|\|\s*(["'`])[^"'`]*\1/, '').replace(/(["'`])[a-z+]+:\/\/[^"'`]*\1/, envRef(f, 'DATABASE_URL'))
    return inPlace(f, line, after, isPython(f) ? ['import os'] : [])
  }
  if (isFrontend(f) && !isPython(f)) {
    return {
      language: fileLang(f), before: line, standalone: true,
      after: `// Never ship this to the browser. Anything in the bundle is public.\n// Call your own API route and keep ${envName} on the server:\nasync function callApi() {\n  return fetch('/api/proxy', { credentials: 'include' })\n}`,
      note: 'import.meta.env.VITE_* is still bundled into client JS, so it is not a fix for secrets.',
    }
  }
  const needle = f.maskedValue.split('\n')[0] ?? ''
  if (f.ruleId === 'CM-S012' && /(["'`])Bearer\s/.test(line)) {
    const lit = isPython(f) ? `"Bearer " + ${envRef(f, envName)}` : `\`Bearer \${${envRef(f, envName)}}\``
    return inPlace(f, line, replaceLiteral(line, needle, lit), isPython(f) ? ['import os'] : [])
  }
  return inPlace(f, line, replaceLiteral(line, needle, envRef(f, envName)), isPython(f) ? ['import os'] : [])
}

function redactArgs(f: Finding, line: string): string {
  const pyInterp = /\{([^{}]*(?:user|email|ssn|password|dob|phone|card)[^{}]*)\}/gi
  if (isPython(f)) {
    if (pyInterp.test(line)) return line.replace(pyInterp, (_m, e: string) => (/\[["'](email|ssn|password|dob|phone|card)["']\]/i.test(e) ? `{user['id']}` : `{redact(${e})}`))
  } else if (line.includes('${')) return line.replace(/\$\{([^}]+)\}/g, (m, e: string) => (/(user|email|ssn|password|dob|phone|card)/i.test(e) ? `\${redact(${e})}` : m))
  const open = line.indexOf('(')
  const close = line.lastIndexOf(')')
  if (open < 0 || close < open) return line
  const args = line.slice(open + 1, close)
  const comma = /^\s*(["'`]).*?\1\s*,/.exec(args)
  if (comma) return `${line.slice(0, open + 1)}${comma[0]} redact(${args.slice(comma[0].length).trim()})${line.slice(close)}`
  return `${line.slice(0, open + 1)}redact(${args})${line.slice(close)}`
}

const REDACT_HELPER_JS = `const SENSITIVE = ['email', 'ssn', 'password', 'dob', 'phone', 'card', 'token']
const redact = (v) => JSON.parse(JSON.stringify(v ?? null, (k, x) => (SENSITIVE.includes(k) ? '[redacted]' : x)))`
const REDACT_HELPER_PY = `SENSITIVE = {"email", "ssn", "password", "dob", "phone", "card", "token"}
def redact(v):
    if isinstance(v, list):
        return [redact(x) for x in v]
    if isinstance(v, dict):
        return {k: "[redacted]" if k in SENSITIVE else redact(x) for k, x in v.items()}
    return v`

/** Helper + rewritten line, with the helper indented to the line's block so it stays valid in place. */
function withHelper(f: Finding, line: string, rewritten: string): string {
  const helper = isPython(f) ? REDACT_HELPER_PY : REDACT_HELPER_JS
  const ind = indentOf(line)
  return `${helper.split('\n').map((l) => (l ? ind + l : l)).join('\n')}\n\n${rewritten}`
}

// ---------------------------------------------------------------------------
// Weak password hashing (CM-D002): bcrypt with real hash/verify semantics
// ---------------------------------------------------------------------------

const OPERAND = String.raw`[\w$.\[\]"']+(?:\(\))?`
const PY_HASH = /hashlib\.(?:md5|sha1)\(((?:[^()]|\([^()]*\))*)\)(\.hexdigest\(\)|\.digest\(\))?/
const JS_HASH = /(?:crypto\.)?createHash\(\s*['"](?:md5|sha1)['"]\s*\)\.update\(((?:[^()]|\([^()]*\))*)\)(?:\.digest\([^)]*\))?/

/** A comparison against `name` in the next few lines of the same block. Mirrors fixes._later_comparison. */
function laterComparison(rows: string[], idx: number, name: string, js: boolean): { j: number; m: RegExpExecArray; operandFirst: boolean } | null {
  const ops = js ? '(===|==|!==|!=)' : '(==|!=)'
  const n = `(?<![\\w$.])${esc(name)}(?![\\w$])`
  const base = indentOf(rows[idx] ?? '').length
  for (let j = idx + 1; j < Math.min(rows.length, idx + 8); j++) {
    const row = rows[j]!
    if (row.trim() && indentOf(row).length < base) break
    let m = new RegExp(`(${OPERAND})\\s*${ops}\\s*${n}`).exec(row)
    if (m && m[1] !== name) return { j, m, operandFirst: true }
    m = new RegExp(`${n}\\s*${ops}\\s*(${OPERAND})`).exec(row)
    if (m) return { j, m, operandFirst: false }
  }
  return null
}

/** Line index and kind of the JS function enclosing line `idx`. Mirrors fixes._enclosing_js_function. */
function enclosingJsFunction(rows: string[], idx: number): { j: number; kind: 'function' | 'arrow' | 'method' } | null {
  let depth = 0
  for (let j = idx; j >= 0; j--) {
    const text = rows[j]!.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '').replace(/\/\/.*$/, '')
    const seg = j === idx ? '' : text
    depth += (seg.match(/\}/g) ?? []).length - (seg.match(/\{/g) ?? []).length
    if (depth < 0) {
      if (/\bfunction\b/.test(text)) return { j, kind: 'function' }
      if (text.includes('=>')) return { j, kind: 'arrow' }
      if (/^\s*(?:static\s+)?(?:get\s+|set\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{/.test(text) && !/^\s*(?:if|for|while|switch|catch)\b/.test(text)) return { j, kind: 'method' }
      depth = 0
    }
  }
  return null
}

function makeAsync(line: string, kind: 'function' | 'arrow' | 'method'): string {
  if (/\basync\b/.test(line)) return line
  if (kind === 'function') return line.replace(/\bfunction\b/, 'async function')
  if (kind === 'arrow') return line.replace(/(\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>/, 'async $1 =>')
  return line.replace(/^(\s*(?:static\s+)?)/, '$1async ')
}

function weakHashFix(f: Finding, line: string, content?: string): Fix {
  const rows = content?.split('\n')
  const idx = f.line - 1
  if (isPython(f)) {
    const m = PY_HASH.exec(line)
    let arg = m?.[1]?.trim() ?? ''
    if (!m || !arg) return example(f, line)
    if (!arg.endsWith('.encode()') && !/^b["'].*["']$/.test(arg)) {
      if (!/^[A-Za-z_][\w.]*$/.test(arg)) return example(f, line)
      arg = `${arg}.encode()`
    }
    const before = line.slice(0, m.index)
    const after = line.slice(m.index + m[0].length)
    const note = 'Verify with bcrypt.checkpw(password.encode(), stored_hash.encode()). argon2id (argon2-cffi) is an equally good choice.'
    const cmpA = new RegExp(`^\\s*(==|!=)\\s*(${OPERAND})`).exec(after)
    const cmpB = new RegExp(`(${OPERAND})\\s*(==|!=)\\s*$`).exec(before)
    if (cmpA || cmpB) {
      const [op, other] = cmpA ? [cmpA[1]!, cmpA[2]!] : [cmpB![2]!, cmpB![1]!]
      const check = `${op === '!=' ? 'not ' : ''}bcrypt.checkpw(${arg}, ${other}.encode())`
      const text = cmpB ? before.slice(0, cmpB.index) + check + after : before + check + after.slice(cmpA![0].length)
      return inPlace(f, line, text, ['import bcrypt'], 'Stored values must be bcrypt hashes (re-hash on next login). argon2id is an equally good choice.')
    }
    const assigned = /^\s*([A-Za-z_]\w*)\s*=\s*$/.exec(before)
    const later = rows && assigned && !after.trim() ? laterComparison(rows, idx, assigned[1]!, false) : null
    if (later && rows) {
      const other = later.operandFirst ? later.m[1]! : later.m[3]!
      const check = `${later.m[2] === '!=' ? 'not ' : ''}bcrypt.checkpw(${arg}, ${other}.encode())`
      const row = rows[later.j]!
      const verify = row.slice(0, later.m.index) + check + row.slice(later.m.index + later.m[0].length)
      const text = `${indentOf(line)}# password is verified with bcrypt.checkpw below`
      return inPlace(f, line, text, ['import bcrypt'], 'Stored values must be bcrypt hashes (re-hash on next login).', [{ from: later.j + 1, to: later.j + 1, text: verify }])
    }
    return inPlace(f, line, `${before}bcrypt.hashpw(${arg}, bcrypt.gensalt())${m[2] === '.hexdigest()' ? '.decode()' : ''}${after}`, ['import bcrypt'], note)
  }
  if (!isJs(f)) return example(f, line)
  const m = JS_HASH.exec(line)
  const arg = m?.[1]?.trim() ?? ''
  // Without the file we can't tell whether `await` is legal here: show the reviewed example.
  if (!m || !arg || !rows) return example(f, line, 'Hash with await bcrypt.hash(password, 12) and verify with await bcrypt.compare(password, storedHash) inside an async function.')
  const extra: { from: number; to: number; text: string }[] = []
  let note = 'Verify with await bcrypt.compare(password, storedHash). argon2id (argon2 package) is an equally good choice.'
  const fn = enclosingJsFunction(rows, idx)
  if (!fn && !isEsm(content!)) return example(f, line)
  if (fn && !/\basync\b/.test(rows[fn.j]!)) {
    extra.push({ from: fn.j + 1, to: fn.j + 1, text: makeAsync(rows[fn.j]!, fn.kind) })
    note = `Make the enclosing function async (line ${fn.j + 1}); its callers must then await it. ${note}`
  }
  const imports = [jsImport(content, 'bcrypt', 'bcryptjs')]
  const before = line.slice(0, m.index)
  const after = line.slice(m.index + m[0].length)
  const cmpA = new RegExp(`^\\s*(===|==|!==|!=)\\s*(${OPERAND})`).exec(after)
  const cmpB = new RegExp(`(${OPERAND})\\s*(===|==|!==|!=)\\s*$`).exec(before)
  if (cmpA || cmpB) {
    const [op, other] = cmpA ? [cmpA[1]!, cmpA[2]!] : [cmpB![2]!, cmpB![1]!]
    const check = `${op.startsWith('!') ? '!' : ''}(await bcrypt.compare(${arg}, ${other}))`
    return inPlace(f, line, cmpB ? before.slice(0, cmpB.index) + check + after : before + check + after.slice(cmpA![0].length), imports, note, extra)
  }
  const assigned = /^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*$/.exec(before)
  const later = assigned && !after.replace(/[\s;]/g, '') ? laterComparison(rows, idx, assigned[1]!, true) : null
  if (later) {
    const other = later.operandFirst ? later.m[1]! : later.m[3]!
    const check = `${later.m[2]!.startsWith('!') ? '!' : ''}(await bcrypt.compare(${arg}, ${other}))`
    const row = rows[later.j]!
    extra.push({ from: later.j + 1, to: later.j + 1, text: row.slice(0, later.m.index) + check + row.slice(later.m.index + later.m[0].length) })
    return inPlace(f, line, `${indentOf(line)}// password is verified with bcrypt.compare below`, imports, `Stored values must be bcrypt hashes (re-hash on next login). ${note}`, extra)
  }
  return inPlace(f, line, `${before}await bcrypt.hash(${arg}, 12)${after}`, imports, note, extra)
}

// ---------------------------------------------------------------------------
// Per-rule templates
// ---------------------------------------------------------------------------

function cookieFix(f: Finding, line: string): Fix {
  if (/document\.cookie/.test(line)) return { ...example(f, line), note: 'Don’t set auth cookies from the browser; set them server-side with HttpOnly, Secure and SameSite.' }
  const open = line.search(isPython(f) ? /\.set_cookie\s*\(/ : /\b(?:res|response|ctx|reply)\.(?:cookie|setCookie)\s*\(/)
  const close = line.lastIndexOf(')')
  if (open < 0 || close < open) return example(f, line)
  const call = line.slice(open, close + 1)
  if (isPython(f)) {
    const add = [
      !/httponly\s*=\s*True/i.test(call) && 'httponly=True',
      !/secure\s*=\s*True/i.test(call) && 'secure=True',
      !/samesite\s*=/i.test(call) && 'samesite="Lax"',
    ].filter(Boolean)
    return inPlace(f, line, add.length ? `${line.slice(0, close)}, ${add.join(', ')}${line.slice(close)}` : line)
  }
  const missing = [
    !/httpOnly\s*:\s*true/i.test(call) && 'httpOnly: true',
    !/secure\s*:\s*true/i.test(call) && 'secure: true',
    !/sameSite\s*:/i.test(call) && "sameSite: 'lax'",
  ].filter(Boolean)
  if (!missing.length) return inPlace(f, line, line)
  const brace = call.indexOf('{')
  const text = brace >= 0 ? `${line.slice(0, open + brace + 1)} ${missing.join(', ')},${line.slice(open + brace + 1)}` : `${line.slice(0, close)}, { ${missing.join(', ')} }${line.slice(close)}`
  return inPlace(f, line, text)
}

function queryStringFix(f: Finding, line: string): Fix {
  const m = /fetch\(\s*(`|'|")([^`'"?]*)\?([^`'"]*)\1\s*\)/.exec(line)
  if (!m || !isJs(f)) return example(f, line)
  const pairs = m[3]!.split('&').map((kv) => kv.split('=')).filter((kv) => kv.length === 2)
  const fields = pairs.map(([k, v]) => { const e = /^\$\{([^}]+)\}$/.exec(v!); return e ? (e[1]!.trim() === k ? k : `${k}: ${e[1]!.trim()}`) : `${k}: ${JSON.stringify(v)}` })
  const call = `fetch(${m[1]}${m[2]}${m[1]}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ${fields.join(', ')} }) })`
  return inPlace(f, line, line.slice(0, m.index) + call + line.slice(m.index + m[0].length), [], 'Sensitive values travel in the request body instead of the URL, so they stay out of logs and browser history.')
}

function plaintextPasswordFix(f: Finding, line: string): Fix {
  if (f.language === 'sql') {
    return { language: 'sql', before: line, after: line.replace(/\b(password|passwd|pwd)\s+(?:VARCHAR|TEXT|CHAR|NVARCHAR)(\(\d+\))?/i, 'password_hash TEXT') + '  -- bcrypt / argon2id hash, never the password' }
  }
  if (isPython(f)) {
    const m = /(["'])password\1\s*:\s*((?:[^,}()]|\([^()]*\))+)/.exec(line)
    if (m) {
      const value = m[2]!.trim()
      const text = line.replace(m[0], `"password_hash": bcrypt.hashpw(${value}.encode(), bcrypt.gensalt()).decode()`)
      return inPlace(f, line, text, ['import bcrypt'], 'Check logins with bcrypt.checkpw(password.encode(), stored_hash.encode()).')
    }
  }
  return example(f, line, 'Hash the password with bcrypt (or argon2id) before it is stored, and store only the hash.')
}

const SIMPLE: Record<string, (f: Finding, line: string) => Fix | null> = {
  'CM-A003': (f, line) => (/(?<![\w.])eval\s*\(/.test(line) ? inPlace(f, line, line.replace(/(?<![\w.])eval\s*\(/, 'ast.literal_eval('), ['import ast'], 'literal_eval accepts Python literals only, never code.') : null),
  'CM-A004': (f, line) => (/\byaml\.load\(/.test(line) ? inPlace(f, line, line.replace(/\byaml\.load\(\s*([^,()]+?)\s*(?:,\s*Loader\s*=\s*[\w.]+\s*)?\)/, 'yaml.safe_load($1)')) : null),
  'CM-A005': (f, line) => inPlace(f, line, line.replace(/debug\s*=\s*True/, 'debug=os.environ.get("FLASK_DEBUG") == "1"'), ['import os'], 'Debug stays off unless FLASK_DEBUG=1 is set on a developer machine.'),
  'CM-A006': (f, line) => inPlace(f, line, line.replace(/\bverify\s*=\s*False\b/, 'verify=True'), [], 'If you use a private CA, pass verify="/path/to/ca.pem" instead.'),
  'CM-C003': (f, line) => {
    const m = /^(\s*)DEBUG\s*=\s*True\b(.*)$/.exec(line)
    if (m) return inPlace(f, line, `${m[1]}DEBUG = os.environ.get("DEBUG") == "1"${m[2]}`, ['import os'])
    return inPlace(f, line, line.replace(/\bdebug\s*=\s*True\b/, 'debug=False').replace(/(\.debug\s*=\s*)True\b/, '$1False').replace(/(\[\s*["']DEBUG["']\s*\]\s*=\s*)True\b/, '$1False'))
  },
  'CM-J001': (f, line) => (/\.innerHTML\s*=(?!=)/.test(line) && !/\+=/.test(line) ? inPlace(f, line, line.replace(/\.innerHTML(\s*=)/, '.textContent$1'), [], 'If you really need markup, sanitize it first: el.innerHTML = DOMPurify.sanitize(html).') : null),
  'CM-J005': (f, line) => (/\bjwt\.decode\s*\(\s*[^,()]+?\s*\)/.test(line) ? inPlace(f, line, line.replace(/\bjwt\.decode\s*\(\s*([^,()]+?)\s*\)/, "jwt.verify($1, process.env.JWT_SECRET, { algorithms: ['HS256'] })")) : null),
  'CM-C002': (f, line) => (isPython(f) && /(?<![\w.])random\.(?:choice|choices|sample|randint)\s*\(/.test(line) ? inPlace(f, line, line.replace(/(?<![\w.])random\.(choice|choices|sample|randint)\s*\(/g, 'secrets.SystemRandom().$1('), ['import secrets']) : null),
}

function corsFix(f: Finding, line: string): Fix {
  if (isPython(f)) {
    const env = 'os.environ.get("ALLOWED_ORIGINS", "").split(",")'
    const text = line.replace(/allow_origins\s*=\s*\[\s*["']\*["']\s*\]/, `allow_origins=${env}`).replace(/\borigins\s*=\s*["']\*["']/, `origins=${env}`).replace(/\bCORS\(\s*(\w+)\s*\)/, `CORS($1, origins=${env})`)
    return text === line ? example(f, line) : inPlace(f, line, text, ['import os'], 'List the exact frontends you trust in ALLOWED_ORIGINS.')
  }
  const env = "(process.env.ALLOWED_ORIGINS || '').split(',')"
  const text = line.replace(/\borigin\s*:\s*(?:["']\*["']|true\b)/, `origin: ${env}`).replace(/\bcors\(\s*\)/, `cors({ origin: ${env} })`)
  return text === line ? example(f, line) : inPlace(f, line, text, [], 'List the exact frontends you trust in ALLOWED_ORIGINS.')
}

function fixFor(f: Finding, line: string, content?: string): Fix {
  const lang = fileLang(f)
  if (f.ruleId === 'CM-S007' && isJs(f)) {
    return inPlace(f, line, replaceLiteral(line, f.maskedValue, 'import.meta.env.VITE_GOOGLE_MAPS_KEY'), [],
      'Maps browser keys end up public by design, so the real fix is in Google Cloud Console: restrict the key to your domains and to the Maps APIs only.')
  }
  const simple = SIMPLE[f.ruleId]?.(f, line)
  if (simple) return simple
  switch (f.ruleId) {
    case 'CM-S013':
      return { language: 'shell', before: `# ${f.file}\n${line}`, after: 'git rm --cached .env\necho ".env" >> .gitignore\ncp .env .env.example   # then blank every value in .env.example\ngit commit -m "Stop tracking .env"', note: 'If the repo was ever pushed, also purge it from history (git filter-repo) and rotate every value.' }
    case 'CM-D008':
      return { language: 'gitignore', before: '# .gitignore\nnode_modules/\ndist/', after: '# .gitignore\nnode_modules/\ndist/\n.env\n.env.*\n!.env.example' }
    case 'CM-P001':
      return inPlace(f, line, line.replace(f.maskedValue, 'user1@example.test'), [], 'Use reserved test domains (example.test) or generate fixtures with a faker library.')
    case 'CM-P002':
      return inPlace(f, line, line.replace(f.maskedValue, '(555) 010-0000'), [], '555-01xx numbers are reserved for fiction and testing.')
    case 'CM-P003':
      return inPlace(f, line, line.replace(f.maskedValue, '000-00-0000'), [], 'Area 000 is never issued, so it can’t belong to a real person. Better: don’t store SSNs at all.')
    case 'CM-P004':
      return inPlace(f, line, /^\s*(\/\/|#)/.test(line) ? line.replace(f.maskedValue, 'Stripe test card (see their docs)') : line.replace(f.maskedValue, 'tok_visa'), [], 'Never store PANs. Use your processor’s tokens; that keeps you out of PCI scope.')
    case 'CM-P005':
      return inPlace(f, line, line.replace(f.maskedValue, '1970-01-01'))
    case 'CM-P006':
      if (!isPython(f) && !isJs(f)) return example(f, line)
      return inPlace(f, line, withHelper(f, line, redactArgs(f, line)), [], 'Better still, log an id instead of the person.')
    case 'CM-P007':
      return queryStringFix(f, line)
    case 'CM-D001': {
      const userish = /user|profile/i.test(f.name ?? '') && !/token|auth|session/i.test(f.name ?? '')
      return userish
        ? inPlace(f, line, `${indentOf(line)}sessionStorage.setItem('userId', String(user.id))  // ids only; fetch the profile when needed`)
        : { ...example(f, line), note: 'HttpOnly cookies are invisible to JavaScript, so an XSS bug can’t read the token.' }
    }
    case 'CM-D002':
      return weakHashFix(f, line, content)
    case 'CM-D003':
      return plaintextPasswordFix(f, line)
    case 'CM-D004':
      return secretFix({ ...f, name: f.name ?? (line.includes('session(') ? 'SESSION_SECRET' : 'JWT_SECRET') }, line, content)
    case 'CM-D005':
      return cookieFix(f, line)
    case 'CM-D006': {
      if (!isPython(f) && !isJs(f)) return example(f, line)
      const word = /`([^`]+)`/.exec(f.note ?? '')?.[1] ?? 'user'
      const rewritten = line.replace(new RegExp(`\\b${esc(word)}\\b(?![\\w'"])`), `redact(${word})`)
      return inPlace(f, line, withHelper(f, line, rewritten), [], 'If you truly need the record on disk, encrypt it and give the file 0600 permissions.')
    }
    case 'CM-D007':
      if (/NODE_TLS_REJECT_UNAUTHORIZED/.test(line)) return inPlace(f, line, `${indentOf(line)}// Removed. Trust your internal CA explicitly instead:\n${indentOf(line)}//   NODE_EXTRA_CA_CERTS=/etc/ssl/internal-ca.pem node server/index.js`)
      if (/rejectUnauthorized/.test(line)) return inPlace(f, line, line.replace(/rejectUnauthorized\s*:\s*false/, 'ca: fs.readFileSync(process.env.DB_CA_CERT_PATH)'), [jsImport(content, 'fs', 'fs')])
      if (/verify\s*=\s*False/.test(line)) return inPlace(f, line, line.replace(/verify\s*=\s*False/, 'verify="/etc/ssl/certs/internal-ca.pem"'))
      if (/curl/.test(line)) return { language: lang, before: line, after: line.replace(/\s(?:-k|--insecure)\b/, ' --cacert ./certs/internal-ca.pem') }
      if (/_create_unverified_context/.test(line)) return inPlace(f, line, line.replace(/ssl\._create_unverified_context\(/, 'ssl.create_default_context('))
      if (/CERT_NONE|check_hostname/.test(line)) return inPlace(f, line, line.replace(/\bCERT_NONE\b/, 'CERT_REQUIRED').replace(/(\.check_hostname\s*=\s*)False\b/, '$1True'))
      return example(f, line)
    case 'CM-J004':
    case 'CM-C004':
      return corsFix(f, line)
    case 'CM-A001': return example(f, line, 'Pass values as query parameters instead of formatting them into the SQL string.')
    case 'CM-J003': return example(f, line, 'Use placeholders (? or $1) and pass the values array as the second argument.')
    case 'CM-A002': return example(f, line, 'Build an argument list and run it with shell=False.')
    case 'CM-J002': return example(f, line, 'Use execFile/spawn with an argument array and no shell.')
    case 'CM-A008': return example(f, line, 'Escape request values with markupsafe.escape() or render a Jinja2 template.')
    case 'CM-J006': return example(f, line, 'Escape request values before they are written into HTML.')
    default:
      if (CATALOG[f.ruleId]?.category === 'secrets') return secretFix(f, line, content)
      return example(f, line)
  }
}

/**
 * Explanation, steps and fix for a finding. `fullLine` is the finding's masked source line and
 * `content` the masked file, which lets context-dependent fixes (bcrypt + async) apply in place.
 */
export function adviceFor(f: Finding, fullLine?: string, content?: string): Advice {
  const entry = CATALOG[f.ruleId] ?? { explanation: 'This pattern is commonly associated with security incidents.', steps: ['Review the code and remove the sensitive value.'], category: f.category }
  const line = (fullLine ?? f.snippet).replace(/\s+$/, '')
  const steps = f.ruleId === 'CM-S013' ? [...entry.steps, ROTATE_STEP] : entry.category === 'secrets' || f.ruleId === 'CM-D004' ? [ROTATE_STEP, ...entry.steps] : [...entry.steps]
  return { why: entry.explanation, steps, fix: fixFor(f, line, content) }
}
