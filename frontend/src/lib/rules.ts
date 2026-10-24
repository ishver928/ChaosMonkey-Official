import type { DetectContext, RawMatch, Rule, RuleMeta, SourceFile } from './types'
import { isPlaceholder, shannonEntropy } from './entropy'
import { baseName, isEnvFile, isEnvTemplate } from './language'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Run a /gd regex and return a hit for capture group `group` (0 = whole match). */
function regexHits(
  content: string,
  re: RegExp,
  opts: { group?: number; confidence: number; sensitive?: boolean; nameGroup?: number; filter?: (value: string, m: RegExpExecArray) => boolean | number },
): RawMatch[] {
  const out: RawMatch[] = []
  const group = opts.group ?? 0
  for (const m of content.matchAll(re) as IterableIterator<RegExpExecArray>) {
    const span = m.indices?.[group]
    const value = m[group]
    if (!span || value === undefined) continue
    let confidence = opts.confidence
    if (opts.filter) {
      const verdict = opts.filter(value, m)
      if (verdict === false) continue
      if (typeof verdict === 'number') confidence = verdict
    }
    out.push({
      start: span[0],
      end: span[1],
      sensitive: opts.sensitive ?? true,
      confidence,
      name: opts.nameGroup !== undefined ? m[opts.nameGroup] : undefined,
    })
  }
  return out
}

interface LineInfo { text: string; start: number; index: number }

function lines(content: string): LineInfo[] {
  const out: LineInfo[] = []
  let start = 0
  content.split('\n').forEach((text, index) => {
    out.push({ text, start, index })
    start += text.length + 1
  })
  return out
}

const isCodeLanguage = (ctx: DetectContext) => ctx.language === 'javascript' || ctx.language === 'typescript' || ctx.language === 'python'

/** Keep the code-ish parts of an expression: drop plain string literal contents but keep ${...} / f-string {...} interpolations. */
function codeParts(expr: string): string {
  const interpolations: string[] = []
  expr.replace(/\$\{([^}]*)\}/g, (_, inner: string) => { interpolations.push(inner); return '' })
  expr.replace(/\bf(["'])((?:\\.|(?!\1).)*)\1/g, (_, _q: string, body: string) => {
    body.replace(/\{([^}]*)\}/g, (__, inner: string) => { interpolations.push(inner); return '' })
    return ''
  })
  const stripped = expr.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, ' ')
  return `${stripped} ${interpolations.join(' ')}`
}

const SECRET_NAME = /(api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|\bpwd\b|_pwd\b|passphrase|credential|private[_-]?key|access[_-]?key|auth[_-]?key|signing[_-]?key|encryption[_-]?key|client[_-]?secret|(?:^|[_.-])key$)/i
const PASSWORD_NAME = /(passw(?:or)?d|passwd|pwd|passphrase)/i
const PII_WORDS = /\b(users?|customers?|patients?|members?|email|e_?mail|ssn|social_?security|password|passwd|dob|birth\w*|phone\w*|card\w*|credit\w*|req\.body|request\.(?:body|json|form)|profile|account|address)\b/i

function luhn(digits: string): boolean {
  let sum = 0
  let dbl = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (dbl) { d *= 2; if (d > 9) d -= 9 }
    sum += d
    dbl = !dbl
  }
  return sum % 10 === 0
}

function globToRegExp(glob: string): RegExp {
  const body = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*')
  return new RegExp(`^${body}$`)
}

function dirOf(path: string): string {
  const i = path.replace(/\\/g, '/').lastIndexOf('/')
  return i < 0 ? '' : path.replace(/\\/g, '/').slice(0, i)
}

/** Is `envPath` ignored by any .gitignore in an ancestor directory? Supports the common subset of gitignore globs. */
function coveredByGitignore(envPath: string, project: readonly SourceFile[]): { covered: boolean; hasGitignore: boolean } {
  const normalized = envPath.replace(/\\/g, '/')
  const ignores = project.filter((f) => baseName(f.path) === '.gitignore')
  let covered = false
  for (const gi of ignores) {
    const dir = dirOf(gi.path)
    if (dir && !normalized.startsWith(`${dir}/`)) continue
    const rel = dir ? normalized.slice(dir.length + 1) : normalized
    for (const raw of gi.content.split('\n')) {
      const line = raw.trim()
      if (!line || line.startsWith('#')) continue
      const negate = line.startsWith('!')
      const pattern = (negate ? line.slice(1) : line).replace(/^\//, '').replace(/\/$/, '')
      const re = globToRegExp(pattern)
      const hit = pattern.includes('/') ? re.test(rel) : re.test(baseName(rel))
      if (hit) covered = !negate
    }
  }
  return { covered, hasGitignore: ignores.length > 0 }
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const RULES: Rule[] = [
  // ----------------------------- Exposed secrets -----------------------------
  {
    id: 'CM-S001', title: 'AWS access key ID', category: 'secrets', severity: 'critical',
    description: 'AKIA/ASIA-prefixed AWS access key IDs. Paired with a secret key they grant API access to your cloud account.',
    detect: (ctx) => regexHits(ctx.content, /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/gd, { group: 1, confidence: 0.95 }),
  },
  {
    id: 'CM-S002', title: 'AWS secret access key', category: 'secrets', severity: 'critical',
    description: '40-character AWS secret keys assigned to an aws…secret name in code, config or .env files.',
    detect: (ctx) => regexHits(ctx.content, /(aws[\w.\-]{0,30}?secret[\w\-]*)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gid, { group: 2, nameGroup: 1, confidence: 0.92 }),
  },
  {
    id: 'CM-S003', title: 'GitHub token', category: 'secrets', severity: 'critical',
    description: 'Classic (ghp_, gho_, ghs_…) and fine-grained (github_pat_) GitHub tokens, which can read or push to your repositories.',
    detect: (ctx) => regexHits(ctx.content, /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b/gd, { group: 1, confidence: 0.97 }),
  },
  {
    id: 'CM-S004', title: 'Stripe live key', category: 'secrets', severity: 'critical',
    description: 'Live-mode Stripe secret (sk_live_) and restricted (rk_live_) keys. These can move real money.',
    detect: (ctx) => regexHits(ctx.content, /\b((?:sk|rk)_live_[0-9a-zA-Z]{16,})\b/gd, { group: 1, confidence: 0.97 }),
  },
  {
    id: 'CM-S005', title: 'OpenAI-style API key', category: 'secrets', severity: 'high',
    description: 'sk-… and sk-proj-… keys used by OpenAI and compatible LLM APIs. Leaked keys get used to run up large bills within hours.',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w-])(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})/gd, {
      group: 1, confidence: 0.85,
      filter: (v) => v.length >= 24 && /\d/.test(v) && /[A-Za-z]/.test(v.slice(3)),
    }),
  },
  {
    id: 'CM-S006', title: 'Anthropic API key', category: 'secrets', severity: 'critical',
    description: 'sk-ant-… keys for the Anthropic API.',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w-])(sk-ant-[A-Za-z0-9_\-]{20,})/gd, { group: 1, confidence: 0.96 }),
  },
  {
    id: 'CM-S007', title: 'Google API key', category: 'secrets', severity: 'high',
    description: 'AIza-prefixed Google Cloud / Firebase / Maps API keys.',
    detect: (ctx) => regexHits(ctx.content, /\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])/gd, { group: 1, confidence: 0.93 }),
  },
  {
    id: 'CM-S008', title: 'Slack token', category: 'secrets', severity: 'high',
    description: 'xoxb-/xoxp-/xoxa- Slack bot and user tokens that can read channels and post as your workspace.',
    detect: (ctx) => regexHits(ctx.content, /\b(xox[abposr]-[A-Za-z0-9-]{10,})/gd, { group: 1, confidence: 0.92 }),
  },
  {
    id: 'CM-S009', title: 'Private key block', category: 'secrets', severity: 'critical',
    description: 'PEM-encoded RSA, EC, OpenSSH or PKCS#8 private keys committed alongside code.',
    detect: (ctx) => regexHits(ctx.content, /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/gd, { confidence: 0.99 }),
  },
  {
    id: 'CM-S010', title: 'JSON Web Token', category: 'secrets', severity: 'high',
    description: 'Hardcoded JWTs (eyJ….eyJ….sig). Anyone holding one can act as that session until it expires.',
    detect: (ctx) => regexHits(ctx.content, /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/gd, { group: 1, confidence: 0.88 }),
  },
  {
    id: 'CM-S011', title: 'Database URL with credentials', category: 'secrets', severity: 'critical',
    description: 'Connection strings like postgres://user:password@host with the password embedded.',
    detect: (ctx) => regexHits(ctx.content, /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^:\/\s'"@]*:([^@\s'"\/]+)@/gd, {
      group: 1, confidence: 0.93,
      filter: (v) => !isPlaceholder(v) && !v.startsWith('$') && !v.startsWith('{'),
    }),
  },
  {
    id: 'CM-S012', title: 'Hardcoded Bearer token', category: 'secrets', severity: 'high', generic: true,
    description: 'Literal "Authorization: Bearer <token>" values in code, scripts or fixtures.',
    detect: (ctx) => regexHits(ctx.content, /Bearer\s+([A-Za-z0-9\-._~+\/]{20,}=*)/gd, {
      group: 1, confidence: 0.8,
      filter: (v) => !isPlaceholder(v),
    }),
  },
  {
    id: 'CM-S013', title: 'Committed .env file', category: 'secrets', severity: 'high',
    description: '.env files with real values included in the scanned tree. .env.example / .env.sample templates are allowed.',
    detect: (ctx) => {
      if (!isEnvFile(ctx.path) || isEnvTemplate(ctx.path)) return []
      const assignments = lines(ctx.content)
        .map((l) => ({ l, m: /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(l.text) }))
        .filter((x) => x.m && x.m[2]!.trim().replace(/^["']|["']$/g, '').length > 0)
      if (assignments.length === 0) return []
      const first = assignments[0]!
      const offset = first.l.text.indexOf(first.m![1]!)
      return [{
        start: first.l.start + offset, end: first.l.start + offset + first.m![1]!.length,
        sensitive: false, confidence: 0.95, note: `${assignments.length} value${assignments.length === 1 ? '' : 's'} committed`,
      }]
    },
  },
  {
    id: 'CM-S014', title: 'High-entropy secret assignment', category: 'secrets', severity: 'high', generic: true,
    description: 'Values assigned to names like key, secret, token or password, scored with Shannon entropy. Placeholders such as YOUR_API_KEY or "changeme" are ignored.',
    detect: (ctx) => {
      const out: RawMatch[] = []
      const consider = (name: string, value: string, start: number) => {
        if (!SECRET_NAME.test(name) || isPlaceholder(value) || value.includes('${')) return
        if (/^(?:https?:)?\/\//.test(value) || /^[./]/.test(value)) return
        const isPassword = PASSWORD_NAME.test(name)
        const h = shannonEntropy(value)
        let confidence: number
        if (isPassword) {
          if (value.length < 6) return
          confidence = Math.min(0.9, 0.55 + h / 12)
        } else {
          if (value.length < 12 || h < 3.2) return
          confidence = Math.max(0.45, Math.min(0.92, (h - 3) / 1.6))
        }
        out.push({ start, end: start + value.length, sensitive: true, confidence, name, note: isPassword ? 'hardcoded password' : `entropy ${h.toFixed(2)} bits/char` })
      }
      const quoted = /\b([A-Za-z_$][\w.\-$]*)["']?\s*(?:=>|:=|[:=])\s*(["'`])([^"'`\s]{6,})\2/gd
      for (const m of ctx.content.matchAll(quoted) as IterableIterator<RegExpExecArray>) {
        const span = m.indices?.[3]
        if (span) consider(m[1]!, m[3]!, span[0])
      }
      if (['env', 'ini', 'toml', 'yaml'].includes(ctx.language)) {
        const bare = /^[ \t]*(?:export\s+)?([A-Za-z_][\w.\-]*)[ \t]*[=:][ \t]*([^"'\s#][^\s#]{5,})/gmd
        for (const m of ctx.content.matchAll(bare) as IterableIterator<RegExpExecArray>) {
          const span = m.indices?.[2]
          if (span) consider(m[1]!, m[2]!, span[0])
        }
      }
      return out
    },
  },

  // ------------------------- Sensitive personal info -------------------------
  {
    id: 'CM-P001', title: 'Email address', category: 'pii', severity: 'low',
    description: 'Real-looking email addresses in source, fixtures or seed data.',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w.%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b/gd, {
      group: 1, confidence: 0.6,
      filter: (v, m) => {
        const before = ctx.content[(m.indices?.[1]?.[0] ?? 1) - 1]
        if (before === ':' || before === '/') return false
        if (/^(noreply|no-reply|git)@/i.test(v) || /\.(png|jpe?g|gif|svg|webp|css|js|ts)$/i.test(v)) return false
        return true
      },
    }),
  },
  {
    id: 'CM-P002', title: 'Phone number', category: 'pii', severity: 'low', generic: true,
    description: 'North American phone numbers with separators, e.g. (415) 555-0134 or +1 415-555-0134.',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w-])((?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4})(?![\w-])/gd, { group: 1, confidence: 0.55 }),
  },
  {
    id: 'CM-P003', title: 'US Social Security number', category: 'pii', severity: 'high',
    description: 'NNN-NN-NNNN values that pass SSA structural rules (no 000/666/9xx area, no 00 group, no 0000 serial).',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w-])((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\w-])/gd, { group: 1, confidence: 0.85 }),
  },
  {
    id: 'CM-P004', title: 'Credit card number', category: 'pii', severity: 'high',
    description: 'Visa, Mastercard, Amex and Discover numbers. Every candidate is Luhn-checked to cut false positives.',
    detect: (ctx) => regexHits(ctx.content, /(?<![\w-])((?:\d[ -]?){12,18}\d)(?![\w-])/gd, {
      group: 1, confidence: 0.9,
      filter: (v) => {
        const digits = v.replace(/[ -]/g, '')
        if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false
        if (!/^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))/.test(digits)) return false
        return luhn(digits)
      },
    }),
  },
  {
    id: 'CM-P005', title: 'Date of birth', category: 'pii', severity: 'medium',
    description: 'Dates assigned to dob / birthdate / date_of_birth fields.',
    detect: (ctx) => regexHits(ctx.content, /\b(dob|date_?of_?birth|birth_?date|birthday|dateOfBirth)["']?\s*[:=]\s*["']?(\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4})/gid, { group: 2, nameGroup: 1, confidence: 0.8 }),
  },
  {
    id: 'CM-P006', title: 'Personal data written to logs', category: 'pii', severity: 'high',
    description: 'console.log / print / logger calls that print user objects, emails, SSNs, passwords or request bodies.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      const out: RawMatch[] = []
      const re = /\b(console\.(?:log|info|debug|warn|error)|print|logger\.(?:info|debug|warn|warning|error|log)|logging\.(?:info|debug|warning|error)|log\.(?:info|debug|warn))\s*\(/g
      for (const l of lines(ctx.content)) {
        for (const m of l.text.matchAll(re)) {
          const args = l.text.slice((m.index ?? 0) + m[0].length)
          const words = codeParts(args).match(PII_WORDS)
          if (!words) continue
          const start = l.start + (m.index ?? 0)
          out.push({ start, end: l.start + l.text.trimEnd().length, sensitive: false, confidence: 0.75, note: `logs \`${words[0]}\`` })
        }
      }
      return out
    },
  },
  {
    id: 'CM-P007', title: 'Personal data in URL', category: 'pii', severity: 'medium',
    description: 'Emails, SSNs, phone numbers, passwords or tokens placed in query strings, where they end up in server logs, proxies and browser history.',
    detect: (ctx) => regexHits(ctx.content, /[?&](email|e-mail|ssn|phone|dob|password|pwd|token|access_token|api_key|card)=/gid, {
      sensitive: false, confidence: 0.7, nameGroup: 1,
      filter: () => isCodeLanguage(ctx) || ctx.language === 'shell',
    }),
  },

  // --------------------------- Unsafe data storage ---------------------------
  {
    id: 'CM-D001', title: 'Sensitive data in browser storage', category: 'storage', severity: 'high',
    description: 'Tokens, passwords, user profiles or card data written to localStorage / sessionStorage, readable by any script on the page.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      const re = /\b(localStorage|sessionStorage)\s*(?:\.setItem\(\s*["'`]([^"'`]+)["'`]|\.([A-Za-z_]\w*)\s*=(?!=)|\[\s*["'`]([^"'`]+)["'`]\s*\]\s*=(?!=))/gd
      const out: RawMatch[] = []
      for (const m of ctx.content.matchAll(re) as IterableIterator<RegExpExecArray>) {
        const key = m[2] ?? m[3] ?? m[4] ?? ''
        if (!/(token|jwt|auth|session|sess|password|passwd|pwd|secret|ssn|card|credit|api[_-]?key|apikey|refresh|bearer|cred|user|profile)/i.test(key)) continue
        const lineEnd = ctx.content.indexOf('\n', m.index)
        out.push({ start: m.index ?? 0, end: lineEnd < 0 ? ctx.content.length : lineEnd, sensitive: false, confidence: 0.85, name: key, note: `key "${key}"` })
      }
      return out
    },
  },
  {
    id: 'CM-D002', title: 'Weak password hashing (MD5/SHA-1)', category: 'storage', severity: 'critical',
    description: 'Passwords hashed with MD5 or SHA-1, which commodity GPUs crack at billions of guesses per second.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      const all = lines(ctx.content)
      return regexHits(ctx.content, /\b(createHash\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\b|md5\s*\(|sha1\s*\(|CryptoJS\.(?:MD5|SHA1)\b)/gid, {
        group: 1, sensitive: false, confidence: 0.85,
        filter: (_v, m) => {
          const lineIdx = ctx.content.slice(0, m.index).split('\n').length - 1
          const around = all.slice(Math.max(0, lineIdx - 2), lineIdx + 3).map((l) => l.text).join('\n')
          return /(pass|pwd|credential)/i.test(around)
        },
      })
    },
  },
  {
    id: 'CM-D003', title: 'Plaintext password storage', category: 'storage', severity: 'high',
    description: 'Passwords saved to a database or file as-is, or schema columns named password with a text type.',
    detect: (ctx) => {
      const out: RawMatch[] = []
      if (ctx.language === 'sql') {
        out.push(...regexHits(ctx.content, /\b(password|passwd|pwd)\s+(?:VARCHAR|TEXT|CHAR|NVARCHAR)\b[^,\n]*/gid, { sensitive: false, confidence: 0.8 }))
      }
      if (isCodeLanguage(ctx)) {
        for (const l of lines(ctx.content)) {
          const m = /\bpassword["']?\s*[:=]\s*(req(?:uest)?\.(?:body|json|form)(?:\.|\[["'])password|body\.password|data\[["']password["']\]|password\b(?!_?hash))/i.exec(l.text)
          if (!m) continue
          const ctxLines = lines(ctx.content).slice(Math.max(0, l.index - 3), l.index + 1).map((x) => x.text).join('\n')
          if (!/\b(insert|create|save|update|put|add|write|execute|push|set)\b/i.test(ctxLines)) continue
          out.push({ start: l.start + m.index, end: l.start + m.index + m[0].length, sensitive: false, confidence: 0.7 })
        }
      }
      return out
    },
  },
  {
    id: 'CM-D004', title: 'Hardcoded JWT / session secret', category: 'storage', severity: 'critical',
    description: 'Literal signing secrets passed to jwt.sign, express-session, Flask SECRET_KEY and friends. Whoever knows it can mint valid sessions.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      return [
        ...regexHits(ctx.content, /\bjwt\.(?:sign|verify)\([^,\n]+,\s*(["'`])([^"'`\n]{4,})\1/gd, { group: 2, confidence: 0.9 }),
        ...regexHits(ctx.content, /\b(jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret|SECRET_KEY|secretOrKey|signing[_-]?secret|secret_key)["'\]]?\s*[:=]\s*(["'`])([^"'`\n]{4,})\2/gid, { group: 3, nameGroup: 1, confidence: 0.88 }),
        ...regexHits(ctx.content, /\bsession\(\s*\{[^}]*?\bsecret\s*:\s*(["'`])([^"'`\n]+)\1/gd, { group: 2, confidence: 0.9 }),
      ].filter((h) => !ctx.content.slice(h.start, h.end).includes('${'))
    },
  },
  {
    id: 'CM-D005', title: 'Cookie missing HttpOnly / Secure / SameSite', category: 'storage', severity: 'medium',
    description: 'Session or auth cookies set without HttpOnly, Secure and SameSite, or written from client-side JavaScript.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      const out: RawMatch[] = []
      const js = ctx.language !== 'python'
      const re = js ? /\b(?:res|response|ctx|reply)\.(?:cookie|setCookie)\s*\(/g : /\.set_cookie\s*\(/g
      for (const m of ctx.content.matchAll(re)) {
        const start = m.index ?? 0
        const close = ctx.content.indexOf(js ? ');' : ')\n', start)
        const end = close < 0 ? Math.min(ctx.content.length, start + 300) : close + 1
        const call = ctx.content.slice(start, end)
        const missing = [
          !(js ? /httpOnly\s*:\s*true/i : /httponly\s*=\s*True/).test(call) && 'HttpOnly',
          !(js ? /secure\s*:\s*true/i : /secure\s*=\s*True/).test(call) && 'Secure',
          !(js ? /sameSite\s*:/i : /samesite\s*=/i).test(call) && 'SameSite',
        ].filter(Boolean)
        if (missing.length) out.push({ start, end: ctx.content.indexOf('\n', start) < 0 ? end : Math.min(end, ctx.content.indexOf('\n', start)), sensitive: false, confidence: 0.8, note: `missing ${missing.join(', ')}` })
      }
      if (js) {
        out.push(...regexHits(ctx.content, /document\.cookie\s*=\s*[^;\n]*(?:token|session|auth|jwt|sid)[^\n]*/gid, { sensitive: false, confidence: 0.85 })
          .map((h) => ({ ...h, note: 'set from JavaScript, so it can never be HttpOnly' })))
      }
      return out
    },
  },
  {
    id: 'CM-D006', title: 'Secrets or PII written to files', category: 'storage', severity: 'medium',
    description: 'fs.writeFile / appendFile / open().write calls that dump tokens, passwords or user records to disk in plaintext.',
    detect: (ctx) => {
      if (!isCodeLanguage(ctx)) return []
      const out: RawMatch[] = []
      const re = /\b(fs\.(?:writeFile|writeFileSync|appendFile|appendFileSync)|createWriteStream|\w+\.write)\s*\(/g
      for (const l of lines(ctx.content)) {
        for (const m of l.text.matchAll(re)) {
          if (/^(res|response|reply|process\.stdout|sys\.stdout)\.write$/.test(m[1]!)) continue
          const args = codeParts(l.text.slice((m.index ?? 0) + m[0].length))
          const hit = /\b(passwords?|passwd|secrets?|tokens?|api_?key|apiKey|ssn|credit\w*|card\w*|users?|customers?|patients?|emails?)\b/i.exec(args)
          if (!hit) continue
          out.push({ start: l.start + (m.index ?? 0), end: l.start + l.text.trimEnd().length, sensitive: false, confidence: 0.65, note: `writes \`${hit[0]}\`` })
        }
      }
      return out
    },
  },
  {
    id: 'CM-D007', title: 'TLS certificate verification disabled', category: 'storage', severity: 'high',
    description: 'rejectUnauthorized: false, verify=False, NODE_TLS_REJECT_UNAUTHORIZED=0, curl -k and similar. Data in transit can be intercepted.',
    detect: (ctx) => regexHits(ctx.content, /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\]?\s*[=:]\s*["']?0|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|strictSSL\s*:\s*false|\bcurl\b[^\n]*\s(?:-k|--insecure)\b/gd, { sensitive: false, confidence: 0.9 }),
  },
  {
    id: 'CM-D008', title: '.env file not covered by .gitignore', category: 'storage', severity: 'high',
    description: 'A .env file exists but no .gitignore rule excludes it, so the next `git add .` publishes every secret in it.',
    detect: (ctx) => {
      if (!isEnvFile(ctx.path) || isEnvTemplate(ctx.path) || ctx.project.length < 2) return []
      const { covered, hasGitignore } = coveredByGitignore(ctx.path, ctx.project)
      if (covered) return []
      const firstLineEnd = ctx.content.indexOf('\n')
      return [{ start: 0, end: firstLineEnd < 0 ? ctx.content.length : firstLineEnd, sensitive: false, confidence: hasGitignore ? 0.9 : 0.8, note: hasGitignore ? 'no matching .gitignore rule' : 'no .gitignore in project' }]
    },
  },
]

export const RULE_META: RuleMeta[] = RULES.map(({ detect: _detect, ...meta }) => meta)
export const RULE_BY_ID: Record<string, RuleMeta> = Object.fromEntries(RULE_META.map((r) => [r.id, r]))
