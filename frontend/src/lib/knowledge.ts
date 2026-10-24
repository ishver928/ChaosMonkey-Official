import type { Finding } from './types'

/*
 * The "Built-in analyst": a hand-written knowledge base per rule plus fix templates that rewrite the
 * finding's (masked) line into a safer version. Deterministic and fully offline.
 */

export interface Fix { before: string; after: string; language: string; note?: string }
export interface Advice { why: string; steps: string[]; fix: Fix }

export const ROTATE_STEP = 'Rotate this credential now. Deleting it from code doesn’t un-leak it: it’s already in git history, CI logs, and any clone or AI context window that saw it.'

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function isPython(f: Finding) { return f.language === 'python' }
function isFrontend(f: Finding) { return /\.(tsx|jsx)$/.test(f.file) || /(^|\/)(src\/components|public|client|web)\//.test(f.file) }
function fileLang(f: Finding): string {
  if (f.language === 'env') return 'dotenv'
  return f.language
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

function secretFix(f: Finding, line: string): Fix {
  const name = toEnvName(assignedName(f, line), SECRET_DEFAULT_ENV[f.ruleId] ?? 'API_SECRET')
  const envName = f.ruleId === 'CM-S011' ? 'DATABASE_URL' : /^(CONFIG|KEY|TOKEN|SECRET|STRIPE|CLIENT)$/.test(name) ? (SECRET_DEFAULT_ENV[f.ruleId] ?? name) : name
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
  const needle = f.ruleId === 'CM-S011' ? 'postgres' : f.maskedValue.split('\n')[0] ?? ''
  if (f.ruleId === 'CM-S011') {
    const after = line.replace(/\s*\|\|\s*(["'`])[^"'`]*\1/, '').replace(/(["'`])[a-z+]+:\/\/[^"'`]*\1/, envRef(f, 'DATABASE_URL'))
    return { language: fileLang(f), before: line, after }
  }
  if (isFrontend(f) && f.language !== 'python') {
    return {
      language: fileLang(f), before: line,
      after: `// Never ship this to the browser. Anything in the bundle is public.\n// Call your own API route and keep ${envName} on the server:\nconst res = await fetch('/api/proxy', { credentials: 'include' })`,
      note: 'import.meta.env.VITE_* is still bundled into client JS, so it is not a fix for secrets.',
    }
  }
  const pyImport = isPython(f) ? 'import os\n\n' : ''
  return { language: fileLang(f), before: line, after: `${pyImport}${replaceLiteral(line, needle, envRef(f, envName))}` }
}

function redactArgs(f: Finding, line: string): string {
  const pyInterp = /\{([^{}]*(?:user|email|ssn|password|dob|phone|card)[^{}]*)\}/gi
  if (isPython(f)) return line.replace(pyInterp, (_m, e: string) => (/\[["'](email|ssn|password|dob|phone|card)["']\]/i.test(e) ? `{user['id']}` : `{redact(${e})}`))
  if (line.includes('${')) return line.replace(/\$\{([^}]+)\}/g, (m, e: string) => (/(user|email|ssn|password|dob|phone|card)/i.test(e) ? `\${redact(${e})}` : m))
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

function fixFor(f: Finding, line: string): Fix {
  const lang = fileLang(f)
  if (f.ruleId === 'CM-S007' && !isPython(f) && f.language !== 'env' && f.language !== 'shell') {
    return {
      language: lang, before: line,
      after: replaceLiteral(line, f.maskedValue, 'import.meta.env.VITE_GOOGLE_MAPS_KEY'),
      note: 'Maps browser keys end up public by design, so the real fix is in Google Cloud Console: restrict the key to your domains and to the Maps APIs only.',
    }
  }
  switch (f.ruleId) {
    case 'CM-S009':
      return { language: lang, before: line, after: isPython(f) ? 'PRIVATE_KEY = open(os.environ["PRIVATE_KEY_PATH"]).read()' : 'export const SAML_PRIVATE_KEY = fs.readFileSync(process.env.SAML_PRIVATE_KEY_PATH, \'utf8\')', note: 'Mount the key from a secret manager or a file outside the repo.' }
    case 'CM-S013':
      return { language: 'shell', before: `# ${f.file}\n${line}`, after: 'git rm --cached .env\necho ".env" >> .gitignore\ncp .env .env.example   # then blank every value in .env.example\ngit commit -m "Stop tracking .env"', note: 'If the repo was ever pushed, also purge it from history (git filter-repo) and rotate every value.' }
    case 'CM-D008':
      return { language: 'gitignore', before: '# .gitignore\nnode_modules/\ndist/', after: '# .gitignore\nnode_modules/\ndist/\n.env\n.env.*\n!.env.example' }
    case 'CM-P001':
      return { language: lang, before: line, after: line.replace(f.maskedValue, 'user1@example.test'), note: 'Use reserved test domains (example.test) or generate fixtures with a faker library.' }
    case 'CM-P002':
      return { language: lang, before: line, after: line.replace(f.maskedValue, '(555) 010-0000'), note: '555-01xx numbers are reserved for fiction and testing.' }
    case 'CM-P003':
      return { language: lang, before: line, after: line.replace(f.maskedValue, '000-00-0000'), note: 'Area 000 is never issued, so it can’t belong to a real person. Better: don’t store SSNs at all.' }
    case 'CM-P004':
      return { language: lang, before: line, after: /^\s*(\/\/|#)/.test(line) ? line.replace(f.maskedValue, 'Stripe test card (see their docs)') : line.replace(f.maskedValue, 'tok_visa'), note: 'Never store PANs. Use your processor’s tokens; that keeps you out of PCI scope.' }
    case 'CM-P005':
      return { language: lang, before: line, after: line.replace(f.maskedValue, '1970-01-01') }
    case 'CM-P006':
      return { language: lang, before: line, after: `${isPython(f) ? REDACT_HELPER_PY : REDACT_HELPER_JS}\n\n${redactArgs(f, line)}` }
    case 'CM-P007': {
      const keys = [...line.matchAll(/[?&](\w+)=/g)].map((m) => m[1]).join(', ')
      const after = line.replace(/\?[^`'"]*(?=[`'"])/, '')
      return { language: lang, before: line, after: `${after}\n  // send ${keys || 'it'} in the body instead:\n  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ${keys} }),` }
    }
    case 'CM-D001': {
      const userish = /user|profile/i.test(f.name ?? '') && !/token|auth|session/i.test(f.name ?? '')
      return userish
        ? { language: lang, before: line, after: 'sessionStorage.setItem(\'userId\', String(user.id))  // ids only; fetch the profile when needed' }
        : { language: lang, before: line, after: '// Server side, after login:\nres.cookie(\'session\', token, { httpOnly: true, secure: true, sameSite: \'lax\' })\n\n// Client side: no storage at all, just send cookies\nfetch(\'/api/todos\', { credentials: \'include\' })', note: 'HttpOnly cookies are invisible to JavaScript, so an XSS bug can’t read the token.' }
    }
    case 'CM-D002':
      return isPython(f)
        ? { language: lang, before: line, after: line.replace(/hashlib\.(?:md5|sha1)\([^)]*\)(?:\.hexdigest\(\))?/, 'bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))') }
        : { language: lang, before: line, after: line.replace(/crypto\.createHash\(\s*["'](?:md5|sha1)["']\s*\)(?:\.update\([^)]*\))?(?:\.digest\([^)]*\))?/, 'await bcrypt.hash(password, 12)'), note: 'Compare with bcrypt.compare(password, user.passwordHash). argon2id is an equally good choice.' }
    case 'CM-D003':
      return f.language === 'sql'
        ? { language: lang, before: line, after: line.replace(/\b(password|passwd|pwd)\s+(?:VARCHAR|TEXT|CHAR|NVARCHAR)(\(\d+\))?/i, 'password_hash TEXT') + '  -- bcrypt / argon2id hash, never the password' }
        : { language: lang, before: line, after: line.replace(/password["']?\s*[:=]\s*[^,}\n]+/i, 'passwordHash: await bcrypt.hash(password, 12)') }
    case 'CM-D004':
      return secretFix({ ...f, name: f.name ?? (line.includes('session(') ? 'SESSION_SECRET' : 'JWT_SECRET') }, line)
    case 'CM-D005': {
      if (/document\.cookie/.test(line)) {
        return { language: lang, before: line, after: '// Don’t set auth cookies from the browser. Server side instead:\nres.cookie(\'admin_session\', token, { httpOnly: true, secure: true, sameSite: \'strict\', path: \'/\' })' }
      }
      if (isPython(f)) return { language: lang, before: line, after: line.replace(/\)\s*$/, ', httponly=True, secure=True, samesite="Lax")') }
      const after = /\{/.test(line)
        ? line.replace(/\{\s*/, '{ httpOnly: true, secure: true, sameSite: \'lax\', ')
        : line.replace(/\)\s*;?\s*$/, ', { httpOnly: true, secure: true, sameSite: \'lax\' })')
      return { language: lang, before: line, after }
    }
    case 'CM-D006': {
      const word = /`([^`]+)`/.exec(f.note ?? '')?.[1] ?? 'user'
      const after = line.replace(new RegExp(`\\b${esc(word)}\\b(?![\\w'"])`), `redact(${word})`)
      return { language: lang, before: line, after: `${isPython(f) ? REDACT_HELPER_PY : REDACT_HELPER_JS}\n\n${after}`, note: 'If you truly need the record on disk, encrypt it and give the file 0600 permissions.' }
    }
    case 'CM-D007':
      if (/NODE_TLS_REJECT_UNAUTHORIZED/.test(line)) return { language: lang, before: line, after: '// Removed. Trust your internal CA explicitly instead:\n//   NODE_EXTRA_CA_CERTS=/etc/ssl/internal-ca.pem node server/index.js' }
      if (/rejectUnauthorized/.test(line)) return { language: lang, before: line, after: line.replace(/rejectUnauthorized\s*:\s*false/, 'ca: fs.readFileSync(process.env.DB_CA_CERT_PATH)') }
      if (/verify\s*=\s*False/.test(line)) return { language: lang, before: line, after: line.replace(/verify\s*=\s*False/, 'verify="/etc/ssl/certs/internal-ca.pem"') }
      if (/curl/.test(line)) return { language: lang, before: line, after: line.replace(/\s(?:-k|--insecure)\b/, ' --cacert ./certs/internal-ca.pem') }
      return { language: lang, before: line, after: '// Verify certificates; pin a CA bundle if you use a private CA.' }
    default:
      return secretFix(f, line)
  }
}

interface Entry { why: string; steps: string[] }

const KB: Record<string, Entry> = {
  'CM-S001': { why: 'Bots scrape public repos for AKIA keys within minutes of a push. With the matching secret, an attacker spins up GPU instances in every region and you find out from a five-figure bill, or they quietly copy your S3 buckets.', steps: ['Deactivate the key in IAM, then create a new one.', 'Load credentials from the environment or an IAM role, never from source.', 'Check CloudTrail for activity from this key ID since it was committed.'] },
  'CM-S002': { why: 'The secret half of an AWS key pair is what actually signs requests. Anyone holding it can act as that IAM user: read databases, delete backups, or mine crypto on your account.', steps: ['Delete the access key in IAM and issue a new one.', 'Prefer short-lived credentials (SSO, instance roles) over long-lived keys.', 'Review CloudTrail for unfamiliar API calls.'] },
  'CM-S003': { why: 'A GitHub token can clone private repos, push malicious commits, or edit CI workflows to steal more secrets. Supply-chain attacks often start with exactly one leaked token.', steps: ['Revoke the token under Settings → Developer settings.', 'Use fine-grained tokens with a single repo and an expiry.', 'Audit recent pushes and workflow changes.'] },
  'CM-S004': { why: 'A live Stripe secret key can issue refunds to attacker-controlled cards, read customer billing details, and create charges. Stripe will freeze the account, but money that has already moved is gone.', steps: ['Roll the key in the Stripe dashboard (Developers → API keys).', 'Keep it server-side only, loaded from the environment.', 'Use restricted keys (rk_) with the minimum permissions.'] },
  'CM-S005': { why: 'Leaked LLM keys get resold and drained fast: someone runs millions of tokens through your account overnight, and your usage limit is the only brake.', steps: ['Revoke the key in the provider dashboard.', 'Proxy LLM calls through your server; never ship keys to the browser.', 'Set a hard monthly spend limit.'] },
  'CM-S006': { why: 'An Anthropic key lets anyone bill API usage to your organization and see whatever prompts they send under your name. Automated scanners look for the sk-ant- prefix specifically.', steps: ['Disable the key in the Anthropic Console and create a new one.', 'Read it from ANTHROPIC_API_KEY on the server.', 'Set workspace spend limits.'] },
  'CM-S007': { why: 'Unrestricted Google API keys get abused for Maps, Places or Gemini calls billed to you. Firebase keys with loose rules can also expose your database.', steps: ['Restrict or regenerate the key in Google Cloud Console.', 'Apply HTTP referrer and API restrictions.', 'Move server-side keys to the environment.'] },
  'CM-S008': { why: 'A Slack bot token can read every channel the bot is in and post messages as your app. That makes it a perfect phishing launchpad inside your own workspace.', steps: ['Revoke the token from the Slack app settings.', 'Reinstall the app to issue a fresh token.', 'Store it in your CI or host secret store.'] },
  'CM-S009': { why: 'A private key is identity. With it an attacker can sign SAML assertions, impersonate your server over TLS, or SSH into machines that trust it, and nothing in the logs looks wrong.', steps: ['Generate a new key pair and replace the public key everywhere it’s trusted.', 'Load private keys from a secret manager or a mounted file outside the repo.', 'Revoke any certificates issued for the old key.'] },
  'CM-S010': { why: 'A JWT is a bearer credential: whoever holds it is that user until it expires. Hardcoded tokens tend to be long-lived admin tokens, which turns a leak into instant admin access.', steps: ['Invalidate the token (rotate the signing key if you can’t revoke individually).', 'Obtain tokens at runtime through a real login flow.', 'Keep token lifetimes short.'] },
  'CM-S011': { why: 'A connection string with the password inside gives direct database access, skipping your API and its auth checks. One leaked URL is a full dump of your users table.', steps: ['Change the database user’s password.', 'Read DATABASE_URL from the environment, with no fallback literal.', 'Restrict database network access to your app servers.'] },
  'CM-S012': { why: 'A hardcoded Bearer token works for anyone who copies it. These usually end up in screenshots, gists and AI chat logs long before anyone notices.', steps: ['Revoke the token at its issuer.', 'Fetch tokens at runtime from a secret store or login flow.'] },
  'CM-S013': { why: 'A committed .env file is every secret in your project gathered in one place. Even after you delete it, it lives on in git history and in every fork and clone.', steps: ['Stop tracking it: git rm --cached .env.', 'Add .env to .gitignore and commit a .env.example with blank values.', 'If it was ever pushed, purge history with git filter-repo and rotate everything in it.'] },
  'CM-S014': { why: 'This value is high-entropy and assigned to a name like key, secret or password, which is the signature of a real credential. Attackers grep for exactly these patterns.', steps: ['Confirm what the value is; if it’s live, rotate it.', 'Move it to an environment variable or secret manager.', 'If it’s a test fixture, use an obvious placeholder.'] },
  'CM-P001': { why: 'Real email addresses in source end up in public repos, AI training sets and spam lists. Under GDPR/CCPA they count as personal data, so a leak can be a reportable incident.', steps: ['Replace with reserved test domains (example.test).', 'Generate fixtures at test time instead of committing real people.'] },
  'CM-P002': { why: 'Phone numbers enable SIM-swap and phishing attacks, and they’re regulated personal data. Fixtures copied from production are a common source of leaks.', steps: ['Use 555-01xx fictional numbers in fixtures.', 'Keep production data out of the repo.'] },
  'CM-P003': { why: 'An SSN plus a name and date of birth is enough to open credit in someone’s name. Exposing one usually triggers breach-notification laws in most US states.', steps: ['Remove it and purge it from history.', 'Avoid storing SSNs at all; if you must, encrypt the field and limit access.', 'Use obviously invalid values (000-xx-xxxx) in tests.'] },
  'CM-P004': { why: 'Storing card numbers puts your whole system in PCI DSS scope. A real PAN in code or logs is a reportable cardholder-data exposure.', steps: ['Delete it and use processor tokens (tok_visa) instead.', 'Never log or persist full card numbers.'] },
  'CM-P005': { why: 'Date of birth is a classic identity-verification answer. Combined with a name or email it makes account-recovery attacks much easier.', steps: ['Use synthetic dates in fixtures.', 'Store age brackets instead of full DOB when you can.'] },
  'CM-P006': { why: 'Logs get shipped to third-party services, kept for months, and read by far more people than your database. An email or SSN in a log line is a quiet, long-lived leak.', steps: ['Log IDs, not people: user.id instead of the user object.', 'Add a redaction helper and use it in every logger call.', 'Purge existing logs that contain personal data.'] },
  'CM-P007': { why: 'Query strings land in server access logs, proxy logs, browser history and Referer headers sent to other sites. A password in a URL is effectively public.', steps: ['Send sensitive fields in a POST body over HTTPS.', 'Scrub query strings from existing logs.'] },
  'CM-D001': { why: 'localStorage is readable by any script on the page. One XSS bug or one compromised npm package can read the token and replay it from anywhere, and it never expires on its own.', steps: ['Have the server set an HttpOnly, Secure, SameSite cookie.', 'Send requests with credentials: \'include\' instead of reading the token in JS.', 'Store only non-sensitive IDs client-side.'] },
  'CM-D002': { why: 'MD5 and SHA-1 are fast by design, so a single GPU tests billions of guesses per second. If the users table leaks, most passwords are cracked the same afternoon and reused on other sites.', steps: ['Switch to bcrypt (cost 12+) or argon2id.', 'Re-hash on next login, and force a reset for accounts that don’t log in.', 'Never hash passwords with a general-purpose digest.'] },
  'CM-D003': { why: 'Plaintext passwords mean one SQL injection or backup leak exposes every user’s password, and with it their accounts on other sites where they reused it.', steps: ['Store only a bcrypt/argon2id hash, in a column named for what it holds.', 'Migrate existing rows and force resets.'] },
  'CM-D004': { why: 'Whoever knows the signing secret can mint a valid session for any user, including admins, without a password. Copy-pasted tutorial defaults are the first values attackers try.', steps: ['Generate a long random secret (openssl rand -base64 48) and keep it in the environment.', 'Rotate it, which logs everyone out.', 'Never fall back to a literal default.'] },
  'CM-D005': { why: 'Without HttpOnly, any XSS can read the session cookie. Without Secure it travels over plain HTTP, and without SameSite it rides along on cross-site requests (CSRF).', steps: ['Set httpOnly: true, secure: true and sameSite: \'lax\' (or \'strict\').', 'Set auth cookies server-side only.'] },
  'CM-D006': { why: 'Files on disk get backed up, synced and copied with far less care than your database. A plaintext dump of users or tokens is a breach waiting for one misconfigured bucket.', steps: ['Redact sensitive fields before writing.', 'Encrypt at rest and restrict file permissions.', 'Delete old dumps.'] },
  'CM-D007': { why: 'Turning off certificate checks means anyone on the network path (coffee-shop Wi-Fi, a compromised router) can read and alter traffic, including database credentials and user data.', steps: ['Fix the certificate or trust your private CA explicitly.', 'Never ship verify=False / rejectUnauthorized: false to production.'] },
  'CM-D008': { why: 'Without a .gitignore rule, the next "git add ." quietly commits every secret in .env. AI coding agents run that command constantly.', steps: ['Add .env and .env.* to .gitignore (with !.env.example).', 'Check git history for past commits of the file.'] },
}

export function adviceFor(f: Finding, fullLine?: string): Advice {
  const entry = KB[f.ruleId] ?? { why: 'This pattern is commonly associated with security incidents.', steps: ['Review the code and remove the sensitive value.'] }
  const line = (fullLine ?? f.snippet).replace(/\s+$/, '')
  const steps = f.ruleId === 'CM-S013' ? [...entry.steps, ROTATE_STEP] : f.category === 'secrets' || f.ruleId === 'CM-D004' ? [ROTATE_STEP, ...entry.steps] : [...entry.steps]
  return { why: entry.why, steps, fix: fixFor(f, line) }
}
