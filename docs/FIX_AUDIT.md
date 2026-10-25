# Fix audit

Every suggested fix (backend patches, frontend built-in analyst, catalog examples) is now
checked by `backend/tests/test_fix_syntax.py`. Each fix is applied to its real file with any
imports it needs, then parsed: `ast.parse` for Python, `node --check` for JavaScript, the
TypeScript parser for TS/TSX. Sources: the eval corpus, the demo apps, `tests/fixtures/fixes`
(bcrypt cases) and the bundled frontend demo project.

## Reproduction (before the fix), 2026-10-24

The original frontend analyst (`main`), run through the same in-context check: **13 of 64
fixes did not parse.**

- **CM-D002, Python (the broken bcrypt fix):**
  `return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))).hexdigest()` has an
  unmatched `)`. The regex `hashlib.md5\([^)]*\)` stopped at the `)` of `password.encode()`.
  This also hit the bundled `flask_store` demo.
- **CM-D002, Node:** `return await bcrypt.hash(password, 12)` inside a non-async function is a
  SyntaxError. In async code the login check became
  `user.passwordHash !== await bcrypt.hash(...)`, which is never equal because bcrypt salts, so
  nobody could log in.
- **CM-D003, Python file:** emitted JavaScript (`"passwordHash: await bcrypt.hash(...)`).
- **CM-P006 / CM-D006, Python:** a column-0 helper pasted into an indented block
  (IndentationError).
- **CM-S009:** replaced the first line of a multi-line PEM string, leaving an unterminated
  literal.
- **CM-P007:** appended a dangling `method: 'POST', ...` object fragment after the call.
- **CM-D007, Python:** a `//` comment inserted into Python.
- **Rules without templates** (all `CM-A*`/`CM-J*` and new rules) fell through to the
  *secret* template, producing unrelated `process.env` suggestions.

The original backend generator had the same bcrypt problems. It replaced the whole line with
`bcrypt.hashpw(...)  # was MD5/SHA-1`, which dropped `return` and assignments, never added
`import bcrypt`, and turned password *verification* into a fresh salted hash. In non-async JS it
inserted `await` (a SyntaxError). Its SQLi and command-injection "fixes" were only comments, so
the vulnerability remained.

## After

`test_fix_syntax.py` reports 0 failures (5 tests). Every diff the backend shows is verified:
it parses and the finding is gone on re-scan. A patch that fails either check is not shown at
all, and the catalog example is offered instead.

## Security review of each fix family

| Area | Fix now suggested |
| --- | --- |
| Password hashing (D002/D003) | Python: `bcrypt.hashpw(pw.encode(), bcrypt.gensalt())`, verification with `bcrypt.checkpw(pw.encode(), stored.encode())`. Node: `bcryptjs` with `await bcrypt.hash(pw, 12)` / `await bcrypt.compare(pw, hash)`; the enclosing function is made `async` and callers are told to await. Two-step verify code (`h = md5(pw); if stored == h`) becomes a single `checkpw`/`compare`. argon2id is named as an alternative. No MD5/SHA-1 anywhere. |
| SQL injection (A001/J003) | Parameterized queries with the driver's placeholder style (`?`, `%s`, `$1`). Quotes and `LIKE` wildcards move into the parameter. Table names held in UPPER_CASE constants stay interpolated. |
| Secrets (S0xx/D004) | Read from the environment (`os.environ[...]` / `process.env.*`), **plus "rotate the exposed key"** in the steps and patch note. Browser code gets "move it server-side" instead (a `VITE_` env var is still public). |
| Deserialization (A004/J007) | `yaml.safe_load`; `json` / `JSON.parse` instead of pickle or node-serialize. |
| Command injection (A002/J002) | `subprocess.run([...], shell=False)` / `execFile(cmd, [args])`. Commands containing shell metacharacters are not auto-rewritten. |
| XSS (A008/J001/J006) | `markupsafe.escape`, `textContent`, or `DOMPurify.sanitize`; an `escapeHtml` helper for Express. |
| Browser storage / cookies (D001/D005) | HttpOnly + Secure + SameSite cookies set by the server, not localStorage. Only missing cookie flags are added, so keyword arguments are never duplicated. |
| TLS (D007/A006) | Verification back on; a private CA via `ca:` / `verify="/path/ca.pem"` / `NODE_EXTRA_CA_CERTS`. |
| Debug / CORS (A005/C003/C004/J004) | Debug reads an env flag that defaults to off. CORS uses an explicit origin allowlist from `ALLOWED_ORIGINS`. |
| Weak ciphers / randomness (C001/C002) | AES-GCM with a random nonce; `secrets` / `crypto.randomBytes`. |
