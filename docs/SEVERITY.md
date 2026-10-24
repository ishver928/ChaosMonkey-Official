# Severity rubric

Each rule in `rules/catalog.json` has exactly one severity. That severity is what both the
in-browser scanner and the backend report for every finding of that rule. The backend's numeric
`severity_score` (0-10) is kept for ordering and explanation, but it is always clamped into the
band of the rule's severity, so the label and the number cannot disagree.

| Severity | Band (score) | Use it when the issue, as written, typically lets an attacker... |
| --- | --- | --- |
| **critical** | 9.0 - 10.0 | ...run code on the server, read or alter the whole database, or use a working high-value credential (cloud, payments, source control, signing keys), **without** special preconditions. |
| **high** | 7.0 - 8.9 | ...compromise accounts or regulated personal data, but with one precondition such as a victim clicking a link (XSS), a network position (TLS off), or a prior data leak (weak password hashing is the deliberate exception below). |
| **medium** | 4.0 - 6.9 | ...weaken a defense or learn limited information. These usually need chaining with another bug (cookie flags, permissive CORS without credentials, debug configuration, DOB in fixtures). |
| **low** | 1.0 - 3.9 | ...cause a hygiene or privacy issue with little direct impact (an email address or phone number in source). |

Notes and deliberate choices:

- Severity rates the **pattern**, not your deployment. Static analysis can't see whether
  a route is public, so it assumes the code is reachable.
- `CM-D002` (MD5/SHA-1 password hashing) stays **critical**, as the original rule set had it.
  A database leak turns into mass account takeover within hours, and password reuse spreads it
  to other sites.
- `CM-A003` (eval/exec on a non-literal) is **high**, not critical, because the rule can't prove
  the argument is attacker-controlled.
- `CM-C004` (wildcard CORS) is **medium**. When credentials are also enabled, `CM-J004`
  (**high**) fires instead and replaces it on that line.
- `CM-A006` (requests `verify=False`, AST-confirmed) and `CM-D007` (regex, any language) can
  both fire on the same Python line. Both are kept on purpose: existing reports, tests and Chaos
  Mode depend on each id. They have the same severity, so the rating does not change.

The numeric score starts from a per-CWE base value (`backend/app/pipeline/severity.py`), adds
small modifiers (live-format credential, confirmed by two methods, directly exploitable class),
and is then clamped into the band above.
