# Detection evaluation

`eval/corpus/` is a labeled set of realistic vulnerable and safe code for every rule in
`rules/catalog.json`: Python, JavaScript, TypeScript/TSX, SQL, shell, YAML and dotenv. Lines
that should produce a finding carry an `expect: CM-XXXX` comment. Every other line is a
negative, so any finding on it counts as a false positive. The safe samples include tricky
lookalikes: parameterized queries, sanitized `innerHTML`, `shell=True` with a constant command,
`yaml.load(..., Loader=SafeLoader)`, TS type annotations named `ssn`, env-var names in string
values, and so on. Cases marked `fp-fixed` were false positives in the original rule set that
this work removed (see below).

```bash
backend/.venv/bin/python eval/run_eval.py                    # both engines (frontend needs Node)
backend/.venv/bin/python eval/run_eval.py --engine backend
backend/.venv/bin/python eval/run_eval.py --json
```

The frontend engine is the real browser code (`frontend/src/lib`), run under Node by
`frontend/scripts/scan-folder.ts` through the same intake -> scan path the folder upload uses.

## Thresholds (the script exits 1 below these)

| Measure | Threshold | Why |
| --- | --- | --- |
| Overall precision, per engine | >= 0.95 | False positives erode trust fastest, so keep them rare. |
| Overall recall, per engine | >= 0.95 | The corpus covers each pattern a rule claims to detect. |
| Per-rule precision and recall | >= 0.80 | No single rule may be badly broken behind a good average. |
| Coverage | every catalog rule has at least one positive sample | A rule with no sample is untested. |

## Results (2026-10-24)

30 files, 108 labeled positives, 49 rules. Both engines: **TP 108, FP 0, FN 0, precision 1.000,
recall 1.000**, every rule at 1.00/1.00.

These numbers are optimistic. The corpus was written by the same person, at the same time, as the
rules, so it works as a regression suite, not an independent benchmark. Expect lower numbers on
code in the wild, especially for flows that cross functions or files (taint tracking is
intra-function and one-pass). Add any real-world miss or false alarm to the corpus.

## False positives found and fixed

| Rule | Before | Now |
| --- | --- | --- |
| CM-J003 | Any template literal containing SELECT passed to `query()`, even with no `${}` | Requires interpolation of a non-constant |
| CM-A001 | Interpolating an UPPER_CASE constant (`{TABLE}`); a `query` variable built dynamically in another function | Constants ignored; variable tracking is per function and uses the latest assignment |
| CM-A002 | `subprocess.run("ls -la", shell=True)` with a constant command | Needs a non-constant command |
| CM-J002 | `/regex/.exec(a + b)` (RegExp.exec) | Needs `child_process` in the file and a bare or `child_process.` exec |
| CM-J001 | `el.innerHTML = DOMPurify.sanitize(html)`, literal strings, empty string | Only unsanitized, non-literal values |
| CM-A007 | Any `open(path)` where a variable was named path/user/input | Needs request data to reach the path, without a containment check or `secure_filename` |
| CM-S014 | `"token_expired"`, `"GITHUB_TOKEN"` (env-var name), `"password-input"` | Word identifiers and env-var names skipped; non-password values need letters and digits |
| CM-S001-S010 | `AKIAXXXXXXXXXXXXXXXX`, `sk-xxxx...` templates | Template placeholders skipped |
| CM-D001 | `localStorage.setItem('userPrefersDark', ...)` | Key matcher tightened; a value check catches `setItem('data', JSON.stringify(user))` |
| CM-P006 / CM-D006 | (backend only) words inside string literals, e.g. `console.log('loaded users', data)` | Backend now ignores literal text, as the frontend already did |
| CM-P008 | `type User = { ssn: string }` (TS annotation) | Schema type tokens are case-sensitive |
| CM-D005 / CM-J005 | Semicolon-less JS: read the next statement's options / `verify` | Call is bounded by matching parentheses / the end of the line |

## Deliberate deviation

Known-format key rules (AWS, GitHub, Stripe...) skip template placeholders (`YOUR_...`, `xxxx`,
`<...>`, `changeme`). They do **not** skip values just because they contain the word "example":
AWS's documented `AKIAIOSFODNN7EXAMPLE` is structurally valid and is what the bundled demo and
the existing tests use. The generic entropy rule (CM-S014) does skip "example" values.
