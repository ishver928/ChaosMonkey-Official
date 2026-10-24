"""Deterministic mock LLM analyzer for tests and offline demos (LLM_MOCK=1).

Produces LLM-style findings in the same JSON shape the real model is prompted for, but
with zero network use and byte-identical output for identical input. Findings are grounded
in the actual code: each ``evidence_snippet`` is a verbatim line from the chunk, so the
evidence validator passes them (and a deliberately planted hallucination is included only
when ``CHAOS_MOCK_HALLUCINATE`` patterns are present, to exercise rejection in tests).
"""

from __future__ import annotations

import re

# (regex, cwe_id, title, explanation, attack, fix) — ordered, deterministic.
_PATTERNS: list[tuple[re.Pattern[str], str, str, str, str, str]] = [
    (re.compile(r".*\.execute\s*\(.*(\+|%|format|f[\"']).*", re.I), "CWE-89", "SQL injection",
     "User input is concatenated into a SQL statement passed to execute().",
     "An attacker submits ' OR '1'='1 to bypass authentication or dump the table via UNION.",
     "Use a parameterized query with placeholders instead of string building."),
    (re.compile(r".*(os\.system|subprocess).*(\+|shell\s*=\s*True).*", re.I), "CWE-78", "OS command injection",
     "A shell command is built from untrusted input.",
     "An attacker injects `; rm -rf /` or `$(curl evil)` to run arbitrary commands.",
     "Pass an argument list and shell=False; validate the input."),
    (re.compile(r".*(hashlib\.(md5|sha1)|createHash\([\"'](md5|sha1)).*", re.I), "CWE-328", "Weak password hash",
     "Passwords are hashed with a fast, broken algorithm.",
     "Leaked hashes are cracked offline at billions of guesses per second.",
     "Use bcrypt/scrypt/argon2 with a per-user salt."),
    (re.compile(r".*\b(eval|exec)\s*\(.*", re.I), "CWE-94", "Code injection via eval",
     "Dynamic input is evaluated as code.",
     "An attacker supplies an expression that executes arbitrary code.",
     "Never eval input; use a safe parser such as ast.literal_eval / JSON.parse."),
    (re.compile(r".*\.innerHTML\s*=.*(\+|\$\{).*", re.I), "CWE-79", "DOM-based XSS",
     "A variable is written into innerHTML without escaping.",
     "An attacker stores <img src=x onerror=...> to run script in a victim's browser.",
     "Use textContent or sanitize the HTML before insertion."),
    (re.compile(r".*verify\s*=\s*False.*", re.I), "CWE-295", "TLS verification disabled",
     "Certificate verification is turned off for an HTTPS request.",
     "A network attacker performs a man-in-the-middle and reads/alters the traffic.",
     "Remove verify=False so certificates are validated."),
    (re.compile(r".*(debug\s*=\s*True).*", re.I), "CWE-489", "Debug mode enabled",
     "The web framework runs with the interactive debugger enabled.",
     "An attacker triggers an error to reach the console and execute code on the server.",
     "Set debug=False in any shipped configuration."),
    (re.compile(r".*(jwt\.decode|algorithms?\s*:\s*\[[^\]]*none).*", re.I), "CWE-347", "JWT not verified",
     "A JWT is decoded without verifying its signature (or alg:none is accepted).",
     "An attacker forges a token with an admin claim and is trusted.",
     "Use jwt.verify with an explicit algorithm allowlist."),
    (re.compile(r".*(api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}[\"'].*", re.I), "CWE-798", "Hard-coded credential",
     "A secret is embedded directly in the source.",
     "Anyone with repo access uses the key to run up charges or access data.",
     "Load the secret from an environment variable and rotate the leaked value."),
]


def mock_analyze(content: str, cwe_context: list[dict] | None = None) -> dict:
    findings = []
    lines = content.split("\n")
    seen: set[tuple[str, int]] = set()
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rx, cwe, title, expl, attack, fix in _PATTERNS:
            if rx.match(line):
                key = (cwe, idx)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "cwe_id": cwe,
                    "title": title,
                    "line_start": idx,
                    "line_end": idx,
                    "evidence_snippet": stripped,
                    "explanation": expl,
                    "attack_scenario": attack,
                    "confidence": 0.7,
                    "suggested_fix": fix,
                })
                break
    return {"findings": findings}
