"""Extended JS/TS regex detectors (CM-J0xx) beyond the ported CM-* set.

innerHTML/dangerouslySetInnerHTML with variables, child_process.exec with input,
string-concatenated SQL, CORS ``*`` with credentials, and JWT used without verification.
"""

from __future__ import annotations

import re

from .common import DetectContext, RawMatch

JS_RULES = {
    "CM-J001": ("DOM XSS via innerHTML", "injection", "high",
                "Assigning a variable to innerHTML/outerHTML/dangerouslySetInnerHTML can inject scripts.", "CWE-79"),
    "CM-J002": ("Command injection via child_process", "injection", "critical",
                "child_process.exec with interpolated input runs a shell command.", "CWE-78"),
    "CM-J003": ("SQL built by string concatenation", "injection", "critical",
                "A SQL query assembled with template literals or + is executed.", "CWE-89"),
    "CM-J004": ("CORS wildcard with credentials", "auth", "high",
                "Access-Control-Allow-Origin: * together with credentials exposes authenticated data.", "CWE-942"),
    "CM-J005": ("JWT decoded without verification", "auth", "high",
                "jwt.decode / manual base64 parsing trusts a token without verifying its signature.", "CWE-347"),
}


def _hits(rule_id: str, content: str, pattern: re.Pattern[str], conf: float, note: str | None = None) -> list[RawMatch]:
    out = []
    for m in pattern.finditer(content):
        out.append(RawMatch(rule_id, m.start(), m.end(), False, conf, note=note))
    return out


def detect_js(ctx: DetectContext) -> list[RawMatch]:
    if ctx.language not in {"javascript", "typescript"}:
        return []
    c = ctx.content
    out: list[RawMatch] = []

    # CM-J001: innerHTML with a variable / template literal (not a plain string literal)
    out += _hits("CM-J001", c, re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*(?![\"'])[^;\n]*(?:\$\{|\+|\w)"), 0.75)
    out += _hits("CM-J001", c, re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{[^}]*\}\}"), 0.75, "dangerouslySetInnerHTML")

    # CM-J002: child_process.exec with interpolation
    out += _hits("CM-J002", c, re.compile(r"(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)"), 0.85)

    # CM-J003: concatenated SQL
    out += _hits("CM-J003", c, re.compile(r"(?:query|execute)\s*\(\s*(?:`(?:[^`]*\$\{[^`]*)?(?:SELECT|INSERT|UPDATE|DELETE)[^`]*`|[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+)", re.I), 0.8)

    # CM-J004: CORS wildcard with credentials
    if re.search(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']|origin\s*:\s*[\"']\*[\"']", c, re.I) and \
       re.search(r"credentials\s*:\s*true|Access-Control-Allow-Credentials[\"']?\s*[:,]\s*[\"']?true", c, re.I):
        m = re.search(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']|origin\s*:\s*[\"']\*[\"']", c, re.I)
        if m:
            out.append(RawMatch("CM-J004", m.start(), m.end(), False, 0.85, note="wildcard origin with credentials"))

    # CM-J005: jwt.decode without verify / alg none acceptance
    out += _hits("CM-J005", c, re.compile(r"jwt\.decode\s*\([^)]*\)(?![^;]*verify)"), 0.7, "jwt.decode without verify")
    out += _hits("CM-J005", c, re.compile(r"algorithms?\s*:\s*\[[^\]]*[\"']none[\"']", re.I), 0.9, "accepts alg:none")

    return out
