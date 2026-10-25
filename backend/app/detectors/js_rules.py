"""JS/TS regex detectors (CM-J0xx). CM-J004 also covers Python CORS configuration.

DOM XSS sinks with unsanitized non-literal input, Express reflected XSS, child_process
command injection, string-built SQL, CORS any-origin with credentials, JWT used without
verification and node-serialize deserialization. Ported 1:1 to ``frontend/src/lib/codeRules.ts``;
keep the regexes in sync (the parity test runs both engines on the eval corpus).
"""

from __future__ import annotations

import re

from .catalog import load_catalog
from .common import DetectContext, RawMatch

JS_RULE_IDS = ("CM-J001", "CM-J002", "CM-J003", "CM-J004", "CM-J005", "CM-J006", "CM-J007")


def _js_rules() -> dict[str, tuple[str, str, str, str, str]]:
    cat = load_catalog()
    return {rid: (cat[rid].title, cat[rid].category, cat[rid].severity, cat[rid].description, cat[rid].cwe)
            for rid in JS_RULE_IDS}


JS_RULES = _js_rules()

JS_LANGS = {"javascript", "typescript"}

SANITIZED = re.compile(r"DOMPurify\.sanitize|\bsanitize\w*\(|\bescape\w*\(|\bencode\w*\(|\bxss\(|\bpurify\(|\bhe\.encode\(", re.I)
SQL_STMT = re.compile(r"\b(?:select\b[\s\S]*?\bfrom|insert\s+into|update\s+[\w.`\"\[\]]+\s+set|delete\s+from|replace\s+into)\b", re.I)
SQL_SINK = r"(?:query|execute|raw|run|all|prepare|queryRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)"
REQ_SOURCE = re.compile(r"\breq(?:uest)?\.(?:query|params|body|cookies|headers)\b")
UPPER_ONLY = re.compile(r"^\s*[A-Z][A-Z0-9_]*\s*$")


def _interpolations(template: str) -> list[str]:
    return re.findall(r"\$\{([^}]*)\}", template)


def _all_upper(parts: list[str]) -> bool:
    return bool(parts) and all(UPPER_ONLY.match(p) for p in parts)


def unsafe_html_value(value: str) -> bool:
    """True if a value written to an HTML sink is non-literal and not sanitized."""
    v = value.strip().rstrip(";").strip()
    if not v or SANITIZED.search(v):
        return False
    if re.fullmatch(r"([\"'])(?:\\.|(?!\1).)*\1", v):
        return False
    if re.fullmatch(r"`[^`]*`", v) and "${" not in v:
        return False
    if re.fullmatch(r"-?\d+(\.\d+)?|null|undefined|true|false", v):
        return False
    return True


def _hit(rule_id: str, start: int, end: int, conf: float, note: str | None = None) -> RawMatch:
    return RawMatch(rule_id, start, end, False, conf, note=note)


def _j001(c: str) -> list[RawMatch]:
    out = []
    sinks = [
        (re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*([^;\n]+)"), "innerHTML"),
        (re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,\n]+,([^\n]*)\)"), "insertAdjacentHTML"),
        (re.compile(r"\bdocument\.write(?:ln)?\s*\(([^\n]*)\)"), "document.write"),
        (re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}\n]+)\}\}"), "dangerouslySetInnerHTML"),
        (re.compile(r"\$\([^)\n]*\)\.html\(\s*([^)\n]+)\)"), "jQuery .html()"),
    ]
    for rx, label in sinks:
        for m in rx.finditer(c):
            if unsafe_html_value(m.group(1)):
                out.append(_hit("CM-J001", m.start(), m.end(), 0.8, label))
    return out


def _j002(c: str) -> list[RawMatch]:
    if not re.search(r"child_process", c):
        return []
    out = []
    rx = re.compile(r"(?<![\w.$])(?:(?:child_process|cp|childProcess)\.)?(?:exec|execSync)\s*\(\s*(`[^`]*\$\{[^`]*`|[\"'][^\"'\n]*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*\+)")
    for m in rx.finditer(c):
        arg = m.group(1)
        if arg.startswith("`") and _all_upper(_interpolations(arg)):
            continue
        out.append(_hit("CM-J002", m.start(), m.end(), 0.85, "shell command built from variables"))
    rx_spawn = re.compile(r"\bspawn(?:Sync)?\s*\(\s*(`[^`]*\$\{[^`]*`|[\"'][^\"'\n]*[\"']\s*\+)[^\n]*\bshell\s*:\s*true")
    for m in rx_spawn.finditer(c):
        out.append(_hit("CM-J002", m.start(), m.end(), 0.85, "spawn with shell: true"))
    return out


def _j003(c: str) -> list[RawMatch]:
    out = []
    tmpl = re.compile(r"\b" + SQL_SINK + r"\s*\(\s*(`[^`]*`)")
    for m in tmpl.finditer(c):
        t = m.group(1)
        parts = _interpolations(t)
        if parts and SQL_STMT.search(t) and not _all_upper(parts):
            out.append(_hit("CM-J003", m.start(), m.end(), 0.85, "interpolated SQL"))
    concat = re.compile(r"\b" + SQL_SINK + r"\s*\(\s*([\"'])((?:(?!\1)[^\n])*)\1\s*\+\s*([A-Za-z_$][\w$.\[\]'\"]*)")
    for m in concat.finditer(c):
        if SQL_STMT.search(m.group(2)) and not UPPER_ONLY.match(m.group(3)):
            out.append(_hit("CM-J003", m.start(), m.end(), 0.85, "concatenated SQL"))
    # Query text built into a variable first, then executed.
    built: dict[str, int] = {}
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(`[^`]*`|([\"'])[^\n]*?\3\s*\+[^\n;]*)", c):
        val = m.group(2)
        if not SQL_STMT.search(val):
            continue
        if val.startswith("`"):
            parts = _interpolations(val)
            if not parts or _all_upper(parts):
                continue
        else:
            operands = [o.strip() for o in re.split(r"\+", re.sub(r"([\"'])(?:\\.|(?!\1).)*\1", "''", val))]
            if all(o in ("''", "") or UPPER_ONLY.match(o) for o in operands):
                continue
        built[m.group(1)] = m.start()
    for name, pos in built.items():
        for m in re.finditer(r"\b" + SQL_SINK + r"\s*\(\s*" + re.escape(name) + r"\s*[,)]", c):
            if m.start() > pos:
                out.append(_hit("CM-J003", m.start(), m.end(), 0.8, f"query text `{name}` built dynamically"))
    return out


_ANY_ORIGIN_JS = re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']|\borigin\s*:\s*(?:[\"']\*[\"']|true\b)|\bcors\(\s*\)", re.I)
_ANY_ORIGIN_PY = re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|\borigins\s*=\s*[\"']\*[\"']|[\"']origins[\"']\s*:\s*[\"']\*[\"']|\bCORS\(\s*\w+\s*(?:\)|,(?![^)\n]*\borigins\s*=))|Access-Control-Allow-Origin[\"']?\s*[\],:]\s*=?\s*[\"']\*[\"']")
_CREDS_JS = re.compile(r"credentials\s*:\s*true|Access-Control-Allow-Credentials[\"']?\s*[:,]\s*[\"']?true", re.I)
_CREDS_PY = re.compile(r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|Access-Control-Allow-Credentials[\"']?\s*[\],:]\s*=?\s*[\"']true", re.I)


def any_origin_matches(c: str, language: str) -> list[re.Match[str]]:
    rx = _ANY_ORIGIN_PY if language == "python" else _ANY_ORIGIN_JS
    return list(rx.finditer(c))


def has_cors_credentials(c: str, language: str) -> bool:
    return bool((_CREDS_PY if language == "python" else _CREDS_JS).search(c))


def _j004(c: str, language: str) -> list[RawMatch]:
    if not has_cors_credentials(c, language):
        return []
    return [_hit("CM-J004", m.start(), m.end(), 0.85, "any origin with credentials") for m in any_origin_matches(c, language)]


def _j005(c: str) -> list[RawMatch]:
    out = []
    for m in re.finditer(r"jwt\.decode\s*\([^)]*\)", c):
        # Only the rest of this statement: up to ';' or the end of the line.
        tail = re.split(r"[;\n]", c[m.end():], maxsplit=1)[0]
        if "verify" not in tail:
            out.append(_hit("CM-J005", m.start(), m.end(), 0.7, "jwt.decode without verify"))
    for m in re.finditer(r"algorithms?\s*:\s*\[[^\]]*[\"']none[\"']", c, re.I):
        out.append(_hit("CM-J005", m.start(), m.end(), 0.9, "accepts alg:none"))
    return out


def _tainted_js(c: str) -> set[str]:
    names = set()
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)", c):
        if REQ_SOURCE.search(m.group(2)):
            names.add(m.group(1))
    for m in re.finditer(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\.(?:query|params|body|cookies)\b", c):
        for part in m.group(1).split(","):
            name = part.split(":")[-1].split("=")[0].strip()
            if name:
                names.add(name)
    return names


def _expr_tainted(expr: str, tainted: set[str]) -> bool:
    e = expr.strip()
    if re.match(r"^(?:escapeHtml|escape|encode\w*|sanitize\w*|DOMPurify\.sanitize|he\.encode|validator\.escape|Number|parseInt|parseFloat)\s*\(", e):
        return False
    if REQ_SOURCE.search(e):
        return True
    return any(re.search(r"(?<![\w$.])" + re.escape(t) + r"(?![\w$])", e) for t in tainted)


def _j006(c: str) -> list[RawMatch]:
    out = []
    tainted = _tainted_js(c)
    for m in re.finditer(r"\bres\.(?:send|write|end)\s*\(([^\n]*)", c):
        arg = m.group(1)
        hit = False
        if arg.lstrip().startswith("`"):
            t = arg[: arg.rfind("`") + 1] if arg.count("`") >= 2 else arg
            if re.search(r"<\s*[a-zA-Z/!]", re.sub(r"\$\{[^}]*\}", "", t)):
                hit = any(_expr_tainted(p, tainted) for p in _interpolations(t))
        elif re.match(r"\s*[\"']", arg) and "+" in arg:
            strings = " ".join(s for _q, s in re.findall(r"([\"'])((?:(?!\1).)*)\1", arg))
            if re.search(r"<\s*[a-zA-Z/!]", strings):
                operands = re.split(r"\+", re.sub(r"([\"'])(?:\\.|(?!\1).)*\1", "''", arg.rstrip().rstrip(";").rstrip(")")))
                hit = any(_expr_tainted(o, tainted) for o in operands if o.strip() not in ("''", ""))
        else:
            first = re.split(r"[,)]", arg, maxsplit=1)[0]
            hit = bool(first.strip()) and _expr_tainted(first, tainted) and not re.match(r"\s*\{", first)
        if hit:
            end = c.find("\n", m.start())
            out.append(_hit("CM-J006", m.start(), len(c) if end < 0 else end, 0.8, "request data in HTML response"))
    return out


def _j007(c: str) -> list[RawMatch]:
    if not re.search(r"node-serialize|serialize-to-js|funcster", c):
        return []
    return [_hit("CM-J007", m.start(), m.end(), 0.9, "unserialize() evaluates embedded functions")
            for m in re.finditer(r"(?<![\w$])(?:[A-Za-z_$][\w$]*\.)?(?:unserialize|deserialize)\s*\(", c)]


def detect_js(ctx: DetectContext) -> list[RawMatch]:
    c = ctx.content
    if ctx.language == "python":
        return _j004(c, "python")
    if ctx.language not in JS_LANGS:
        return []
    return _j001(c) + _j002(c) + _j003(c) + _j004(c, ctx.language) + _j005(c) + _j006(c) + _j007(c)
