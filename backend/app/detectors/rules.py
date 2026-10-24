"""Deterministic detectors — the high-precision, no-LLM layer.

Ports the 29 ``CM-*`` rules from ``frontend/src/lib/rules.ts`` so the backend reuses the
same rule ids, then adds extra server-side rules (Python AST, extended JS) under the same
id scheme. Each rule returns ``RawMatch`` offsets; masking/line math happens in the pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .common import (
    CODE_LANGS,
    DetectContext,
    RawMatch,
    is_env_file,
    is_env_template,
    is_env_var_name,
    is_placeholder,
    is_template_placeholder,
    is_word_identifier,
    line_at,
    shannon_entropy,
)

SECRET_NAME = re.compile(
    r"(api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|\bpwd\b|_pwd\b|passphrase|"
    r"credential|private[_-]?key|access[_-]?key|auth[_-]?key|signing[_-]?key|"
    r"encryption[_-]?key|client[_-]?secret|(?:^|[_.-])key$)",
    re.I,
)
PASSWORD_NAME = re.compile(r"(passw(?:or)?d|passwd|pwd|passphrase)", re.I)


def luhn(digits: str) -> bool:
    total = 0
    dbl = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: str
    description: str
    detect: Callable[[DetectContext], list[RawMatch]]
    generic: bool = False


def _rx(rule_id: str, content: str, pattern: re.Pattern[str], group: int = 0,
        sensitive: bool = True, confidence: float = 0.9, name_group: int | None = None,
        filt: Callable[[str, re.Match[str]], bool | float] | None = None) -> list[RawMatch]:
    out: list[RawMatch] = []
    for m in pattern.finditer(content):
        try:
            span = m.span(group)
            value = m.group(group)
        except (IndexError, re.error):
            continue
        if value is None or span == (-1, -1):
            continue
        conf = confidence
        if filt is not None:
            verdict = filt(value, m)
            if verdict is False:
                continue
            if isinstance(verdict, (int, float)) and not isinstance(verdict, bool):
                conf = float(verdict)
        out.append(RawMatch(
            rule_id=rule_id, start=span[0], end=span[1],
            sensitive=sensitive, confidence=conf,
            name=m.group(name_group) if name_group else None,
        ))
    return out


# ---------------------------------------------------------------------------
# Secret detectors (CM-S0xx)
# ---------------------------------------------------------------------------

def _not_template(v, _m):
    return not is_template_placeholder(v)


def _s001(ctx):
    return _rx("CM-S001", ctx.content, re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1, confidence=0.95, filt=_not_template)

def _s002(ctx):
    return _rx("CM-S002", ctx.content, re.compile(r"(aws[\w.\-]{0,30}?secret[\w\-]*)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", re.I), 2, name_group=1, confidence=0.92, filt=_not_template)

def _s003(ctx):
    return _rx("CM-S003", ctx.content, re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b"), 1, confidence=0.97, filt=_not_template)

def _s004(ctx):
    return _rx("CM-S004", ctx.content, re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{16,})\b"), 1, confidence=0.97, filt=_not_template)

def _s005(ctx):
    def f(v, _m):
        return len(v) >= 24 and bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v[3:])) and not is_template_placeholder(v)
    return _rx("CM-S005", ctx.content, re.compile(r"(?<![\w-])(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})"), 1, confidence=0.85, filt=f)

def _s006(ctx):
    return _rx("CM-S006", ctx.content, re.compile(r"(?<![\w-])(sk-ant-[A-Za-z0-9_\-]{20,})"), 1, confidence=0.96, filt=_not_template)

def _s007(ctx):
    return _rx("CM-S007", ctx.content, re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])"), 1, confidence=0.93, filt=_not_template)

def _s008(ctx):
    return _rx("CM-S008", ctx.content, re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})"), 1, confidence=0.92, filt=_not_template)

def _s009(ctx):
    return _rx("CM-S009", ctx.content, re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"), 0, confidence=0.99)

def _s010(ctx):
    return _rx("CM-S010", ctx.content, re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"), 1, confidence=0.88, filt=_not_template)

def _s011(ctx):
    def f(v, _m):
        return not is_placeholder(v) and not v.startswith("$") and not v.startswith("{")
    return _rx("CM-S011", ctx.content, re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^:/\s'\"@]*:([^@\s'\"/]+)@"), 1, confidence=0.93, filt=f)

def _s012(ctx):
    def f(v, _m):
        return not is_placeholder(v)
    return _rx("CM-S012", ctx.content, re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]{20,}=*)"), 1, confidence=0.8, filt=f)

def _s013(ctx):
    if not is_env_file(ctx.path) or is_env_template(ctx.path):
        return []
    assignments = []
    offset = 0
    for ln in ctx.content.split("\n"):
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", ln)
        if m and m.group(2).strip().strip("\"'"):
            assignments.append((ln, m, offset))
        offset += len(ln) + 1
    if not assignments:
        return []
    ln, m, off = assignments[0]
    pos = ln.index(m.group(1))
    n = len(assignments)
    return [RawMatch("CM-S013", off + pos, off + pos + len(m.group(1)), False, 0.95,
                     note=f"{n} value{'' if n == 1 else 's'} committed")]

def _s014(ctx):
    out: list[RawMatch] = []

    def consider(name, value, start):
        if not SECRET_NAME.search(name) or is_placeholder(value) or "${" in value:
            return
        if re.match(r"^(?:https?:)?//", value) or re.match(r"^[./]", value):
            return
        # Values that are env-var names or plain word identifiers are not secrets.
        if is_env_var_name(value) or is_word_identifier(value):
            return
        is_pw = bool(PASSWORD_NAME.search(name))
        h = shannon_entropy(value)
        if is_pw:
            if len(value) < 6:
                return
            conf = min(0.9, 0.55 + h / 12)
            note = "hardcoded password"
        else:
            if len(value) < 12 or h < 3.2:
                return
            # Random secrets mix letters and digits; long ones are high-entropy anyway.
            if not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)) and not (len(value) >= 32 and h >= 4.0):
                return
            conf = max(0.45, min(0.92, (h - 3) / 1.6))
            note = f"entropy {h:.2f} bits/char"
        out.append(RawMatch("CM-S014", start, start + len(value), True, conf, name=name, note=note))

    for m in re.finditer(r"\b([A-Za-z_$][\w.\-$]*)[\"']?\s*(?:=>|:=|[:=])\s*([\"'`])([^\"'`\s]{6,})\2", ctx.content):
        consider(m.group(1), m.group(3), m.span(3)[0])
    if ctx.language in {"env", "ini", "toml", "yaml"}:
        for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Za-z_][\w.\-]*)[ \t]*[=:][ \t]*([^\"'\s#][^\s#]{5,})", ctx.content, re.M):
            consider(m.group(1), m.group(2), m.span(2)[0])
    return out


# ---------------------------------------------------------------------------
# PII detectors (CM-P0xx)
# ---------------------------------------------------------------------------

def _p001(ctx):
    def f(v, m):
        before = ctx.content[m.span(1)[0] - 1] if m.span(1)[0] > 0 else ""
        if before in (":", "/"):
            return False
        if re.match(r"^(noreply|no-reply|git)@", v, re.I) or re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|ts)$", v, re.I):
            return False
        return True
    return _rx("CM-P001", ctx.content, re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b"), 1, confidence=0.6, filt=f)

def _p002(ctx):
    return _rx("CM-P002", ctx.content, re.compile(r"(?<![\w-])((?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4})(?![\w-])"), 1, confidence=0.55)

def _p003(ctx):
    return _rx("CM-P003", ctx.content, re.compile(r"(?<![\w-])((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\w-])"), 1, confidence=0.85)

def _p004(ctx):
    def f(v, _m):
        digits = re.sub(r"[ -]", "", v)
        if len(digits) < 13 or len(digits) > 19 or re.fullmatch(r"(\d)\1+", digits):
            return False
        if not re.match(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))", digits):
            return False
        return luhn(digits)
    return _rx("CM-P004", ctx.content, re.compile(r"(?<![\w-])((?:\d[ -]?){12,18}\d)(?![\w-])"), 1, confidence=0.9, filt=f)

def _p005(ctx):
    return _rx("CM-P005", ctx.content, re.compile(r"\b(dob|date_?of_?birth|birth_?date|birthday|dateOfBirth)[\"']?\s*[:=]\s*[\"']?(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})", re.I), 2, name_group=1, confidence=0.8)

_PII_WORDS = re.compile(r"\b(users?|customers?|patients?|members?|email|e_?mail|ssn|social_?security|password|passwd|dob|birth\w*|date_?of_?birth|full_?name|first_?name|last_?name|phone\w*|card\w*|credit\w*|req\.body|request\.(?:body|json|form)|profile|account|address)\b", re.I)

def _p006(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    out = []
    re_log = re.compile(r"\b(console\.(?:log|info|debug|warn|error)|print|logger\.(?:info|debug|warn|warning|error|log)|logging\.(?:info|debug|warning|error)|log\.(?:info|debug|warn))\s*\(")
    offset = 0
    for ln in ctx.content.split("\n"):
        for m in re_log.finditer(ln):
            args = ln[m.end():]
            w = _PII_WORDS.search(args)
            if not w:
                continue
            out.append(RawMatch("CM-P006", offset + m.start(), offset + len(ln.rstrip()), False, 0.75, note=f"logs `{w.group(0)}`"))
        offset += len(ln) + 1
    return out

def _p007(ctx):
    if ctx.language not in CODE_LANGS and ctx.language != "shell":
        return []
    return _rx("CM-P007", ctx.content, re.compile(r"[?&](email|e-mail|ssn|phone|dob|password|pwd|token|access_token|api_key|card)=", re.I), 0, sensitive=False, confidence=0.7, name_group=1)


# ---------------------------------------------------------------------------
# Unsafe-storage detectors (CM-D0xx)
# ---------------------------------------------------------------------------

_STORAGE_KEY = re.compile(r"(token|jwt|auth|session|sess|password|passwd|pwd|secret|ssn|card|credit|api[_-]?key|apikey|refresh|bearer|cred|user(?![a-z])|user_?(?:data|info|profile|obj)|current_?user|profile|e_?mail|dob|birth|phone|address)", re.I)
# Value side of setItem("k", value): only clearly sensitive expressions.
_STORAGE_VALUE = re.compile(r"\b(?:\w*token|jwt|password|passwd|ssn|dob|date_?of_?birth|email|user(?:Data|Info|Profile)?|currentUser|profile)\b", re.I)


def _d001(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    out = []
    re_st = re.compile(r"\b(localStorage|sessionStorage)\s*(?:\.setItem\(\s*[\"'`]([^\"'`]+)[\"'`]|\.([A-Za-z_]\w*)\s*=(?!=)|\[\s*[\"'`]([^\"'`]+)[\"'`]\s*\]\s*=(?!=))")
    for m in re_st.finditer(ctx.content):
        key = m.group(2) or m.group(3) or m.group(4) or ""
        nl = ctx.content.find("\n", m.start())
        paren = ctx.content.find("(", m.start(), m.end())
        rest = ctx.content[m.end(): call_end(ctx.content, paren)] if paren >= 0 else ""
        if not (_STORAGE_KEY.search(key) or (m.group(2) and _STORAGE_VALUE.search(rest))):
            continue
        out.append(RawMatch("CM-D001", m.start(), len(ctx.content) if nl < 0 else nl, False, 0.85, name=key, note=f'key "{key}"'))
    return out

def _d002(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    def f(_v, m):
        idx = m.start()
        line_idx = ctx.content[:idx].count("\n")
        rows = ctx.content.split("\n")
        around = "\n".join(rows[max(0, line_idx - 2): line_idx + 3])
        return bool(re.search(r"(pass|pwd|credential)", around, re.I))
    return _rx("CM-D002", ctx.content, re.compile(r"\b(createHash\(\s*[\"'](?:md5|sha1)[\"']\s*\)|hashlib\.(?:md5|sha1)\b|md5\s*\(|sha1\s*\(|CryptoJS\.(?:MD5|SHA1)\b)", re.I), 1, sensitive=False, confidence=0.85, filt=f)

def _d003(ctx):
    out = []
    if ctx.language == "sql":
        out += _rx("CM-D003", ctx.content, re.compile(r"\b(password|passwd|pwd)\s+(?:VARCHAR|TEXT|CHAR|NVARCHAR)\b[^,\n]*", re.I), 0, sensitive=False, confidence=0.8)
    if ctx.language in CODE_LANGS:
        rows = ctx.content.split("\n")
        offset = 0
        for i, ln in enumerate(rows):
            m = re.search(r"\bpassword[\"']?\s*[:=]\s*(req(?:uest)?\.(?:body|json|form)(?:\.|\[[\"'])password|body\.password|data\[[\"']password[\"']\]|password\b(?!_?hash))", ln, re.I)
            if not m:
                offset += len(ln) + 1
                continue
            around = "\n".join(rows[max(0, i - 3): i + 1])
            if re.search(r"\b(insert|create|save|update|put|add|write|execute|push|set)\b", around, re.I):
                out.append(RawMatch("CM-D003", offset + m.start(), offset + m.start() + len(m.group(0)), False, 0.7))
            offset += len(ln) + 1
    return out

def _d004(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    out = []
    out += _rx("CM-D004", ctx.content, re.compile(r"\bjwt\.(?:sign|verify|encode|decode)\([^,\n]+,\s*([\"'`])([^\"'`\n]{4,})\1"), 2, confidence=0.9)
    out += _rx("CM-D004", ctx.content, re.compile(r"\b(jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret|SECRET_KEY|secretOrKey|signing[_-]?secret|secret_key)[\"'\]]?\s*[:=]\s*([\"'`])([^\"'`\n]{4,})\2", re.I), 3, name_group=1, confidence=0.88)
    out += _rx("CM-D004", ctx.content, re.compile(r"\bsession\(\s*\{[^}]*?\bsecret\s*:\s*([\"'`])([^\"'`\n]+)\1"), 2, confidence=0.9)
    return [h for h in out if "${" not in ctx.content[h.start:h.end]]

def _d005(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    out = []
    js = ctx.language != "python"
    re_set = re.compile(r"\b(?:res|response|ctx|reply)\.(?:cookie|setCookie)\s*\(") if js else re.compile(r"\.set_cookie\s*\(")
    for m in re_set.finditer(ctx.content):
        start = m.start()
        end = call_end(ctx.content, m.end() - 1)
        call = ctx.content[start:end]
        missing = []
        if not re.search(r"httpOnly\s*:\s*true" if js else r"httponly\s*=\s*True", call, re.I):
            missing.append("HttpOnly")
        if not re.search(r"secure\s*:\s*true" if js else r"secure\s*=\s*True", call, re.I):
            missing.append("Secure")
        if not re.search(r"sameSite\s*:" if js else r"samesite\s*=", call, re.I):
            missing.append("SameSite")
        if missing:
            nl = ctx.content.find("\n", start)
            out.append(RawMatch("CM-D005", start, end if nl < 0 else min(end, nl), False, 0.8, note=f"missing {', '.join(missing)}"))
    if js:
        for h in _rx("CM-D005", ctx.content, re.compile(r"document\.cookie\s*=\s*[^;\n]*(?:token|session|auth|jwt|sid)[^\n]*", re.I), 0, sensitive=False, confidence=0.85):
            h.note = "set from JavaScript, so it can never be HttpOnly"
            out.append(h)
    return out

def call_end(content: str, open_paren: int, limit: int = 600) -> int:
    """Offset just past the ``)`` matching ``content[open_paren]`` (string-aware, bounded)."""
    depth = 0
    quote = ""
    i = open_paren
    stop = min(len(content), open_paren + limit)
    while i < stop:
        ch = content[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return stop


def _d006(ctx):
    if ctx.language not in CODE_LANGS:
        return []
    out = []
    re_w = re.compile(r"\b(fs\.(?:writeFile|writeFileSync|appendFile|appendFileSync)|createWriteStream|\w+\.write)\s*\(")
    offset = 0
    for ln in ctx.content.split("\n"):
        for m in re_w.finditer(ln):
            if re.match(r"^(res|response|reply|process\.stdout|sys\.stdout)\.write$", m.group(1)):
                continue
            args = ln[m.end():]
            hit = re.search(r"\b(passwords?|passwd|secrets?|tokens?|api_?key|apiKey|ssn|credit\w*|card\w*|users?|customers?|patients?|emails?)\b", args, re.I)
            if not hit:
                continue
            out.append(RawMatch("CM-D006", offset + m.start(), offset + len(ln.rstrip()), False, 0.65, note=f"writes `{hit.group(0)}`"))
        offset += len(ln) + 1
    return out

def _d007(ctx):
    return _rx("CM-D007", ctx.content, re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\]?\s*[=:]\s*[\"']?0|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|\bCERT_NONE\b|\.check_hostname\s*=\s*False\b|strictSSL\s*:\s*false|\bcurl\b[^\n]*\s(?:-k|--insecure)\b"), 0, sensitive=False, confidence=0.9)


from .common import base_name  # noqa: E402


def _glob_to_re(glob: str) -> re.Pattern[str]:
    body = re.escape(glob).replace(r"\*\*", "\x00").replace(r"\*", "[^/]*").replace(r"\?", "[^/]").replace("\x00", ".*")
    return re.compile(f"^{body}$")


def _covered_by_gitignore(env_path: str, project) -> tuple[bool, bool]:
    normalized = env_path.replace("\\", "/")
    ignores = [f for f in project if base_name(f.path) == ".gitignore"]
    covered = False
    for gi in ignores:
        slash = gi.path.replace("\\", "/").rfind("/")
        d = "" if slash < 0 else gi.path.replace("\\", "/")[:slash]
        if d and not normalized.startswith(d + "/"):
            continue
        rel = normalized[len(d) + 1:] if d else normalized
        for raw in gi.content.split("\n"):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            pat = (line[1:] if negate else line).lstrip("/").rstrip("/")
            rx = _glob_to_re(pat)
            hit = rx.match(rel) if "/" in pat else rx.match(base_name(rel))
            if hit:
                covered = not negate
    return covered, len(ignores) > 0

def _d008(ctx):
    if not is_env_file(ctx.path) or is_env_template(ctx.path) or len(ctx.project) < 2:
        return []
    covered, has_gi = _covered_by_gitignore(ctx.path, ctx.project)
    if covered:
        return []
    nl = ctx.content.find("\n")
    return [RawMatch("CM-D008", 0, len(ctx.content) if nl < 0 else nl, False,
                     0.9 if has_gi else 0.8,
                     note="no matching .gitignore rule" if has_gi else "no .gitignore in project")]


RULES: list[Rule] = [
    Rule("CM-S001", "AWS access key ID", "secrets", "critical", "AKIA/ASIA-prefixed AWS access key IDs grant API access to your cloud account.", _s001),
    Rule("CM-S002", "AWS secret access key", "secrets", "critical", "40-character AWS secret keys assigned to an aws…secret name.", _s002),
    Rule("CM-S003", "GitHub token", "secrets", "critical", "Classic and fine-grained GitHub tokens that can read or push to your repositories.", _s003),
    Rule("CM-S004", "Stripe live key", "secrets", "critical", "Live-mode Stripe secret/restricted keys. These can move real money.", _s004),
    Rule("CM-S005", "OpenAI-style API key", "secrets", "high", "sk-… keys used by OpenAI and compatible LLM APIs.", _s005),
    Rule("CM-S006", "Anthropic API key", "secrets", "critical", "sk-ant-… keys for the Anthropic API.", _s006),
    Rule("CM-S007", "Google API key", "secrets", "high", "AIza-prefixed Google Cloud / Firebase / Maps API keys.", _s007),
    Rule("CM-S008", "Slack token", "secrets", "high", "xoxb-/xoxp-/xoxa- Slack tokens.", _s008),
    Rule("CM-S009", "Private key block", "secrets", "critical", "PEM-encoded private keys committed alongside code.", _s009),
    Rule("CM-S010", "JSON Web Token", "secrets", "high", "Hardcoded JWTs. Anyone holding one can act as that session.", _s010),
    Rule("CM-S011", "Database URL with credentials", "secrets", "critical", "Connection strings with the password embedded.", _s011),
    Rule("CM-S012", "Hardcoded Bearer token", "secrets", "high", "Literal Authorization: Bearer values in code.", _s012, generic=True),
    Rule("CM-S013", "Committed .env file", "secrets", "high", ".env files with real values in the scanned tree.", _s013),
    Rule("CM-S014", "High-entropy secret assignment", "secrets", "high", "High-entropy values assigned to key/secret/token/password names.", _s014, generic=True),
    Rule("CM-P001", "Email address", "pii", "low", "Real-looking email addresses in source or fixtures.", _p001),
    Rule("CM-P002", "Phone number", "pii", "low", "North American phone numbers.", _p002, generic=True),
    Rule("CM-P003", "US Social Security number", "pii", "high", "NNN-NN-NNNN values passing SSA structural rules.", _p003),
    Rule("CM-P004", "Credit card number", "pii", "high", "Luhn-valid card numbers.", _p004),
    Rule("CM-P005", "Date of birth", "pii", "medium", "Dates assigned to dob/birthdate fields.", _p005),
    Rule("CM-P006", "Personal data written to logs", "pii", "high", "Log calls printing user objects, emails, SSNs, passwords.", _p006),
    Rule("CM-P007", "Personal data in URL", "pii", "medium", "PII placed in query strings.", _p007),
    Rule("CM-D001", "Sensitive data in browser storage", "storage", "high", "Tokens/passwords/profiles written to localStorage.", _d001),
    Rule("CM-D002", "Weak password hashing (MD5/SHA-1)", "storage", "critical", "Passwords hashed with MD5 or SHA-1.", _d002),
    Rule("CM-D003", "Plaintext password storage", "storage", "high", "Passwords saved as-is, or text password columns.", _d003),
    Rule("CM-D004", "Hardcoded JWT / session secret", "storage", "critical", "Literal signing secrets for jwt/session/Flask.", _d004),
    Rule("CM-D005", "Cookie missing HttpOnly / Secure / SameSite", "storage", "medium", "Session cookies without protective flags.", _d005),
    Rule("CM-D006", "Secrets or PII written to files", "storage", "medium", "Writes that dump tokens/passwords/records to disk.", _d006),
    Rule("CM-D007", "TLS certificate verification disabled", "storage", "high", "verify=False, rejectUnauthorized:false, curl -k, etc.", _d007),
    Rule("CM-D008", ".env file not covered by .gitignore", "storage", "high", "A .env exists but no .gitignore rule excludes it.", _d008),
]

RULE_BY_ID = {r.id: r for r in RULES}
