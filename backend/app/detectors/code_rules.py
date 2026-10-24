"""Cross-language regex detectors: weak crypto (CM-C001), insecure randomness (CM-C002),
debug configuration (CM-C003), permissive CORS (CM-C004) and plaintext PII at rest (CM-P008).

Ported 1:1 to ``frontend/src/lib/codeRules.ts``; keep the regexes in sync.
"""

from __future__ import annotations

import re

from .common import DetectContext, RawMatch
from .js_rules import any_origin_matches

CODE_RULE_IDS = ("CM-C001", "CM-C002", "CM-C003", "CM-C004", "CM-P008")

_WEAK_CIPHER_PY = re.compile(
    r"\b(?:DES|DES3|ARC4|ARC2|Blowfish|CAST)\.new\s*\(|\bMODE_ECB\b|\bmodes\.ECB\s*\("
    r"|\balgorithms\.(?:TripleDES|ARC4|Blowfish|IDEA|CAST5|SEED)\s*\("
)
_WEAK_CIPHER_JS = re.compile(
    r"\bcreateCipher\s*\(|\bcreateDecipher\s*\("
    r"|\bcreateCipheriv\s*\(\s*[\"'](?:des[\w-]*|rc4[\w-]*|rc2[\w-]*|bf[\w-]*|blowfish[\w-]*|aes-\d+-ecb)[\"']"
    r"|\bCryptoJS\.(?:DES|TripleDES|RC4|RC4Drop|Rabbit)\.(?:encrypt|decrypt)\b|\bCryptoJS\.mode\.ECB\b",
    re.I,
)

_RANDOM_PY = re.compile(r"(?<![\w.])random\.(?:random|randint|randrange|choice|choices|sample|getrandbits|uniform)\s*\(")
_RANDOM_JS = re.compile(r"\bMath\.random\s*\(\s*\)")
_SECURITY_WORD = re.compile(
    r"token|secret|passw|\botp\b|nonce|salt|session_?id|sessionid|api_?key|apikey|csrf|verification|reset_?code|auth_?code|invite_?code",
    re.I,
)

_DEBUG_PY = re.compile(
    r"^[ \t]*DEBUG\s*=\s*True\b|\bFastAPI\([^)\n]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True\b"
    r"|\.config\[\s*[\"']DEBUG[\"']\s*\]\s*=\s*True\b|\.config\.update\([^)\n]*\bDEBUG\s*=\s*True",
    re.M,
)

_SENSITIVE_FIELD = r"(?:ssn|social_?security(?:_?number)?|date_?of_?birth|dob|birth_?date|passport(?:_?(?:number|no))?|tax_?id|national_?id|card_?number|credit_?card(?:_?number)?)"
_PROTECTED = re.compile(r"encrypt|cipher|EncryptedType|hash|fernet|_enc\b|masked|redact", re.I)
_PII_COLUMN_DEF = re.compile(r"\b(" + _SENSITIVE_FIELD + r")\s+(?:VARCHAR|NVARCHAR|TEXT|CHAR|DATE|INTEGER|INT|STRING|BIGINT)\b", re.I)
_PII_INSERT = re.compile(r"\b(?:INSERT\s+INTO|REPLACE\s+INTO)\s+[\w.`\"\[\]]+\s*\(([^)]*)\)", re.I)
_PII_UPDATE = re.compile(r"\bUPDATE\s+[\w.`\"\[\]]+\s+SET\s+[^\n]*?\b(" + _SENSITIVE_FIELD + r")\s*=", re.I)
_PII_ORM_PY = re.compile(r"^[ \t]*(" + _SENSITIVE_FIELD + r")\s*(?::\s*[\w\[\], |]+)?=\s*(?:\w+\.)?(?:Column|mapped_column|CharField|TextField|DateField|StringField)\s*\(", re.I | re.M)
_PII_ORM_JS = re.compile(r"\b(" + _SENSITIVE_FIELD + r")\s*:\s*(?:\{\s*type\s*:\s*)?(?:String|Date|DataTypes\.(?:STRING|DATE|DATEONLY|TEXT)|Sequelize\.(?:STRING|DATE|TEXT))\b", re.I)
_SENSITIVE_NAME = re.compile(r"(?<![A-Za-z0-9])" + _SENSITIVE_FIELD + r"(?![A-Za-z0-9])", re.I)


def _line_bounds(c: str, pos: int) -> tuple[int, int]:
    s = c.rfind("\n", 0, pos) + 1
    e = c.find("\n", pos)
    return s, len(c) if e < 0 else e


def _c001(ctx: DetectContext) -> list[RawMatch]:
    rx = _WEAK_CIPHER_PY if ctx.language == "python" else _WEAK_CIPHER_JS
    return [RawMatch("CM-C001", m.start(), m.end(), False, 0.85, note="broken cipher or mode") for m in rx.finditer(ctx.content)]


def _c002(ctx: DetectContext) -> list[RawMatch]:
    c = ctx.content
    if ctx.language == "python":
        if re.search(r"\brandom\s*=\s*(?:secrets\.)?SystemRandom\(", c):
            return []
        rx = _RANDOM_PY
    else:
        rx = _RANDOM_JS
    rows = c.split("\n")
    out = []
    for m in rx.finditer(c):
        idx = c.count("\n", 0, m.start())
        window = "\n".join(rows[max(0, idx - 2): idx + 1])
        w = _SECURITY_WORD.search(window)
        if w:
            out.append(RawMatch("CM-C002", m.start(), m.end(), False, 0.75, note=f"used for `{w.group(0)}`"))
    return out


def _c003(ctx: DetectContext) -> list[RawMatch]:
    if ctx.language != "python":
        return []
    out = []
    for m in _DEBUG_PY.finditer(ctx.content):
        start = m.start() + (len(m.group(0)) - len(m.group(0).lstrip()))
        out.append(RawMatch("CM-C003", start, m.end(), False, 0.8, note="debug flag hardcoded on"))
    return out


def _c004(ctx: DetectContext) -> list[RawMatch]:
    return [RawMatch("CM-C004", m.start(), m.end(), False, 0.75, note="any origin allowed")
            for m in any_origin_matches(ctx.content, ctx.language)]


def _p008(ctx: DetectContext) -> list[RawMatch]:
    c = ctx.content
    out: list[RawMatch] = []

    def add(start: int, end: int, field: str):
        ls, le = _line_bounds(c, start)
        if _PROTECTED.search(c[ls:le]):
            return
        out.append(RawMatch("CM-P008", start, end, False, 0.75, note=f"`{field}` stored unencrypted"))

    for m in _PII_COLUMN_DEF.finditer(c):
        add(m.start(), m.end(), m.group(1))
    for m in _PII_INSERT.finditer(c):
        cols = [x.strip().strip("`\"[]") for x in m.group(1).split(",")]
        hits = [col for col in cols if _SENSITIVE_NAME.fullmatch(col)]
        if hits:
            add(m.start(), m.end(), hits[0])
    for m in _PII_UPDATE.finditer(c):
        add(m.start(), m.end(), m.group(1))
    if ctx.language == "python":
        for m in _PII_ORM_PY.finditer(c):
            add(m.start(1), m.end(), m.group(1))
    elif ctx.language in {"javascript", "typescript"}:
        for m in _PII_ORM_JS.finditer(c):
            # Schema type tokens are case-sensitive: `ssn: string` is a TS annotation, not a column.
            if re.search(r"\b(?:String|Date|DataTypes|Sequelize)\b", m.group(0)):
                add(m.start(), m.end(), m.group(1))
    return out


def detect_code(ctx: DetectContext) -> list[RawMatch]:
    out: list[RawMatch] = []
    if ctx.language in {"python", "javascript", "typescript"}:
        out += _c001(ctx) + _c002(ctx) + _c003(ctx) + _c004(ctx)
    if ctx.language in {"python", "javascript", "typescript", "sql"}:
        out += _p008(ctx)
    return out
