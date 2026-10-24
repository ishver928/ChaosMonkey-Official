"""Masking helpers — mirrors ``frontend/src/lib/redaction.ts``.

Raw secret/PII values may live in memory but must be masked before they are logged,
stored, returned by the API, or placed in any report. ``scrub`` is the defense-in-depth
last resort applied to any free text (LLM output, explanations) before it leaves a function.
"""

from __future__ import annotations

import re

BULLETS = "•" * 8  # ••••••••

_KNOWN_PREFIX = re.compile(
    r"^(sk_live_|rk_live_|sk-ant-(?:api|admin)\d\d-|sk-ant-|sk-proj-|sk-svcacct-|sk-|"
    r"ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[a-z]-|AKIA|ASIA|ABIA|ACCA|AIza|eyJ)"
)

_PASSWORD_NAME = re.compile(r"(passw|pwd|passphrase)", re.I)


def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    parts = domain.split(".")
    tld = parts.pop() if len(parts) > 1 else ""
    host = ".".join(parts)
    return f"{local[:1]}•••@{host[:1]}•••{('.' + tld) if tld else ''}"


def _mask_pem(v: str) -> str:
    rows = v.split("\n")
    if len(rows) < 2:
        return "•" * 32
    body = ["•" * 32 for _ in rows[1:-1]]
    return "\n".join([rows[0], *body, rows[-1]])


def mask_value(raw: str, rule_id: str = "", name: str | None = None) -> str:
    """Mask a raw sensitive value for display, matching the frontend's rules."""
    v = raw
    digits = re.sub(r"\D", "", v)
    specific = {
        "CM-S009": lambda: _mask_pem(v),
        "CM-P001": lambda: _mask_email(v),
        "CM-P003": lambda: f"•••-••-{v[-4:]}",
        "CM-P004": lambda: f"•••• •••• •••• {digits[-4:]}",
        "CM-P002": lambda: f"(•••) •••-••{digits[-2:]}",
        "CM-P005": lambda: "••••-••-••",
    }
    if rule_id in specific:
        return specific[rule_id]()
    if name and _PASSWORD_NAME.search(name):
        return BULLETS
    if "\n" in v:
        return "\n".join("•" * min(32, len(line)) for line in v.split("\n"))
    m = _KNOWN_PREFIX.match(v)
    if m:
        return f"{m.group(0)}{BULLETS}{v[-4:]}"
    if len(v) <= 16:
        return f"{v[:1]}{BULLETS}"
    return f"{v[:2]}{BULLETS}{v[-2:]}"


# Defense-in-depth: patterns that must never appear raw in any output.
_LAST_RESORT = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}"),
    re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bsk-(?:ant-|proj-|svcacct-|fake-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
]


def scrub(text: str) -> str:
    """Blank anything that still looks like a live credential or SSN."""
    for rx in _LAST_RESORT:
        text = rx.sub("[redacted]", text)
    return text


def contains_unmasked_secret(text: str) -> bool:
    return any(rx.search(text) for rx in _LAST_RESORT)
