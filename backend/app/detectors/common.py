"""Shared detector primitives: entropy, placeholder detection, language mapping, line math."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from ..models.schemas import Language

_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%|x{3,}|\*{3,}|\.{3,}|-+|_+)$"
    r"|your[_\- ]?|changeme|change[_\- ]me|replace[_\- ]?me|placeholder|example|dummy"
    r"|sample|redacted|insert[_\- ]|todo|fixme|^test$|^password$|^secret$|^null$|^none$"
    r"|^undefined$|^true$|^false$|process\.env|import\.meta|os\.environ|getenv",
    re.I,
)


def shannon_entropy(value: str) -> float:
    """Bits per character. Random base64 secrets sit around 4.5–6; English words ~3."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    h = 0.0
    n = len(value)
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


_TEMPLATE = re.compile(
    r"x{4,}|your[_\- ]?|changeme|change[_\- ]me|replace[_\- ]?me|placeholder|dummy|redacted"
    r"|insert[_\- ]|<[^>]*>|\$\{|\{\{|\.\.\.",
    re.I,
)


def is_template_placeholder(value: str) -> bool:
    """Obvious template values (YOUR_KEY, xxxx, <token>, ${X}, changeme) inside a known key format.

    Unlike ``is_placeholder`` this does not treat the word "example" as a placeholder:
    vendors publish structurally valid example keys (AWS AKIAIOSFODNN7EXAMPLE) which the
    bundled demo intentionally uses, and a structurally valid provider key is worth a look.
    """
    body = re.sub(r"^[A-Za-z]+[_-](?:live_|proj-|svcacct-|ant-)?", "", value)
    if len(set(body.lower())) <= 2:
        return True
    return bool(_TEMPLATE.search(value))


def is_env_var_name(value: str) -> bool:
    """A value that is itself an environment-variable name, e.g. "GITHUB_TOKEN"."""
    return bool(re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", value))


def is_word_identifier(value: str) -> bool:
    """snake/kebab-case lowercase words such as "token_expired" or "password-input"."""
    return bool(re.fullmatch(r"[a-z]+(?:[_\-.][a-z]+)+", value))


def is_placeholder(value: str) -> bool:
    v = value.strip()
    if len(v) < 4:
        return True
    if re.fullmatch(r"(.)\1+", v):
        return True
    return bool(_PLACEHOLDER.search(v))


_EXT_LANG: dict[str, Language] = {
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "tsx": "typescript", "mts": "typescript", "cts": "typescript",
    "py": "python", "java": "java", "go": "go", "php": "php",
    "json": "json", "yaml": "yaml", "yml": "yaml", "toml": "toml",
    "ini": "ini", "cfg": "ini", "sql": "sql",
    "sh": "shell", "bash": "shell", "zsh": "shell",
}


def base_name(path: str) -> str:
    return re.split(r"[/\\]", path)[-1]


def is_env_file(path: str) -> bool:
    return bool(re.match(r"^\.env(\..+)?$", base_name(path), re.I))


def is_env_template(path: str) -> bool:
    return bool(re.match(r"^\.env\.(example|sample|template|dist|defaults)$", base_name(path), re.I))


def detect_language(path: str) -> Language:
    name = base_name(path).lower()
    if is_env_file(name):
        return "env"
    if name == ".gitignore":
        return "text"
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    return _EXT_LANG.get(ext, "text")


CODE_LANGS = {"javascript", "typescript", "python", "java", "go", "php"}


@dataclass
class DetectContext:
    path: str
    language: Language
    content: str
    project: list = field(default_factory=list)  # list[SourceFile]

    @property
    def file_name(self) -> str:
        return base_name(self.path)

    @property
    def is_code(self) -> bool:
        return self.language in {"javascript", "typescript", "python"}


@dataclass
class RawMatch:
    """A detector hit in absolute character offsets into ``content``."""
    rule_id: str
    start: int
    end: int
    sensitive: bool
    confidence: float
    name: str | None = None
    note: str | None = None


def line_col(content: str, offset: int) -> tuple[int, int]:
    """1-based (line, column) for a character offset."""
    prefix = content[:offset]
    line = prefix.count("\n") + 1
    col = offset - (prefix.rfind("\n") + 1) + 1
    return line, col


def line_at(content: str, offset: int) -> str:
    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset)
    if end < 0:
        end = len(content)
    return content[start:end]
