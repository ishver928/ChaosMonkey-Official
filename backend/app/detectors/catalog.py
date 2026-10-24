"""Rule catalog: the single source of truth for rule metadata.

``rules/catalog.json`` (repo root) holds every rule's id, title, category, severity, CWE,
plain-English explanation, remediation steps and per-language fix examples. The backend reads
it here; the frontend imports the same file. Detection logic lives in each engine, and a parity
test checks the two engines against each other.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache

from ..config import REPO_DIR

CATALOG_PATH = REPO_DIR / "rules" / "catalog.json"


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    category: str
    severity: str
    cwe: str
    description: str
    explanation: str
    steps: tuple[str, ...]
    fix: dict
    generic: bool = False
    superseded_by: tuple[str, ...] = field(default_factory=tuple)

    def fix_example(self, language: str) -> str:
        """Best catalog fix example for a file language ("" if none)."""
        key = {"typescript": "javascript"}.get(language, language)
        if key in self.fix:
            return self.fix[key]
        for fallback in ("python", "javascript"):
            if fallback in self.fix:
                return self.fix[fallback]
        return next(iter(self.fix.values()), "")


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, RuleInfo]:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    out: dict[str, RuleInfo] = {}
    for r in data["rules"]:
        out[r["id"]] = RuleInfo(
            id=r["id"], title=r["title"], category=r["category"], severity=r["severity"],
            cwe=r["cwe"], description=r["description"], explanation=r["explanation"],
            steps=tuple(r.get("steps", [])), fix=dict(r.get("fix", {})),
            generic=bool(r.get("generic", False)),
            superseded_by=tuple(r.get("superseded_by", [])),
        )
    return out


def rule_info(rule_id: str) -> RuleInfo | None:
    return load_catalog().get(rule_id)
