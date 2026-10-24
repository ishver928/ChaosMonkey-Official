"""Demo scenario registry: metadata, source files to scan, and attack counts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import REPO_DIR
from ..models.schemas import SourceFile

APPS_DIR = REPO_DIR / "demo" / "apps"


@dataclass
class Scenario:
    key: str
    title: str
    blurb: str
    attack_count: int
    extra_files: dict  # mapping scanned-path -> on-disk file (e.g. ".env" -> leaked.env.txt)


SCENARIOS: dict[str, Scenario] = {
    "flask_store": Scenario(
        "flask_store", "Vibe Store (Flask + SQLite)",
        "A hastily built store: SQL injection, an exposed API key, reflected XSS, "
        "path traversal, debug mode, MD5 passwords, and an open /admin route.",
        5, {}),
    "notes_api": Scenario(
        "notes_api", "Notes API (JWT auth)",
        "A notes service with a hard-coded JWT secret and alg:none, IDOR, wildcard CORS, "
        "PII in responses, and a committed .env.",
        4, {".env": "leaked.env.txt"}),
    "ai_chatbot": Scenario(
        "ai_chatbot", "AI Chatbot wrapper",
        "A chatbot that leaks its system prompt and API key through an error handler and "
        "writes user PII to logs.",
        3, {}),
}


def list_scenarios() -> list[dict]:
    return [
        {"key": s.key, "title": s.title, "blurb": s.blurb, "attacks": s.attack_count}
        for s in SCENARIOS.values()
    ]


def scenario_source_files(key: str, variant: str = "vulnerable") -> list[SourceFile]:
    """Return the SourceFiles that Chaos Monkey scans for a scenario."""
    s = SCENARIOS[key]
    base = APPS_DIR / key
    files: list[SourceFile] = []
    script = base / f"{variant}.py"
    if script.exists():
        files.append(SourceFile(path=f"{key}/{variant}.py", content=script.read_text(encoding="utf-8")))
    # A .gitignore-less tree is part of the point for notes_api's committed .env.
    for scan_path, on_disk in s.extra_files.items():
        p = base / on_disk
        if p.exists():
            files.append(SourceFile(path=f"{key}/{scan_path}", content=p.read_text(encoding="utf-8")))
    return files
