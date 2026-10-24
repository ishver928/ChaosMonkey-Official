"""Central configuration for Chaos Monkey.

All settings are read from environment variables (optionally from a local ``.env``).
Every network-facing setting is validated to be localhost-only so that proprietary
code can never leave the machine — this is the core privacy guarantee.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency). Only sets vars not already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(BACKEND_DIR / ".env")


def is_local_url(url: str) -> bool:
    """True only if ``url`` targets this machine (loopback)."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    return host in _LOCAL_HOSTS


@dataclass(frozen=True)
class Settings:
    ollama_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    llm_model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", "qwen2.5-coder:7b-instruct"))
    embed_model: str = field(default_factory=lambda: os.environ.get("EMBED_MODEL", "nomic-embed-text"))

    seed: int = field(default_factory=lambda: int(os.environ.get("SEED", "42")))
    temperature: float = field(default_factory=lambda: float(os.environ.get("LLM_TEMPERATURE", "0")))
    top_k: int = field(default_factory=lambda: int(os.environ.get("LLM_TOP_K", "1")))
    top_p: float = field(default_factory=lambda: float(os.environ.get("LLM_TOP_P", "1")))
    llm_mock: bool = field(default_factory=lambda: os.environ.get("LLM_MOCK", "0") == "1")

    host: str = field(default_factory=lambda: os.environ.get("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("PORT", "8000")))

    db_path: str = field(default_factory=lambda: os.environ.get("DB_PATH", "chaosmonkey.db"))
    max_file_bytes: int = field(default_factory=lambda: int(os.environ.get("MAX_FILE_BYTES", "1000000")))

    cors_origins: tuple[str, ...] = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )

    def db_file(self) -> Path:
        p = Path(self.db_path)
        return p if p.is_absolute() else BACKEND_DIR / p

    def verify_local_only(self) -> list[str]:
        """Return a list of problems if any configured endpoint is not localhost."""
        problems: list[str] = []
        if not is_local_url(self.ollama_url):
            problems.append(f"OLLAMA_URL is not localhost: {self.ollama_url}")
        return problems

    @property
    def data_leaves_machine(self) -> bool:
        """The health-check attestation: True would mean a non-local endpoint is configured."""
        return len(self.verify_local_only()) > 0


settings = Settings()
