"""SQLite-backed LLM result cache.

The key (see ``client.cache_key_for``) covers the model name, pinned digest, prompt template
version, generation options, output schema and a hash of the input, so identical input returns
the identical cached result and any change to model or prompt misses the cache.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Optional

from .. import config

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.settings.db_file(), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS llm_cache ("
        " key TEXT PRIMARY KEY, response TEXT NOT NULL, created_at INTEGER DEFAULT 0)"
    )
    return conn


def key_for(parts: dict) -> str:
    """sha256 of the canonical JSON of ``parts``."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def clear() -> None:
    with _lock:
        conn = _conn()
        try:
            conn.execute("DELETE FROM llm_cache")
            conn.commit()
        finally:
            conn.close()


def get(key: str) -> Optional[str]:
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT response FROM llm_cache WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()


def put(key: str, response: str) -> None:
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO llm_cache (key, response) VALUES (?, ?)",
                (key, response),
            )
            conn.commit()
        finally:
            conn.close()
