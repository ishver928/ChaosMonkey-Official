"""SQLite-backed LLM result cache.

Keyed by sha256(model + prompt + params + content) so identical input yields a
byte-identical cached response — a cornerstone of the determinism guarantee.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Optional

from ..config import settings

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_file(), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS llm_cache ("
        " key TEXT PRIMARY KEY, response TEXT NOT NULL, created_at INTEGER DEFAULT 0)"
    )
    return conn


def cache_key(model: str, prompt: str, params: dict, content: str) -> str:
    blob = json.dumps(
        {"model": model, "prompt": prompt, "params": params, "content": content},
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
