"""Local LLM client (Ollama) with determinism, caching, and a mock mode.

Every call pins temperature=0, top_k=1, top_p=1 and a fixed seed, requests JSON output,
and retries up to 3 times on invalid JSON with the *same* parameters. Results are cached
by content hash. Only ``127.0.0.1`` is ever contacted; ``LLM_MOCK=1`` skips the network
entirely and uses the deterministic recorded analyzer in ``mock.py``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from ..config import is_local_url, settings
from . import cache
from .mock import mock_analyze

logger = logging.getLogger("chaosmonkey.llm")

MAX_RETRIES = 3


@dataclass
class LlmStatus:
    available: bool
    mode: str  # "ollama" | "mock" | "offline"
    model: str
    detail: str = ""


def _params() -> dict:
    return {
        "temperature": settings.temperature,
        "top_k": settings.top_k,
        "top_p": settings.top_p,
        "seed": settings.seed,
    }


def check_status() -> LlmStatus:
    if settings.llm_mock:
        return LlmStatus(True, "mock", settings.llm_model, "LLM_MOCK=1 — recorded responses")
    if not is_local_url(settings.ollama_url):
        return LlmStatus(False, "offline", settings.llm_model, "Ollama URL is not localhost")
    try:
        import httpx

        with httpx.Client(timeout=2.0) as client:
            r = client.get(f"{settings.ollama_url}/api/tags")
            if r.status_code == 200:
                models = [m.get("name", "") for m in r.json().get("models", [])]
                has = settings.llm_model in models or any(settings.llm_model.split(":")[0] in m for m in models)
                return LlmStatus(True, "ollama", settings.llm_model,
                                 "model present" if has else f"model not pulled; have {models}")
    except Exception as exc:
        return LlmStatus(False, "offline", settings.llm_model, f"Ollama not reachable: {exc}")
    return LlmStatus(False, "offline", settings.llm_model, "Ollama returned non-200")


def _ollama_generate(prompt: str, content: str) -> Optional[str]:
    """Call Ollama /api/generate with JSON format enforced. Returns raw text or None."""
    import httpx

    params = _params()
    key = cache.cache_key(settings.llm_model, prompt, params, content)
    cached = cache.get(key)
    if cached is not None:
        return cached

    body = {
        "model": settings.llm_model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {**params},
    }
    last_text = None
    for attempt in range(MAX_RETRIES):
        try:
            with httpx.Client(timeout=120.0) as client:
                r = client.post(f"{settings.ollama_url}/api/generate", json=body)
                if r.status_code != 200:
                    return None
                text = r.json().get("response", "")
        except Exception as exc:
            logger.warning("Ollama generate failed: %s", exc)
            return None
        last_text = text
        try:
            json.loads(text)
            cache.put(key, text)
            return text
        except json.JSONDecodeError:
            logger.info("Invalid JSON from model (attempt %d), retrying", attempt + 1)
            continue
    # Cache the last text anyway so repeated runs are still deterministic.
    if last_text is not None:
        cache.put(key, last_text)
    return last_text


def analyze_chunk(prompt: str, content: str, cwe_context: list[dict]) -> dict:
    """Return a parsed {"findings": [...]} dict for a code chunk.

    Uses the mock analyzer when LLM_MOCK=1 or Ollama is unavailable, so the pipeline
    never hard-fails and tests stay offline.
    """
    if settings.llm_mock:
        return mock_analyze(content, cwe_context)

    status = check_status()
    if not status.available or status.mode != "ollama":
        return mock_analyze(content, cwe_context)

    text = _ollama_generate(prompt, content)
    if text is None:
        return mock_analyze(content, cwe_context)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"findings": []}
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data
    if isinstance(data, list):
        return {"findings": data}
    return {"findings": []}
