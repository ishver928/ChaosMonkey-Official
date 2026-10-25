"""The ONE module that talks to a language model (Ollama on this machine).

Locality is enforced on every request, not only at startup:
  * the URL is checked to be loopback (127.0.0.0/8, ::1, or ``localhost`` resolving only to
    loopback) right before each request, and again by an httpx request hook;
  * ``trust_env=False``, so HTTP_PROXY / HTTPS_PROXY / ALL_PROXY cannot route traffic elsewhere;
  * redirects are never followed (a 3xx is treated as an error).

Generation is deterministic: temperature 0, top_k 1, fixed seed / top_p / num_ctx, bounded
num_predict, ``stream: false`` and a JSON-schema ``format``. Responses are validated against
the schema. The selected model's digest is pinned (startup and every toggle-on), and the cache
key covers model, digest, prompt version, options, schema and a hash of the input, so identical
input returns the identical cached result. Identical *fresh* output is only expected on the same
machine, Ollama version and model digest.

``LLM_MOCK=1`` replaces the network with a deterministic stub (tests, offline demos).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from .. import config
from ..config import is_local_url
from . import cache

logger = logging.getLogger("chaosmonkey.llm")

PROMPT_VERSION = "enrich-v1"
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")


class LocalOnlyError(RuntimeError):
    """A request would have left this machine; it was blocked before sending."""


class ModelNotInstalled(RuntimeError):
    pass


class LlmError(RuntimeError):
    pass


# --------------------------------------------------------------------------- locality

def _resolves_to_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)


def assert_loopback(url: str) -> None:
    """Raise LocalOnlyError unless ``url`` is http(s) to a loopback address."""
    if not is_local_url(url):
        raise LocalOnlyError(f"Refusing non-loopback model URL: {url!r}")
    host = urlparse(url).hostname or ""
    if host == "localhost" and not _resolves_to_loopback(host):
        raise LocalOnlyError("'localhost' does not resolve only to loopback addresses on this machine")


def _guard(request: httpx.Request) -> None:
    assert_loopback(str(request.url))


def _http(timeout: float) -> httpx.Client:
    return httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False,
                        event_hooks={"request": [_guard]})


def _send(method: str, path: str, body: Optional[dict] = None, timeout: float = 5.0) -> httpx.Response:
    url = f"{config.settings.ollama_url.rstrip('/')}{path}"
    assert_loopback(url)  # checked per request, before any socket is opened
    with _http(timeout) as client:
        r = client.request(method, url, json=body)
    if r.is_redirect:
        raise LlmError(f"Ollama answered {r.status_code} redirect to {r.headers.get('location')!r}; redirects are not followed")
    return r


def local_only_report() -> dict:
    """The local-only check shown in /api/health."""
    url = config.settings.ollama_url
    problems: list[str] = []
    try:
        assert_loopback(url)
    except LocalOnlyError as exc:
        problems.append(str(exc))
    proxies = sorted({k.upper() for k in PROXY_ENV_VARS if k in os.environ})
    return {
        "ok": not problems,
        "ollama_url": url,
        "loopback_check": "per request (before send + httpx request hook)",
        "trust_env": False,
        "follow_redirects": False,
        "proxy_env_vars_present_and_ignored": proxies,
        "problems": problems,
    }


# --------------------------------------------------------------------------- options + schema

def deterministic_options() -> dict:
    s = config.settings
    return {
        "temperature": 0.0,
        "top_k": 1,
        "top_p": float(s.top_p),
        "seed": int(s.seed),
        "num_ctx": int(s.num_ctx),
        "num_predict": max(16, min(int(s.num_predict), 2048)),
    }


def validate_schema(data: Any, schema: dict, path: str = "$") -> list[str]:
    """Validate the JSON-schema subset used here (type/required/properties/enum/lengths)."""
    errs: list[str] = []
    t = schema.get("type")
    types = {"object": dict, "string": str, "array": list, "boolean": bool, "integer": int, "number": (int, float)}
    if t and not isinstance(data, types[t]) or (t in {"integer", "number"} and isinstance(data, bool)):
        return [f"{path}: expected {t}"]
    if "enum" in schema and data not in schema["enum"]:
        errs.append(f"{path}: not one of {schema['enum']}")
    if isinstance(data, str):
        if len(data) < schema.get("minLength", 0):
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            errs.append(f"{path}: longer than {schema['maxLength']}")
    if isinstance(data, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in data:
                errs.append(f"{path}: missing {req!r}")
        if schema.get("additionalProperties") is False:
            errs += [f"{path}: unexpected {k!r}" for k in data if k not in props]
        for k, sub in props.items():
            if k in data:
                errs += validate_schema(data[k], sub, f"{path}.{k}")
    if isinstance(data, list) and "items" in schema:
        for i, item in enumerate(data):
            errs += validate_schema(item, schema["items"], f"{path}[{i}]")
    return errs


# --------------------------------------------------------------------------- model pinning + state

@dataclass(frozen=True)
class ModelPin:
    model: str
    digest: str
    ollama_version: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class AiState:
    enabled: bool = False
    pin: Optional[ModelPin] = None
    error: str = ""


_state = AiState()
_state_lock = threading.Lock()


def list_models() -> list[dict]:
    r = _send("GET", "/api/tags", timeout=3.0)
    if r.status_code != 200:
        raise LlmError(f"/api/tags returned {r.status_code}")
    return list(r.json().get("models", []))


def pin_model(name: Optional[str] = None) -> ModelPin:
    """Look up the selected model in Ollama and record its digest. Fails clearly if absent."""
    name = name or config.settings.llm_model
    if config.settings.llm_mock:
        return ModelPin(model=name, digest="mock-" + hashlib.sha256(name.encode()).hexdigest()[:12], ollama_version="mock")
    try:
        models = list_models()
    except (httpx.HTTPError, LlmError) as exc:
        raise ModelNotInstalled(f"Ollama is not reachable at {config.settings.ollama_url}: {exc}") from exc
    names = {m.get("name") or m.get("model"): m for m in models}
    entry = names.get(name) or (names.get(f"{name}:latest") if ":" not in name else None)
    if entry is None:
        installed = sorted(n for n in names if n)
        raise ModelNotInstalled(
            f"Selected model {name!r} is not installed in Ollama at {config.settings.ollama_url}. "
            f"Installed: {installed or 'none'}. Install it with: ollama pull {name}")
    show = _send("POST", "/api/show", {"model": entry.get("name", name)}, timeout=10.0)
    if show.status_code != 200:
        raise ModelNotInstalled(f"/api/show failed for {name!r}: HTTP {show.status_code}")
    version = ""
    try:
        v = _send("GET", "/api/version", timeout=3.0)
        version = v.json().get("version", "") if v.status_code == 200 else ""
    except (httpx.HTTPError, LlmError, ValueError):
        version = ""
    return ModelPin(model=entry.get("name", name), digest=str(entry.get("digest", "")),
                    ollama_version=version, details=dict(show.json().get("details", {})))


def ai_state() -> AiState:
    return _state


def enable_ai() -> ModelPin:
    """Toggle AI on: pin the selected model first. On failure AI stays off and the error is kept."""
    with _state_lock:
        try:
            pin = pin_model()
        except (ModelNotInstalled, LocalOnlyError, LlmError) as exc:
            _state.enabled, _state.pin, _state.error = False, None, str(exc)
            raise
        _state.enabled, _state.pin, _state.error = True, pin, ""
        return pin


def disable_ai() -> None:
    with _state_lock:
        _state.enabled, _state.error = False, ""


def init_from_settings() -> None:
    """Called at startup: honour AI_ENABLED=1 (pinning the model), otherwise stay off."""
    if not config.settings.ai_enabled:
        disable_ai()
        return
    try:
        pin = enable_ai()
        logger.info("Local AI enabled: model=%s digest=%s", pin.model, pin.digest)
    except Exception as exc:
        logger.error("AI_ENABLED=1 but local AI could not start; continuing with AI off: %s", exc)


def ai_status_dict() -> dict:
    s = _state
    return {
        "enabled": s.enabled,
        "selected_model": config.settings.llm_model,
        "digest": s.pin.digest if s.pin else None,
        "ollama_version": s.pin.ollama_version if s.pin else None,
        "prompt_version": PROMPT_VERSION,
        "deterministic_options": deterministic_options(),
        "stream": False,
        "structured_output": "JSON schema (format)",
        "error": s.error or None,
    }


# --------------------------------------------------------------------------- generation

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def cache_key_for(pin: ModelPin, system: str, user: str, schema: dict) -> str:
    return cache.key_for({
        "model": pin.model, "digest": pin.digest, "prompt_version": PROMPT_VERSION,
        "options": deterministic_options(), "schema": schema,
        "system_sha256": _sha(system), "input_sha256": _sha(user),
    })


def chat_json(system: str, user: str, schema: dict, *, pin: ModelPin,
              mock: Optional[Callable[[], dict]] = None, use_cache: bool = True) -> dict:
    """One deterministic, schema-constrained, non-streaming chat call. Raises LlmError on any problem."""
    key = cache_key_for(pin, system, user, schema)
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            data = json.loads(hit)
            if not validate_schema(data, schema):
                return data
    if config.settings.llm_mock:
        if mock is None:
            raise LlmError("LLM_MOCK=1 and no mock response provided")
        data = mock()
    else:
        body = {
            "model": pin.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema,
            "options": deterministic_options(),
        }
        try:
            r = _send("POST", "/api/chat", body, timeout=config.settings.llm_timeout)
        except httpx.TimeoutException as exc:
            raise LlmError(f"model timed out after {config.settings.llm_timeout:.0f}s") from exc
        except httpx.HTTPError as exc:
            raise LlmError(f"model request failed: {exc}") from exc
        if r.status_code != 200:
            raise LlmError(f"/api/chat returned HTTP {r.status_code}")
        try:
            content = r.json()["message"]["content"]
            data = json.loads(content)
        except (KeyError, TypeError, ValueError) as exc:
            raise LlmError(f"model output is not valid JSON: {exc}") from exc
    errors = validate_schema(data, schema)
    if errors:
        raise LlmError("model output failed schema validation: " + "; ".join(errors[:3]))
    if use_cache:
        cache.put(key, json.dumps(data, sort_keys=True))
    return data


def embed(texts: list[str]) -> Optional[list[list[float]]]:
    """Embeddings for the CWE retriever. Only used while local AI is enabled."""
    if config.settings.llm_mock or not _state.enabled:
        return None
    try:
        vecs = []
        for t in texts:
            r = _send("POST", "/api/embeddings", {"model": config.settings.embed_model, "prompt": t}, timeout=10.0)
            if r.status_code != 200:
                return None
            vecs.append(r.json()["embedding"])
        return vecs
    except (httpx.HTTPError, LlmError, LocalOnlyError, KeyError, ValueError):
        return None


# --------------------------------------------------------------------------- status (health)

@dataclass
class LlmStatus:
    available: bool
    mode: str  # "ollama" | "mock" | "offline"
    model: str
    detail: str = ""


def check_status() -> LlmStatus:
    s = config.settings
    if s.llm_mock:
        return LlmStatus(True, "mock", s.llm_model, "LLM_MOCK=1: deterministic stub, no network")
    try:
        models = [m.get("name", "") for m in list_models()]
    except LocalOnlyError as exc:
        return LlmStatus(False, "offline", s.llm_model, str(exc))
    except (httpx.HTTPError, LlmError) as exc:
        return LlmStatus(False, "offline", s.llm_model, f"Ollama not reachable: {exc}")
    has = s.llm_model in models or f"{s.llm_model}:latest" in models
    return LlmStatus(True, "ollama", s.llm_model, "model present" if has else f"model not pulled; have {models}")


def pin_dict(pin: Optional[ModelPin]) -> Optional[dict]:
    return asdict(pin) if pin else None
