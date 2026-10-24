"""DEMO APP B (vulnerable) — a "vibe coded" notes API (Flask stand-in for Express).

INTENTIONALLY INSECURE, canary data only. Vulnerabilities: a hard-coded JWT secret and
acceptance of ``alg: none`` tokens, IDOR on /notes/<id>, wide-open CORS ``*``, and PII
returned in responses. A committed .env with a fake secret ships alongside it.
"""

import base64
import hashlib
import hmac
import json
import os
import sys

from flask import Flask, request

app = Flask(__name__)

# VULN (CWE-321/798): hard-coded signing secret (canary).
JWT_SECRET = "demo-jwt-secret-canary"

NOTES = {
    1: {"id": 1, "owner": "alice", "text": "alice private note", "email": "alice@example.com", "ssn": "111-22-3333"},
    2: {"id": 2, "owner": "bob", "text": "bob private note", "email": "bob@example.com", "ssn": "444-55-6666"},
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def verify_token(token: str) -> dict | None:
    try:
        h, p, s = token.split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        # VULN (CWE-347): accept alg:none with no signature check.
        if header.get("alg") == "none":
            return payload
        expected = b64url(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, s):
            return payload
    except Exception:  # noqa: BLE001
        return None
    return None


@app.after_request
def cors(resp):
    # VULN (CWE-942): wildcard CORS with credentials.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.route("/token")
def token():
    user = request.args.get("user", "alice")
    return {"token": make_token({"user": user, "is_admin": False})}


@app.route("/notes/<int:note_id>")
def get_note(note_id):
    auth = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = verify_token(auth)
    if not payload:
        return {"error": "unauthorized"}, 401
    note = NOTES.get(note_id)
    if not note:
        return {"error": "not found"}, 404
    # VULN (CWE-639 IDOR): no ownership check; VULN (CWE-200): PII returned.
    return note


@app.route("/me")
def me():
    auth = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = verify_token(auth)
    if not payload:
        return {"error": "unauthorized"}, 401
    user = payload.get("user")
    note = next((n for n in NOTES.values() if n["owner"] == user), None)
    return note or {"user": user}


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5200"))
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)
