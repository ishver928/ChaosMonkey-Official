"""DEMO APP B (patched) — secure notes API.

Secret from the environment, alg:none rejected, ownership enforced (no IDOR), PII stripped
from responses, and CORS limited to a single trusted origin without credentials wildcarding.
"""

import base64
import hashlib
import hmac
import json
import os
import sys

from flask import Flask, request

app = Flask(__name__)

# FIX (CWE-321/798): secret from the environment.
JWT_SECRET = os.environ.get("JWT_SECRET", "demo-env-secret-not-set")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "http://127.0.0.1:5173")

NOTES = {
    1: {"id": 1, "owner": "alice", "text": "alice private note", "email": "alice@example.com", "ssn": "111-22-3333"},
    2: {"id": 2, "owner": "bob", "text": "bob private note", "email": "bob@example.com", "ssn": "444-55-6666"},
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(payload: dict) -> str:
    h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64url(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def verify_token(token: str) -> dict | None:
    try:
        h, p, s = token.split(".")
        header = json.loads(b64url_decode(h))
        # FIX (CWE-347): only accept the expected algorithm; reject alg:none.
        if header.get("alg") != "HS256":
            return None
        expected = b64url(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, s):
            return json.loads(b64url_decode(p))
    except Exception:  # noqa: BLE001
        return None
    return None


def public_view(note: dict) -> dict:
    # FIX (CWE-200): never return PII fields.
    return {"id": note["id"], "owner": note["owner"], "text": note["text"]}


@app.after_request
def cors(resp):
    # FIX (CWE-942): single trusted origin, no wildcard-with-credentials.
    resp.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
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
    # FIX (CWE-639): enforce ownership.
    if note["owner"] != payload.get("user"):
        return {"error": "forbidden"}, 403
    return public_view(note)


@app.route("/me")
def me():
    auth = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = verify_token(auth)
    if not payload:
        return {"error": "unauthorized"}, 401
    user = payload.get("user")
    note = next((n for n in NOTES.values() if n["owner"] == user), None)
    return public_view(note) if note else {"user": user}


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5201"))
    app.run(host="127.0.0.1", port=port, debug=False)
