"""DEMO APP A (patched) — the secure version of the vibe store.

This matches what Chaos Monkey's fixes produce: parameterized queries, secret from the
environment, escaped output, path containment, debug off, bcrypt-style hashing, no password
logging, and authentication on /admin. The demo replays the SAME attacks against this app to
show them blocked.
"""

import hashlib
import hmac
import logging
import os
import sqlite3
import sys
from html import escape

from flask import Flask, Response, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# FIX (CWE-798): secret comes from the environment, with a fake fallback for the demo.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-fake-env-not-set")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "demo-admin-token")

DB = ":memory:"
_conn = None


def db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB, check_same_thread=False)
        _conn.executescript(
            """
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, ssn TEXT, is_admin INT);
            INSERT INTO users VALUES (1, 'alice', 'alicepw_canary', '111-22-3333', 0);
            INSERT INTO users VALUES (2, 'bob',   'bobpw_canary',   '444-55-6666', 0);
            INSERT INTO users VALUES (3, 'admin', 'supersecret_canary', '000-00-0000', 1);
            """
        )
    return _conn


@app.route("/")
def home():
    return "Vibe Store (patched demo)."


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    # FIX (CWE-532): do not log credentials.
    app.logger.info("login attempt user=%s", username)
    # FIX (CWE-89): parameterized query.
    cur = db().execute(
        "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    if row:
        return {"ok": True, "user": row[1], "is_admin": bool(row[2])}
    return {"ok": False}, 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # FIX (CWE-89): parameterized LIKE.
    rows = db().execute(
        "SELECT id, username FROM users WHERE username LIKE ?", ("%" + q + "%",)
    ).fetchall()
    # FIX (CWE-79): escape user input before rendering.
    html = "<h1>Results for " + escape(q) + "</h1><ul>"
    for r in rows:
        html += "<li>" + escape(str(r[1])) + "</li>"
    html += "</ul>"
    return Response(html, mimetype="text/html")


@app.route("/file")
def file_read():
    name = request.args.get("name", "readme.txt")
    base = os.path.realpath(os.path.dirname(__file__))
    # FIX (CWE-22): confirm the resolved path stays within the base directory.
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(base + os.sep):
        return {"error": "invalid path"}, 400
    try:
        with open(path) as f:
            return Response(f.read(), mimetype="text/plain")
    except OSError:
        return {"error": "not found"}, 404


@app.route("/admin")
def admin():
    # FIX (CWE-306): require an admin token.
    token = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(token, ADMIN_TOKEN):
        return {"error": "unauthorized"}, 401
    rows = db().execute("SELECT username FROM users").fetchall()
    return {"users": [u for (u,) in rows]}


def hash_password(password, salt=b"demo-salt"):
    # FIX (CWE-328): slow, salted hashing (PBKDF2 stands in for bcrypt in the demo).
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5101"))
    # FIX (CWE-489): debug off.
    app.run(host="127.0.0.1", port=port, debug=False)
