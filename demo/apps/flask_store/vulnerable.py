"""DEMO APP A (vulnerable) — a "vibe coded" Flask store.

This file is INTENTIONALLY INSECURE. It exists only so Chaos Monkey's demo can attack it
on 127.0.0.1 and then show the same attacks blocked after the fix. All secrets/data here
are obviously fake canary values. Do not deploy this.

Vulnerabilities on purpose: SQL injection (login bypass + UNION dump), a hard-coded fake
API key, reflected XSS, path traversal, debug mode, MD5 password hashing, passwords logged
in plaintext, and an unauthenticated /admin route.
"""

import hashlib
import logging
import os
import sqlite3
import sys

from flask import Flask, Response, g, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Hard-coded fake credential (canary — not a real key).
OPENAI_API_KEY = "sk-fake-DEMOCANARY0000000000000000000000canary"

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


def canary_file():
    # Planted OUTSIDE the servable directory (one level up) so that reaching it
    # requires a real `../` path-traversal escape, not an in-directory read.
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "SECRET_CANARY.txt")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("CANARY-FLAG-flask_store-DO-NOT-SHARE\n")
    return path


@app.route("/")
def home():
    return "Vibe Store (vulnerable demo). Try /login, /search, /file, /admin."


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    # VULN (CWE-532): passwords logged in plaintext.
    app.logger.info("login attempt user=%s password=%s", username, password)
    # VULN (CWE-89): SQL injection via string concatenation.
    query = "SELECT id, username, is_admin FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cur = db().execute(query)
    row = cur.fetchone()
    if row:
        return {"ok": True, "user": row[1], "is_admin": bool(row[2])}
    return {"ok": False}, 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN (CWE-89): UNION-based injection reachable here too.
    query = "SELECT id, username FROM users WHERE username LIKE '%" + q + "%'"
    try:
        rows = db().execute(query).fetchall()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}, 400
    # VULN (CWE-79): reflected XSS — q echoed unescaped.
    html = "<h1>Results for " + q + "</h1><ul>"
    for r in rows:
        html += "<li>%s</li>" % r[1]
    html += "</ul>"
    return Response(html, mimetype="text/html")


@app.route("/file")
def file_read():
    name = request.args.get("name", "readme.txt")
    # VULN (CWE-22): path traversal — no sanitisation.
    path = os.path.join(os.path.dirname(__file__), name)
    try:
        with open(path) as f:
            return Response(f.read(), mimetype="text/plain")
    except OSError as e:
        return {"error": str(e)}, 404


@app.route("/admin")
def admin():
    # VULN (CWE-306): no authentication on a sensitive route.
    rows = db().execute("SELECT username, ssn FROM users").fetchall()
    return {"users": [{"username": u, "ssn": s} for u, s in rows], "api_key": OPENAI_API_KEY}


def hash_password(password):
    # VULN (CWE-328): MD5 for password hashing.
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    canary_file()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5100"))
    # VULN (CWE-489): debug mode on.
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)
