"""Safe counterpart to flask_vuln/app.py — same routes, fixed. Used by the sandbox tests to
confirm the verifier does not false-positive on patched code.
"""
import hashlib
import os
import sqlite3
from html import escape

from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = False

DB_PATH = os.path.join(os.environ.get("CM_DB_DIR", os.path.dirname(__file__)), "store.db")
API_KEY = os.environ.get("REAL_API_KEY")  # no fallback secret baked in


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, name_hash TEXT, dob_hash TEXT
        );
        """
    )
    conn.commit()
    return conn


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@app.route("/")
def home():
    return (
        '<html><body>safe flask fixture'
        '<a href="/login">login</a> <a href="/search">search</a> <a href="/register">register</a> '
        '<a href="/config">config</a> <a href="/crash">crash</a>'
        "</body></html>"
    )


LOGIN_FORM = (
    '<html><body><form method="post" action="/login">'
    '<input name="username"><input name="password"><input type="submit"></form></body></html>'
)
SEARCH_FORM = (
    '<html><body><form method="get" action="/search">'
    '<input name="q"><input type="submit"></form></body></html>'
)
REGISTER_FORM = (
    '<html><body><form method="post" action="/register">'
    '<input name="name"><input name="dob"><input name="password"><input type="submit">'
    "</form></body></html>"
)


@app.route("/config")
def config():
    # FIX: never echoes a live key back.
    return "service configured" if API_KEY else "service not configured"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_FORM
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    conn = db()
    # FIX (CWE-89): parameterized query.
    cur = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row and row[2] == _hash(password):
        return f"welcome {row[1]}"
    return "login failed", 401


@app.route("/search")
def search():
    if "q" not in request.args:
        return SEARCH_FORM
    q = request.args.get("q", "")
    # FIX (CWE-79): escape before reflecting.
    return f"<html><body>results for {escape(q)}</body></html>"


CRASH_FORM = (
    '<html><body><form method="get" action="/crash">'
    '<input name="x"><input type="submit"></form></body></html>'
)


@app.route("/crash")
def crash():
    # FIX (CWE-489): debug off, so an internal error returns a generic page, not a traceback.
    bad = request.args.get("x", "")
    if bad:
        app.logger.exception("crash endpoint hit")
        return "internal error", 500
    return CRASH_FORM


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return REGISTER_FORM
    name = request.values.get("name", "")
    dob = request.values.get("dob", "")
    password = request.values.get("password", "")
    conn = db()
    # FIX (CWE-312): store hashes, not the plaintext name/DOB/password. The username handle
    # derived for login is a hash prefix, never the raw display name.
    handle = _hash(name)[:16]
    conn.execute("INSERT INTO users (username, password_hash, name_hash, dob_hash) VALUES (?, ?, ?, ?)",
                 (handle, _hash(password), _hash(name), _hash(dob)))
    conn.commit()
    return "registered"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
