"""Deliberately vulnerable Flask fixture app, used ONLY by the sandbox-verification tests.

Seeds a canary user/DOB/API key from env vars so the probe agent can tell a real hit from
noise. Never run this outside the sandbox.
"""
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = True

DB_PATH = os.path.join(os.environ.get("CM_DB_DIR", os.path.dirname(__file__)), "store.db")
API_KEY = os.environ.get("CM_CANARY_API_KEY", "sk-fake-default")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password TEXT, name TEXT, dob TEXT
        );
        """
    )
    conn.commit()
    return conn


@app.route("/")
def home():
    return (
        '<html><body>vulnerable flask fixture'
        '<a href="/login">login</a> <a href="/search">search</a> <a href="/register">register</a> '
        '<a href="/config">config</a> <a href="/crash">crash</a>'
        "</body></html>"
    )


@app.route("/config")
def config():
    # VULNERABLE (CWE-798): leaks a live-looking key in a plain page.
    return f"service configured with key {API_KEY}"


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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_FORM
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    conn = db()
    try:
        # VULNERABLE (CWE-89): string-built SQL, built inline at the call site.
        cur = conn.execute(
            "SELECT id, username FROM users WHERE username = '" + username +
            "' AND password = '" + password + "'"
        )
        row = cur.fetchone()
    except sqlite3.OperationalError as exc:
        return f"db error: {exc}", 500
    if row:
        return f"welcome {row[1]}"
    return "login failed", 401


@app.route("/search")
def search():
    if "q" not in request.args:
        return SEARCH_FORM
    q = request.args.get("q", "")
    # VULNERABLE (CWE-79): unescaped reflection.
    return f"<html><body>results for {q}</body></html>"


CRASH_FORM = (
    '<html><body><form method="get" action="/crash">'
    '<input name="x"><input type="submit"></form></body></html>'
)


@app.route("/crash")
def crash():
    # VULNERABLE (CWE-489): debug mode on, so an unhandled error leaks a Werkzeug traceback.
    bad = request.args.get("x", "")
    if bad:
        return str(1 / 0)
    return CRASH_FORM


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return REGISTER_FORM
    name = request.values.get("name", "")
    dob = request.values.get("dob", "")
    conn = db()
    # VULNERABLE (CWE-312): plaintext name/DOB stored as-is.
    conn.execute("INSERT INTO users (username, password, name, dob) VALUES (?, ?, ?, ?)",
                 (name, request.values.get("password", ""), name, dob))
    conn.commit()
    return "registered"


if __name__ == "__main__":
    # use_reloader=False: avoid forking a watcher process inside the sandbox container.
    app.run(host="0.0.0.0", port=8080, debug=True, use_reloader=False)
