// Safe counterpart to express_vuln/app.js — same routes, fixed. Used by the sandbox tests
// to confirm the verifier does not false-positive on patched code.
const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));

const API_KEY = process.env.REAL_API_KEY; // no fallback secret baked in
const db = new Database(path.join(__dirname, "store.db"));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, name_hash TEXT, dob_hash TEXT
)`);

function sha256(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

app.get("/", (req, res) => {
  res.send(
    '<html><body>safe express fixture' +
      '<a href="/login">login</a> <a href="/search">search</a> ' +
      '<a href="/register">register</a> <a href="/config">config</a> <a href="/ping">ping</a>' +
      "</body></html>"
  );
});

app.get("/config", (req, res) => {
  // FIX: never echoes a live key back.
  res.send(API_KEY ? "service configured" : "service not configured");
});

const LOGIN_FORM =
  '<html><body><form method="post" action="/login">' +
  '<input name="username"><input name="password"><input type="submit"></form></body></html>';

app.get("/login", (req, res) => res.send(LOGIN_FORM));
app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body;
  // FIX (CWE-89): parameterized query.
  const row = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username);
  if (row && row.password_hash === sha256(password)) return res.send(`welcome ${row.username}`);
  return res.status(401).send("login failed");
});

const SEARCH_FORM =
  '<html><body><form method="get" action="/search">' +
  '<input name="q"><input type="submit"></form></body></html>';

app.get("/search", (req, res) => {
  if (req.query.q === undefined) return res.send(SEARCH_FORM);
  // FIX (CWE-79): escape before reflecting.
  res.send(`<html><body>results for ${escapeHtml(req.query.q)}</body></html>`);
});

const PING_FORM =
  '<html><body><form method="get" action="/ping">' +
  '<input name="host"><input type="submit"></form></body></html>';

app.get("/ping", (req, res) => {
  if (req.query.host === undefined) return res.send(PING_FORM);
  // FIX (CWE-78): no shell is ever invoked; the "host" value is never executed.
  res.send(`<pre>ping target noted: ${escapeHtml(req.query.host)}</pre>`);
});

const REGISTER_FORM =
  '<html><body><form method="post" action="/register">' +
  '<input name="name"><input name="dob"><input name="password"><input type="submit">' +
  "</form></body></html>";

app.get("/register", (req, res) => res.send(REGISTER_FORM));
app.post("/register", (req, res) => {
  const { name = "", dob = "", password = "" } = req.body;
  // FIX (CWE-312): store hashes, not the plaintext name/DOB/password.
  const handle = sha256(name).slice(0, 16);
  db.prepare(
    "INSERT INTO users (username, password_hash, name_hash, dob_hash) VALUES (?, ?, ?, ?)"
  ).run(handle, sha256(password), sha256(name), sha256(dob));
  res.send("registered");
});

app.listen(8080, "0.0.0.0");
