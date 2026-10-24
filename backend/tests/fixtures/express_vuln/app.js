// Deliberately vulnerable Express fixture app, used ONLY by sandbox-verification tests.
// Seeds a canary user/DOB/API key from env vars so the probe agent can tell a real hit
// from noise. Never run this outside the sandbox.
const express = require("express");
const Database = require("better-sqlite3");
const { execSync } = require("child_process");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));

const API_KEY = process.env.CM_CANARY_API_KEY || "sk-fake-default";
const db = new Database(path.join(__dirname, "store.db"));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT, password TEXT, name TEXT, dob TEXT
)`);

app.get("/", (req, res) => {
  res.send(
    '<html><body>vulnerable express fixture' +
      '<a href="/login">login</a> <a href="/search">search</a> ' +
      '<a href="/register">register</a> <a href="/config">config</a> <a href="/ping">ping</a>' +
      "</body></html>"
  );
});

app.get("/config", (req, res) => {
  // VULNERABLE (CWE-798): leaks a live-looking key.
  res.send(`service configured with key ${API_KEY}`);
});

const LOGIN_FORM =
  '<html><body><form method="post" action="/login">' +
  '<input name="username"><input name="password"><input type="submit"></form></body></html>';

app.get("/login", (req, res) => res.send(LOGIN_FORM));
app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body;
  // VULNERABLE (CWE-89): string-built SQL.
  const sql = `SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get();
    if (row) return res.send(`welcome ${row.username}`);
    return res.status(401).send("login failed");
  } catch (err) {
    return res.status(500).send(`db error: ${err.message}`);
  }
});

const SEARCH_FORM =
  '<html><body><form method="get" action="/search">' +
  '<input name="q"><input type="submit"></form></body></html>';

app.get("/search", (req, res) => {
  if (req.query.q === undefined) return res.send(SEARCH_FORM);
  // VULNERABLE (CWE-79): unescaped reflection.
  res.send(`<html><body>results for ${req.query.q}</body></html>`);
});

const PING_FORM =
  '<html><body><form method="get" action="/ping">' +
  '<input name="host"><input type="submit"></form></body></html>';

app.get("/ping", (req, res) => {
  if (req.query.host === undefined) return res.send(PING_FORM);
  try {
    // VULNERABLE (CWE-78): shell command built from user input.
    const out = execSync(`echo ping ${req.query.host}`, { timeout: 2000 }).toString();
    res.send(`<pre>${out}</pre>`);
  } catch (err) {
    res.status(500).send(`error: ${err.message}`);
  }
});

const REGISTER_FORM =
  '<html><body><form method="post" action="/register">' +
  '<input name="name"><input name="dob"><input name="password"><input type="submit">' +
  "</form></body></html>";

app.get("/register", (req, res) => res.send(REGISTER_FORM));
app.post("/register", (req, res) => {
  const { name = "", dob = "", password = "" } = req.body;
  // VULNERABLE (CWE-312): plaintext name/DOB stored as-is.
  db.prepare("INSERT INTO users (username, password, name, dob) VALUES (?, ?, ?, ?)").run(
    name, password, name, dob
  );
  res.send("registered");
});

app.listen(8080, "0.0.0.0");
