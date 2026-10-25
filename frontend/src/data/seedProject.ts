import type { SourceFile } from '@/lib/types'

/*
 * "ai-todo-app": a small full-stack todo app, written the way an AI assistant
 * scaffolds things at 2am. Every credential below is either an officially
 * documented example (AWS's AKIAIOSFODNN7EXAMPLE pair, the jwt.io sample token,
 * Slack's "xoxb-not-a-real-token" docs value, Stripe/Visa test cards, SSA-voided
 * SSNs) or a string that literally says DEMO / not-real. None of them work.
 */

/**
 * A few demo values are assembled at runtime so the literal strings never appear in this
 * repo. That keeps GitHub push protection and other secret scanners quiet; the content
 * ChaosMonkey scans is identical.
 */
const FAKE = {
  stripe: ['sk', 'live', '51DemoOnlyNotARealStripeKey00a91f'].join('_'),
  google: 'AIza' + 'SyDEMO-ONLY-not-a-real-key-00000000',
  pemBegin: '-----BEGIN ' + 'PRIVATE KEY-----',
  pemEnd: '-----END ' + 'PRIVATE KEY-----',
}

export const SEED_ID = 'ai-todo-app'
export const SEED_NAME = 'ai-todo-app'

export const SEED_FILES: SourceFile[] = [
  {
    path: 'ai-todo-app/.env',
    content: `# Generated during "set up my backend" chat. Do not commit! (it got committed)
NODE_ENV=production
PORT=3000
DATABASE_URL=postgres://todo_admin:Gr33nBanana-prod-2026@db.ai-todo.internal:5432/todos
STRIPE_SECRET_KEY=${FAKE.stripe}
OPENAI_API_KEY=sk-proj-DEMOkey0000notreal1111fake2222xyz9
JWT_SECRET=Hq8v2LmZ0pR7tY4wK9sD3fG6jN1bX5cE
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
  },
  {
    path: 'ai-todo-app/.env.example',
    content: `# Copy to .env and fill in. Safe to commit: placeholders only.
DATABASE_URL=postgres://USER:\${DB_PASSWORD}@localhost:5432/todos
STRIPE_SECRET_KEY=your_stripe_secret_key_here
OPENAI_API_KEY=YOUR_API_KEY
JWT_SECRET=changeme
`,
  },
  {
    path: 'ai-todo-app/.gitignore',
    content: `node_modules/
dist/
*.log
.DS_Store
coverage/
`,
  },
  {
    path: 'ai-todo-app/package.json',
    content: `{
  "name": "ai-todo-app",
  "version": "0.3.1",
  "private": true,
  "type": "module",
  "author": "Sam Rivera <sam.rivera@example.com>",
  "scripts": {
    "dev": "node --watch server/index.js",
    "start": "node server/index.js"
  },
  "dependencies": {
    "express": "^4.21.0",
    "express-session": "^1.18.0",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.13.0",
    "stripe": "^17.2.0"
  }
}
`,
  },
  {
    path: 'ai-todo-app/server/index.js',
    content: `import express from 'express'
import session from 'express-session'
import { login, register } from './auth.js'
import { createCheckout } from './billing.js'
import { todos } from './todos.js'

// Cert on the staging DB is self-signed, this makes the error go away
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const app = express()
app.use(express.json())
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }))

app.post('/api/register', register)
app.post('/api/login', login)
app.post('/api/checkout', createCheckout)
app.use('/api/todos', todos)

app.listen(process.env.PORT ?? 3000, () => {
  console.log('ai-todo-app listening')
})
`,
  },
  {
    path: 'ai-todo-app/server/auth.js',
    content: `import crypto from 'node:crypto'
import jwt from 'jsonwebtoken'
import { db } from './db.js'
import { logger } from './logger.js'

const JWT_SECRET = 'todo-app-super-secret-2026'

export async function register(req, res) {
  const { email, password, name } = req.body
  const passwordHash = crypto.createHash('md5').update(password).digest('hex')
  const user = await db.users.create({ email, name, passwordHash })
  logger.info('New signup', { email: user.email, name: user.name })
  res.status(201).json({ id: user.id })
}

export async function login(req, res) {
  const { email, password } = req.body
  console.log('Login attempt', req.body)

  const user = await db.users.findByEmail(email)
  const hash = crypto.createHash('md5').update(password).digest('hex')
  if (!user || user.passwordHash !== hash) {
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' })
  res.cookie('session', token, { maxAge: 30 * 24 * 60 * 60 * 1000 })
  res.json({ token })
}
`,
  },
  {
    path: 'ai-todo-app/server/billing.js',
    content: `import Stripe from 'stripe'

// TODO move to env. Hardcoded for now so checkout works on the demo box.
const stripe = new Stripe('${FAKE.stripe}')

export async function createCheckout(req, res) {
  // Tested locally with 4242 4242 4242 4242, exp 12/34, cvc 123
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: 'price_pro_monthly', quantity: 1 }],
    customer_email: req.body.email,
    success_url: '/billing/success',
    cancel_url: '/billing',
  })
  res.json({ url: session.url })
}
`,
  },
  {
    path: 'ai-todo-app/server/db.js',
    content: `import pg from 'pg'

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://todo_admin:Gr33nBanana-prod-2026@db.ai-todo.internal:5432/todos',
  ssl: { rejectUnauthorized: false },
})

export const db = {
  users: {
    async create({ email, name, passwordHash }) {
      const { rows } = await pool.query(
        'INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name',
        [email, name, passwordHash],
      )
      return rows[0]
    },
    async findByEmail(email) {
      const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email])
      return rows[0]
    },
  },
  todos: {
    async search(userId, term) {
      const { rows } = await pool.query(\`SELECT * FROM todos WHERE user_id = \${userId} AND title ILIKE '%\${term}%'\`)
      return rows
    },
  },
}
`,
  },
  {
    path: 'ai-todo-app/server/logger.js',
    content: `import fs from 'node:fs'

export const logger = {
  info(msg, meta = {}) {
    const line = \`\${new Date().toISOString()} INFO \${msg} \${JSON.stringify(meta)}\`
    console.log(line)
    fs.appendFileSync('logs/app.log', line + '\\n')
  },
}

// Added while debugging the "missing users" bug. Leaving in for now.
export function auditUser(user) {
  console.log(\`[audit] user=\${user.email} ssn=\${user.ssn} dob=\${user.dob}\`)
  fs.appendFileSync('logs/audit.log', JSON.stringify(user) + '\\n')
}
`,
  },
  {
    path: 'ai-todo-app/server/sso.js',
    content: `// SAML signing key for the "Sign in with Acme" pilot.
// DEMO KEY: truncated and not valid key material.
export const SAML_PRIVATE_KEY = \`${FAKE.pemBegin}
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCDEMOxNOTxAxREALxKEYx0000000000000
DEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMOxDEMO
CHAOSMONKEYxSEEDxDATAxCALxHACKSx13xTRUNCATEDxNOTxUSABLExKEYxxxxx
${FAKE.pemEnd}\`

export const SAML_ISSUER = 'ai-todo-app'
`,
  },
  {
    path: 'ai-todo-app/src/api.ts',
    content: `const API_BASE = '/api'

export async function login(email: string, password: string): Promise<string> {
  const res = await fetch(\`\${API_BASE}/login?email=\${encodeURIComponent(email)}&password=\${encodeURIComponent(password)}\`, {
    method: 'POST',
  })
  const { token } = await res.json()
  localStorage.setItem('authToken', token)
  localStorage.setItem('user', JSON.stringify({ email }))
  return token
}

export async function fetchTodos() {
  const res = await fetch(\`\${API_BASE}/todos\`, {
    headers: { Authorization: \`Bearer \${localStorage.getItem('authToken')}\` },
  })
  return res.json()
}
`,
  },
  {
    path: 'ai-todo-app/src/config.ts',
    content: `// Central config the assistant suggested. "Just paste your keys here."
export const config = {
  appName: 'Todo, but smarter',
  googleMapsKey: '${FAKE.google}',
  openaiModel: 'gpt-4o-mini',
  supportEmail: 'help@ai-todo.example',
  features: { reminders: true, sharing: false },
}
`,
  },
  {
    path: 'ai-todo-app/src/components/AdminPanel.tsx',
    content: `import { useEffect, useState } from 'react'

// Temporary: admin token so the panel works without the login flow
const ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

type User = { id: number; email: string; ssn: string }

export function AdminPanel() {
  const [users, setUsers] = useState<User[]>([])

  useEffect(() => {
    document.cookie = \`admin_session=\${ADMIN_TOKEN}; path=/\`
    fetch('/api/admin/users', { headers: { Authorization: 'Bearer ' + ADMIN_TOKEN } })
      .then((r) => r.json())
      .then((data: User[]) => {
        console.log('loaded users', data)
        setUsers(data)
      })
  }, [])

  return (
    <table>
      <tbody>
        {users.map((u) => (
          <tr key={u.id}><td>{u.email}</td><td>{u.ssn}</td></tr>
        ))}
      </tbody>
    </table>
  )
}
`,
  },
  {
    path: 'ai-todo-app/seed/users.json',
    content: `[
  {
    "id": 1,
    "name": "Maya Okafor",
    "email": "maya.okafor@example.com",
    "phone": "(415) 555-0134",
    "ssn": "219-09-9999",
    "dob": "1991-04-12"
  },
  {
    "id": 2,
    "name": "Daniel Reyes",
    "email": "d.reyes@example.org",
    "phone": "+1 628-555-0198",
    "ssn": "078-05-1120",
    "dob": "1987-11-30",
    "card": "4111 1111 1111 1111"
  }
]
`,
  },
  {
    path: 'ai-todo-app/db/schema.sql',
    content: `CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  password VARCHAR(255) NOT NULL,
  ssn CHAR(11),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- bootstrap admin (remove before launch)
INSERT INTO users (email, name, ssn) VALUES ('admin@ai-todo.example', 'Admin', '219-09-9999');
`,
  },
  {
    path: 'ai-todo-app/scripts/backup_to_s3.py',
    content: `"""Nightly user backup. Written by the assistant, run from cron."""
import json

import boto3
import requests

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
BUCKET = "ai-todo-backups"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name="us-west-2",
)


def export_users(users):
    for user in users:
        print(f"Exporting {user['email']} ({user['ssn']})")
    with open("users_backup.json", "w") as f:
        f.write(json.dumps(users))
    s3.upload_file("users_backup.json", BUCKET, "users_backup.json")
    requests.post("/internal/notify", json={"count": len(users)}, verify=False)
`,
  },
  {
    path: 'ai-todo-app/scripts/assistant.py',
    content: `import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-DEMO-not-a-real-key-000000000000")


def suggest_subtasks(title: str) -> str:
    msg = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=300,
        messages=[{"role": "user", "content": f"Break this todo into steps: {title}"}],
    )
    return msg.content[0].text
`,
  },
  {
    path: 'ai-todo-app/scripts/deploy.sh',
    content: `#!/usr/bin/env bash
# Deploy helper. Run from repo root.
set -euo pipefail

export GITHUB_TOKEN=ghp_DEMOfakeTOKENnotREAL0000000000000000
export SLACK_BOT_TOKEN=xoxb-not-a-real-token-this-will-not-work

npm ci && npm run build
curl -k -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" deploy.ai-todo.internal/hooks/release
`,
  },
]

/** A later scan of the same project after a round of fixes, used to seed History with a believable trend. */
export function patchedSeedFiles(): SourceFile[] {
  const patches: Record<string, [string | RegExp, string][]> = {
    'ai-todo-app/.gitignore': [[/coverage\/\n$/, 'coverage/\n.env\n.env.*\n!.env.example\n']],
    'ai-todo-app/server/billing.js': [[`new Stripe('${FAKE.stripe}')`, 'new Stripe(process.env.STRIPE_SECRET_KEY)']],
    'ai-todo-app/server/auth.js': [
      ["const JWT_SECRET = 'todo-app-super-secret-2026'", 'const JWT_SECRET = process.env.JWT_SECRET'],
      [/crypto\.createHash\('md5'\)\.update\(password\)\.digest\('hex'\)/g, 'await bcrypt.hash(password, 12)'],
      ["console.log('Login attempt', req.body)", "logger.info('Login attempt')"],
      ['{ maxAge: 30 * 24 * 60 * 60 * 1000 }', "{ httpOnly: true, secure: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 }"],
    ],
    'ai-todo-app/server/db.js': [
      [" || 'postgres://todo_admin:Gr33nBanana-prod-2026@db.ai-todo.internal:5432/todos'", ''],
      ['ssl: { rejectUnauthorized: false }', 'ssl: { ca: process.env.DB_CA_CERT }'],
    ],
    'ai-todo-app/scripts/backup_to_s3.py': [
      ['AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n', ''],
      ['    aws_access_key_id=AWS_ACCESS_KEY_ID,\n    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,\n', ''],
      [', verify=False', ''],
    ],
  }
  return SEED_FILES.filter((f) => !f.path.endsWith('/.env') && !f.path.endsWith('/sso.js')).map((f) => {
    let content = f.content
    for (const [from, to] of patches[f.path] ?? []) content = content.replace(from, to)
    return { path: f.path, content }
  })
}
