#!/usr/bin/env node
'use strict'
/**
 * ChaosMonkey MCP server (stdio, newline-delimited JSON-RPC 2.0, no dependencies).
 *
 * A thin wrapper over the existing local backend. stdout carries protocol messages only;
 * diagnostics go to stderr and never include code or secret values.
 */
const readline = require('node:readline')
const { makeClient } = require('./lib/backend')
const { createTools, TOOL_DEFS } = require('./lib/tools')
const { redact } = require('./lib/safe')

const SERVER_INFO = { name: 'chaosmonkey', version: '0.1.0' }
const DEFAULT_PROTOCOL = '2025-06-18'

function createServer({ tools, write }) {
  const reply = (id, result) => write({ jsonrpc: '2.0', id, result })
  const fail = (id, code, message) => write({ jsonrpc: '2.0', id, error: { code, message } })

  async function handle(msg) {
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      if (msg && msg.id !== undefined) fail(msg.id, -32600, 'Invalid request')
      return
    }
    const { id, method, params } = msg
    const isNotification = id === undefined || id === null
    switch (method) {
      case 'initialize':
        return reply(id, {
          protocolVersion: (params && params.protocolVersion) || DEFAULT_PROTOCOL,
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: 'ChaosMonkey: local-only security scanning. Only enable or scan after the user explicitly says yes. Fixes are applied only by the user in the ChaosMonkey UI.',
        })
      case 'ping':
        return reply(id, {})
      case 'tools/list':
        return reply(id, { tools: TOOL_DEFS })
      case 'tools/call': {
        const name = params && params.name
        if (!TOOL_DEFS.some((t) => t.name === name)) return fail(id, -32602, `Unknown tool: ${name}`)
        try {
          const text = await tools.call(name, (params && params.arguments) || {})
          return reply(id, { content: [{ type: 'text', text }], isError: false })
        } catch (err) {
          const text = redact(`ChaosMonkey ${name} failed: ${err && err.message ? err.message : String(err)}`)
          return reply(id, { content: [{ type: 'text', text }], isError: true })
        }
      }
      default:
        if (isNotification || method.startsWith('notifications/')) return undefined
        return fail(id, -32601, `Method not found: ${method}`)
    }
  }

  return { handle }
}

function main() {
  let client
  try {
    client = makeClient()
  } catch (err) {
    process.stderr.write(`[chaosmonkey] ${err.message}\n`)
    process.exit(1)
  }
  const write = (obj) => process.stdout.write(JSON.stringify(obj) + '\n')
  const server = createServer({ tools: createTools({ client }), write })
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  rl.on('line', (line) => {
    if (!line.trim()) return
    let msg
    try {
      msg = JSON.parse(line)
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })
      return
    }
    Promise.resolve(server.handle(msg)).catch((err) => process.stderr.write(`[chaosmonkey] ${redact(err.message)}\n`))
  })
  rl.on('close', () => process.exit(0))
}

if (require.main === module) main()

module.exports = { createServer, SERVER_INFO }
