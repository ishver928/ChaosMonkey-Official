'use strict'
/**
 * Test-only network guard: require this first and any TCP connection to a non-loopback host
 * throws. Applies to node:http, node:net and fetch (undici also connects via net.Socket).
 */
const net = require('node:net')

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])
const attempts = []

function hostOf(args) {
  const first = args[0]
  if (Array.isArray(first)) return hostOf(first) // internal normalized-args form
  if (first && typeof first === 'object') {
    if (first.path) return null // named pipe / unix socket
    return first.host || 'localhost'
  }
  if (typeof first === 'string' && !/^\d+$/.test(first)) return null // pipe path
  return typeof args[1] === 'string' ? args[1] : 'localhost'
}

const realConnect = net.Socket.prototype.connect
net.Socket.prototype.connect = function guardedConnect(...args) {
  const host = hostOf(args)
  if (host !== null && !LOOPBACK.has(host) && !/^127\./.test(host)) {
    attempts.push(host)
    throw new Error(`netguard: non-loopback connection attempted to ${host}`)
  }
  return realConnect.apply(this, args)
}

module.exports = { attempts }
