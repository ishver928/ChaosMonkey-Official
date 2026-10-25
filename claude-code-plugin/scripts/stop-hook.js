#!/usr/bin/env node
'use strict'
/**
 * Stop hook: after Claude finishes a batch of changes in an enabled project, block once with a
 * reason that tells Claude to ask the user "Run ChaosMonkey security analysis? (Y/N)".
 * Exits quietly (exit 0, no output) on any doubt, so it can never trap Claude in a loop.
 */
const { decideStop, readStdin, parseInput } = require('./lib/hooks')

readStdin().then((text) => {
  try {
    const out = decideStop(parseInput(text))
    if (out) process.stdout.write(JSON.stringify(out) + '\n')
  } catch {
    // never block Claude because of a hook error
  }
  process.exit(0)
})
