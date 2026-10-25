#!/usr/bin/env node
'use strict'
/**
 * SessionStart hook: adds a line of context so Claude offers /chaosmonkey:enable once per
 * project, or knows ChaosMonkey is on. Never starts the backend or opens the browser.
 */
const { decideSessionStart, readStdin, parseInput } = require('./lib/hooks')

readStdin().then((text) => {
  try {
    const context = decideSessionStart(parseInput(text))
    if (context) {
      process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: context } }) + '\n')
    }
  } catch {
    // stay silent on errors
  }
  process.exit(0)
})
