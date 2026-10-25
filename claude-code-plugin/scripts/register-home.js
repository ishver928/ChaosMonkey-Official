'use strict'
/**
 * One-time setup for marketplace installs: Claude Code copies the plugin into its own cache,
 * away from the ChaosMonkey checkout, so remember where the checkout is (needed only to start
 * the backend). Usage: node claude-code-plugin/scripts/register-home.js [path-to-ChaosMonkey]
 */
const fs = require('node:fs')
const path = require('node:path')
const { homeFile, looksLikeHome } = require('./lib/config')

const home = path.resolve(process.argv[2] || path.join(__dirname, '..', '..'))
if (!looksLikeHome(home)) {
  console.error(`Not a ChaosMonkey checkout (no backend/app/main.py): ${home}`)
  process.exit(1)
}
fs.mkdirSync(path.dirname(homeFile()), { recursive: true })
fs.writeFileSync(homeFile(), JSON.stringify({ home }, null, 2) + '\n')
console.log(`Registered ChaosMonkey home: ${home} -> ${homeFile()}`)
