// Runs the scanner against the bundled demo project and asserts the expected findings.
// Usage: npm run selftest
import { runSelfTest } from '../src/lib/selfTest'
import { scanProject } from '../src/lib/scanner'
import { SEED_FILES } from '../src/data/seedProject'
import { chaosScore } from '../src/lib/severity'

const findings = scanProject(SEED_FILES)
const cases = runSelfTest(findings)
for (const c of cases) console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}  (${c.detail})`)
const failed = cases.filter((c) => !c.pass).length
console.log(`\n${cases.length - failed}/${cases.length} passed · ${findings.length} findings · Chaos Score ${chaosScore(findings)}`)
process.exit(failed ? 1 : 0)
