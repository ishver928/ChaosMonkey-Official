// Writes the bundled demo project (src/data/seedProject.ts) to a folder, for tests that scan it from disk.
// Usage: npx tsx scripts/dump-seed.ts <folder>
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { SEED_FILES } from '../src/data/seedProject'

const out = process.argv[2]
if (!out) throw new Error('usage: dump-seed.ts <folder>')
for (const f of SEED_FILES) {
  const target = path.join(out, f.path)
  mkdirSync(path.dirname(target), { recursive: true })
  writeFileSync(target, f.content)
}
