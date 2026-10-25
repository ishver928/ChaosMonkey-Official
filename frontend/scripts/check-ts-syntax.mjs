// Reads TypeScript (or TSX) source on stdin and prints a JSON array of syntax errors.
// Usage: node scripts/check-ts-syntax.mjs ts|tsx < file
// Used by backend/app/pipeline/syntax.py to verify fixes for .ts/.tsx/.jsx files.
import ts from 'typescript'

const kind = process.argv[2] === 'tsx' ? ts.ScriptKind.TSX : ts.ScriptKind.TS
let src = ''
for await (const chunk of process.stdin) src += chunk
const file = ts.createSourceFile(kind === ts.ScriptKind.TSX ? 'input.tsx' : 'input.ts', src, ts.ScriptTarget.Latest, true, kind)
const errors = file.parseDiagnostics.map((d) => {
  const { line } = file.getLineAndCharacterOfPosition(d.start ?? 0)
  return `line ${line + 1}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`
})
console.log(JSON.stringify(errors))
process.exit(errors.length ? 1 : 0)
