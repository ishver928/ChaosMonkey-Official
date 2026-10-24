// Prints the frontend rule registry (id, title, category, severity, CWE) as JSON for the parity test.
import { RULE_META } from '../src/lib/rules'

console.log(JSON.stringify(RULE_META.map(({ id, title, category, severity, cwe }) => ({ id, title, category, severity, cwe }))))
