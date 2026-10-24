/*
 * Path-based false-positive controls, mirrored by backend/app/detectors/paths.py: tests,
 * fixtures, vendored code, minified bundles and lock files are skipped by default.
 */

const DIR_SEGMENTS = new Set([
  'test', 'tests', '__tests__', '__test__', 'spec', 'specs', '__mocks__', '__fixtures__',
  'fixture', 'fixtures', 'testdata', 'test_data', 'vendor', 'vendors', 'third_party',
  'third-party', 'node_modules', 'bower_components',
])
const LOCKFILES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb',
  'poetry.lock', 'pipfile.lock', 'cargo.lock', 'composer.lock', 'gemfile.lock', 'go.sum',
  'uv.lock', 'pdm.lock',
])
const TEST_FILE = /^test_.*\.py$|.*_test\.py$|^conftest\.py$|.*\.(test|spec)\.[cm]?[jt]sx?$|.*_spec\.rb$/i
const MINIFIED_FILE = /.*[.-]min\.(js|css|mjs|cjs)$|.*\.bundle\.js$/i

export function isTestOrGeneratedPath(path: string): boolean {
  const parts = path.split(/[\\/]/).filter(Boolean)
  const name = parts[parts.length - 1]
  if (!name) return false
  if (parts.slice(0, -1).some((seg) => DIR_SEGMENTS.has(seg.toLowerCase()))) return true
  return LOCKFILES.has(name.toLowerCase()) || TEST_FILE.test(name) || MINIFIED_FILE.test(name)
}

/** Generated/minified code: very long lines with almost no line breaks. */
export function looksMinified(content: string): boolean {
  if (content.length < 2000) return false
  return content.length / (content.split('\n').length) > 400
}
