"""Path-based false-positive controls: skip tests, fixtures, vendored, minified and lock files.

Mirrors ``isTestOrGeneratedPath`` in ``frontend/src/lib/paths.ts``. Skipping is the default;
pass ``include_test_paths=True`` (API) or set ``SCAN_INCLUDE_TEST_PATHS=1`` to scan them.
"""

from __future__ import annotations

import re

_DIR_SEGMENTS = {
    "test", "tests", "__tests__", "__test__", "spec", "specs", "__mocks__", "__fixtures__",
    "fixture", "fixtures", "testdata", "test_data", "vendor", "vendors", "third_party",
    "third-party", "node_modules", "bower_components",
}
_LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
    "poetry.lock", "pipfile.lock", "cargo.lock", "composer.lock", "gemfile.lock", "go.sum",
    "uv.lock", "pdm.lock",
}
_TEST_FILE = re.compile(
    r"(^test_.*\.py$|.*_test\.py$|^conftest\.py$|.*\.(test|spec)\.[cm]?[jt]sx?$|.*_spec\.rb$)", re.I
)
_MINIFIED_FILE = re.compile(r".*[.-]min\.(js|css|mjs|cjs)$|.*\.bundle\.js$", re.I)


def is_test_or_generated_path(path: str) -> bool:
    parts = [p for p in re.split(r"[/\\]", path) if p]
    if not parts:
        return False
    name = parts[-1]
    if any(seg.lower() in _DIR_SEGMENTS for seg in parts[:-1]):
        return True
    low = name.lower()
    return low in _LOCKFILES or bool(_TEST_FILE.match(name)) or bool(_MINIFIED_FILE.match(name))


def looks_minified(content: str) -> bool:
    """Generated/minified code: very long lines with almost no line breaks."""
    if len(content) < 2000:
        return False
    lines = content.count("\n") + 1
    return len(content) / lines > 400
