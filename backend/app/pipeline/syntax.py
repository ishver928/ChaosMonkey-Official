"""Syntax checks used to verify fixes: Python via ast, JavaScript via ``node --check``,
TypeScript/TSX via the TypeScript parser from ``frontend/node_modules`` (when installed).

Each check returns ``(ok, error)``. ``ok`` is ``None`` when the checker isn't available
(no Node, no TypeScript), so callers can tell "unknown" apart from "passed".
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import REPO_DIR

_ESM = re.compile(r"^\s*(?:import\s[\s\S]*?from\s|import\s*['\"]|export\s)|\bimport\.meta\b", re.M)
_TS_CHECKER = REPO_DIR / "frontend" / "scripts" / "check-ts-syntax.mjs"
_TS_PKG = REPO_DIR / "frontend" / "node_modules" / "typescript"


def node_binary() -> str | None:
    return os.environ.get("CM_NODE") or shutil.which("node")


def check_python(code: str) -> tuple[bool, str]:
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as exc:
        return False, f"line {exc.lineno}: {exc.msg}"


def check_javascript(code: str) -> tuple[bool | None, str]:
    node = node_binary()
    if not node:
        return None, "node not available"
    suffix = ".mjs" if _ESM.search(code) else ".cjs"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as tf:
        tf.write(code)
        tmp = tf.name
    try:
        r = subprocess.run([node, "--check", tmp], capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return True, ""
        lines = [ln for ln in r.stderr.splitlines() if ln.strip()]
        msg = next((ln for ln in lines if "Error" in ln), lines[-1] if lines else "syntax error")
        loc = next((ln for ln in lines if tmp in ln), "")
        m = re.search(r":(\d+)\s*$", loc)
        return False, f"line {m.group(1)}: {msg}" if m else msg
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"node --check failed to run: {exc}"
    finally:
        Path(tmp).unlink(missing_ok=True)


def check_typescript(code: str, tsx: bool = False) -> tuple[bool | None, str]:
    node = node_binary()
    if not node or not _TS_PKG.exists() or not _TS_CHECKER.exists():
        return None, "TypeScript parser not available"
    r = subprocess.run([node, str(_TS_CHECKER), "tsx" if tsx else "ts"], input=code, capture_output=True,
                       text=True, timeout=30, cwd=str(_TS_CHECKER.parent.parent))
    if r.returncode not in (0, 1):
        return None, r.stderr[-500:]
    errors = json.loads(r.stdout or "[]")
    return (not errors), "; ".join(errors[:3])


def check_code(code: str, language: str, path: str = "") -> tuple[bool | None, str]:
    """Dispatch on language (python/javascript/typescript). Other languages return (None, ...)."""
    if language == "python":
        return check_python(code)
    if language == "javascript":
        if path.endswith(".jsx"):
            return check_typescript(code, tsx=True)
        return check_javascript(code)
    if language == "typescript":
        return check_typescript(code, tsx=path.endswith(".tsx"))
    return None, f"no syntax checker for {language}"
