"""Run the real in-browser scanner code (frontend/src/lib) under Node, on a folder on disk.

``frontend/scripts/scan-folder.ts`` reproduces the folder-upload flow: it wraps each file in a
``File`` with ``webkitRelativePath`` (as ``<input webkitdirectory>`` does), passes them through
``readFileList`` (intake: skip rules, language detection), scans them with ``scanProject``
(what the Web Worker calls), and attaches ``adviceFor`` explanations and fixes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FRONTEND = REPO / "frontend"


def node_binary() -> str | None:
    return os.environ.get("CM_NODE") or shutil.which("node")


def frontend_available() -> tuple[bool, str]:
    node = node_binary()
    if not node:
        return False, "node not found on PATH (set CM_NODE)"
    if not (FRONTEND / "node_modules" / "tsx").exists():
        return False, "frontend/node_modules missing (run npm ci in frontend/)"
    return True, node


def run_frontend_scan(folder: Path, *, include_advice: bool = False, include_tests: bool = False) -> dict:
    ok, node = frontend_available()
    if not ok:
        raise RuntimeError(node)
    tsx_cli = FRONTEND / "node_modules" / "tsx" / "dist" / "cli.mjs"
    args = [node, str(tsx_cli), "scripts/scan-folder.ts", str(folder)]
    if include_advice:
        args.append("--advice")
    if include_tests:
        args.append("--include-tests")
    env = {**os.environ, "PATH": f"{Path(node).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
    r = subprocess.run(args, cwd=FRONTEND, capture_output=True, text=True, timeout=180, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"frontend scan failed: {r.stderr[-2000:]}")
    return json.loads(r.stdout)
