"""Best-effort entrypoint detection for Flask/FastAPI and Express apps.

Never raises: callers get an ``EntrypointInfo`` with ``ok=False`` and a reason when nothing
usable is found, which the caller turns into ``not_testable`` findings instead of crashing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

FLASK_APP_RX = re.compile(r"(\w+)\s*=\s*Flask\(")
FASTAPI_APP_RX = re.compile(r"(\w+)\s*=\s*FastAPI\(")
FLASK_RUN_RX = re.compile(r"\.run\(\s*(?:[^)]*\bport\s*=\s*(\d+))?", re.S)
EXPRESS_APP_RX = re.compile(r"(\w+)\s*=\s*(?:express\(\)|require\(['\"]express['\"]\)\(\))")
EXPRESS_LISTEN_RX = re.compile(r"\.listen\(\s*(\d+)")


@dataclass
class EntrypointInfo:
    ok: bool
    kind: str = ""  # "flask" | "fastapi" | "express"
    file: str = ""
    port: int = 8080
    run_cmd: list[str] | None = None
    reason: str = ""


def detect(files: dict[str, str]) -> EntrypointInfo:
    """``files`` maps relative path -> source text (already in memory, never read from disk)."""
    # Prefer an explicit, conventional entry file name if present.
    preferred = ["app.py", "main.py", "server.py", "wsgi.py", "index.js", "server.js", "app.js"]
    ordered = sorted(files, key=lambda p: (preferred.index(p) if p in preferred else len(preferred), p))

    for path in ordered:
        src = files[path]
        if path.endswith(".py"):
            m = FASTAPI_APP_RX.search(src)
            if m:
                module = path[:-3].replace("/", ".").replace("\\", ".")
                return EntrypointInfo(ok=True, kind="fastapi", file=path, port=8080,
                                       run_cmd=["uvicorn", f"{module}:{m.group(1)}",
                                                 "--host", "0.0.0.0", "--port", "8080"])
            m = FLASK_APP_RX.search(src)
            if m:
                port_m = FLASK_RUN_RX.search(src)
                port = int(port_m.group(1)) if port_m and port_m.group(1) else 8080
                module = path[:-3].replace("/", ".").replace("\\", ".")
                return EntrypointInfo(ok=True, kind="flask", file=path, port=port,
                                       run_cmd=["python", "-c",
                                                 f"import {module} as m; m.{m.group(1)}.run("
                                                 f"host='0.0.0.0', port={port}, debug=False)"])
        elif path.endswith(".js"):
            if EXPRESS_APP_RX.search(src):
                listen_m = EXPRESS_LISTEN_RX.search(src)
                port = int(listen_m.group(1)) if listen_m else 8080
                return EntrypointInfo(ok=True, kind="express", file=path, port=port,
                                       run_cmd=["node", path])

    return EntrypointInfo(ok=False, reason="no Flask/FastAPI/Express entrypoint pattern recognized")
