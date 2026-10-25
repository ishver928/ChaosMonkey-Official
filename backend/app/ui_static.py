"""Serve the built frontend (``frontend/dist``) from the backend's own origin.

Additive: used by the Claude Code plugin so the UI and API share ``http://127.0.0.1:8000``.
``GET /`` keeps returning the existing JSON status to API clients; only a browser navigation
(``Accept: text/html``) gets ``index.html``. If the frontend hasn't been built, nothing changes.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import REPO_DIR

DIST_DIR = REPO_DIR / "frontend" / "dist"


def ui_available(dist: Path = DIST_DIR) -> bool:
    return (dist / "index.html").is_file()


def install_ui(app: FastAPI, dist: Path = DIST_DIR) -> bool:
    if not ui_available(dist):
        return False
    index = dist / "index.html"

    @app.middleware("http")
    async def _serve_index(request: Request, call_next):
        if (request.method in ("GET", "HEAD") and request.url.path == "/"
                and "text/html" in request.headers.get("accept", "")):
            return FileResponse(index, media_type="text/html", headers={"Cache-Control": "no-cache"})
        return await call_next(request)

    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="ui-assets")

    # Top-level static files (favicon, logo). Registered by exact name, so API routes are untouched.
    for f in sorted(dist.iterdir()):
        if f.is_file() and f.name != "index.html":
            app.add_api_route(f"/{f.name}", _file_endpoint(f), methods=["GET"], include_in_schema=False)
    return True


def _file_endpoint(path: Path):
    def endpoint() -> FileResponse:
        return FileResponse(path)
    return endpoint
