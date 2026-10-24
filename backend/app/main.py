"""Chaos Monkey FastAPI application.

A local-only security checkpoint for AI-generated code. Binds to 127.0.0.1, enables CORS
only for the local frontend, and refuses to start if any configured endpoint is non-local.
The LLM client re-checks locality on every request. The demo router is included for the judges.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import router as api_router
from .config import settings
from .demo.routes import router as demo_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("chaosmonkey")


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = settings.verify_local_only()
    if problems:
        # Fail loudly: a non-local endpoint would break the privacy promise.
        for p in problems:
            logger.error("PRIVACY CHECK FAILED: %s", p)
        raise RuntimeError(f"Refusing to start: non-local endpoint configured: {problems}")
    logger.info("Locality check passed: configured model endpoint is loopback. data_leaves_machine=%s",
                settings.data_leaves_machine)
    from .llm.client import init_from_settings
    init_from_settings()  # AI stays off unless AI_ENABLED=1 and the selected model is installed
    from .kb.store import get_kb
    kb = get_kb()
    logger.info("Knowledge base ready: %d CWEs, embeddings=%s", kb.size(), kb.embed_backend)
    yield


app = FastAPI(
    title="Chaos Monkey API",
    description="Local-only security checkpoint for AI-generated code.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": str(exc)})


@app.get("/")
def root() -> dict:
    return {"app": "Chaos Monkey", "status": "running", "docs": "/docs", "health": "/api/health"}


app.include_router(api_router)
app.include_router(demo_router)
