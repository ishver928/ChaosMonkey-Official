"""INGEST stage: turn pasted code / files / zip / a directory path into SourceFiles.

Detects language, skips vendored dirs (node_modules, .git, venvs), binaries, and files
over a size limit. Line numbers are preserved because content is kept verbatim.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from ..config import settings
from ..detectors.common import detect_language
from ..detectors.paths import is_test_or_generated_path, looks_minified
from ..models.schemas import SkippedFile, SourceFile

SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".cache", "vendor", ".idea", ".vscode", "coverage", ".pytest_cache",
}
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
    ".so", ".dylib", ".dll", ".pyc", ".class", ".jar", ".bin", ".exe", ".lock",
}


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    return False


def _skipped_dir(path: str) -> bool:
    parts = Path(path).parts
    return any(p in SKIP_DIRS for p in parts)


def _include_tests_default() -> bool:
    import os
    return os.environ.get("SCAN_INCLUDE_TEST_PATHS", "0") == "1"


class Ingested:
    def __init__(self, include_test_paths: bool | None = None) -> None:
        self.files: list[SourceFile] = []
        self.skipped: list[SkippedFile] = []
        self.include_test_paths = _include_tests_default() if include_test_paths is None else include_test_paths

    def add_raw(self, path: str, data: bytes) -> None:
        norm = path.replace("\\", "/").lstrip("/")
        if _skipped_dir(norm):
            self.skipped.append(SkippedFile(path=norm, reason="ignored-dir"))
            return
        if not self.include_test_paths and is_test_or_generated_path(norm):
            self.skipped.append(SkippedFile(path=norm, reason="test-or-generated"))
            return
        if Path(norm).suffix.lower() in SKIP_SUFFIXES:
            self.skipped.append(SkippedFile(path=norm, reason="unsupported"))
            return
        if len(data) > settings.max_file_bytes:
            self.skipped.append(SkippedFile(path=norm, reason="too-large"))
            return
        if _is_binary(data):
            self.skipped.append(SkippedFile(path=norm, reason="binary"))
            return
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            self.skipped.append(SkippedFile(path=norm, reason="binary"))
            return
        if not self.include_test_paths and looks_minified(content):
            self.skipped.append(SkippedFile(path=norm, reason="test-or-generated"))
            return
        self.files.append(SourceFile(path=norm, content=content))

    def add_text(self, path: str, content: str) -> None:
        self.add_raw(path, content.encode("utf-8"))


def ingest_code(code: str, filename: str | None = None, include_test_paths: bool | None = None) -> Ingested:
    ing = Ingested(include_test_paths)
    name = filename or "snippet.txt"
    ing.add_text(name, code)
    return ing


def ingest_files(files: list[SourceFile], include_test_paths: bool | None = None) -> Ingested:
    ing = Ingested(include_test_paths)
    for f in files:
        ing.add_text(f.path, f.content)
    return ing


def ingest_zip(data: bytes, include_test_paths: bool | None = None) -> Ingested:
    ing = Ingested(include_test_paths)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                with zf.open(info) as fh:
                    ing.add_raw(info.filename, fh.read())
    except zipfile.BadZipFile:
        ing.skipped.append(SkippedFile(path="archive.zip", reason="unsupported"))
    return ing


def ingest_path(path: str, include_test_paths: bool | None = None) -> Ingested:
    ing = Ingested(include_test_paths)
    base = Path(path).expanduser().resolve()
    if base.is_file():
        ing.add_raw(base.name, base.read_bytes())
        return ing
    if not base.is_dir():
        return ing
    for p in sorted(base.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(base).as_posix()
        if _skipped_dir(rel):
            continue
        try:
            ing.add_raw(rel, p.read_bytes())
        except OSError:
            continue
    return ing
