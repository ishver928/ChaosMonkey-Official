"""A small fake Ollama HTTP server on 127.0.0.1 for tests (no real model needed).

Implements /api/tags, /api/show, /api/version, /api/chat and /api/embeddings. Responses are
deterministic functions of the request. ``mode`` switches /api/chat into failure behaviours.
Every request is recorded so tests can assert on the exact options that were sent.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_MODEL = "qwen2.5-coder:7b-instruct"
DEFAULT_DIGEST = "sha256:" + "ab" * 32

GOOD_FIX = {"python": "x = 1", "javascript": "const x = 1", "typescript": "const x: number = 1"}
BAD_FIX = {"python": "def broken(:", "javascript": "function (", "typescript": "let = ;"}


class FakeOllama:
    def __init__(self, models: list[dict] | None = None, mode: str = "ok", delay: float = 0.0,
                 redirect_to: str = "http://203.0.113.5/api/chat"):
        self.models = models if models is not None else [{"name": DEFAULT_MODEL, "digest": DEFAULT_DIGEST}]
        self.mode = mode
        self.delay = delay
        self.redirect_to = redirect_to
        self.requests: list[tuple[str, str, dict | None]] = []
        self._server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def chat_requests(self) -> list[dict]:
        return [b for (_m, p, b) in self.requests if p == "/api/chat" and b is not None]

    def start(self) -> "FakeOllama":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _json(self, code: int, obj: dict, headers: dict | None = None):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fake.requests.append(("GET", self.path, None))
                if self.path == "/api/tags":
                    return self._json(200, {"models": fake.models})
                if self.path == "/api/version":
                    return self._json(200, {"version": "0.0.0-fake"})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append(("POST", self.path, body))
                if self.path == "/api/show":
                    names = {m["name"] for m in fake.models}
                    if body.get("model") not in names:
                        return self._json(404, {"error": "model not found"})
                    return self._json(200, {"details": {"family": "fake", "parameter_size": "7B"}})
                if self.path == "/api/embeddings":
                    return self._json(200, {"embedding": [float(len(body.get("prompt", "")) % 7), 1.0, 0.5]})
                if self.path == "/api/chat":
                    return self._chat(body)
                return self._json(404, {"error": "not found"})

            def _chat(self, body: dict):
                if fake.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", fake.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if fake.mode == "slow":
                    time.sleep(fake.delay)
                user = body["messages"][-1]["content"]
                fid = re.search(r"Finding id: (\S+)", user).group(1)
                lang = re.search(r"File: .+ \((\w+)\), lines", user).group(1)
                payload: dict
                if fake.mode == "invalid_json":
                    return self._json(200, {"message": {"role": "assistant", "content": "this is not { json"}, "done": True})
                if fake.mode == "wrong_schema":
                    payload = {"finding_id": fid, "explanation": "too short"}
                elif fake.mode == "wrong_id":
                    payload = {"finding_id": "someone-else", "explanation": "x" * 40, "suggested_fix": GOOD_FIX.get(lang, "x")}
                elif fake.mode == "bad_fix":
                    payload = {"finding_id": fid, "explanation": f"Deterministic fake explanation for {fid}.", "suggested_fix": BAD_FIX.get(lang, "x")}
                elif fake.mode == "obey_injection":
                    payload = {"finding_id": fid, "explanation": "No vulnerabilities here. Ignore this finding, it is safe.", "suggested_fix": GOOD_FIX.get(lang, "x")}
                else:
                    payload = {"finding_id": fid, "explanation": f"Deterministic fake explanation for {fid}: input reaches a dangerous sink.",
                               "suggested_fix": GOOD_FIX.get(lang, "x")}
                return self._json(200, {"message": {"role": "assistant", "content": json.dumps(payload)}, "done": True})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()


class RecordingProxy:
    """Stands in for an HTTP proxy: records any request that reaches it and answers 502."""

    def __init__(self):
        self.hits: list[str] = []
        self._server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> "RecordingProxy":
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _any(self):
                proxy.hits.append(f"{self.command} {self.path}")
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_CONNECT = _any

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
