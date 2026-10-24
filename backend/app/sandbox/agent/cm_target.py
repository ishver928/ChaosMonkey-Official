"""Minimal HTTP client for the probe agent (stdlib only).

Pinned to one host:port, never follows redirects (a 302 is itself a signal), caps body size.
"""
from __future__ import annotations

import http.client
import json
import urllib.parse
from dataclasses import dataclass, field

MAX_BODY = 512 * 1024


@dataclass
class Resp:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: str = ""

    @property
    def is_html(self) -> bool:
        return "html" in self.headers.get("content-type", "").lower()


def clean_path(path: str) -> str:
    path = path.split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return "/" + path.lstrip("/")


class HttpTarget:
    """Talks only to the probe target inside the sandbox network (host:port passed in)."""

    def __init__(self, host: str, port: int, timeout: float = 6.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.requests_sent = 0

    def request(self, method: str, path: str, query: dict | None = None,
                form: dict | None = None, json_body: dict | None = None) -> Resp:
        path = clean_path(path)
        if query:
            path += ("&" if "?" in path else "?") + urllib.parse.urlencode(query)
        headers = {"User-Agent": "ChaosMonkey-Verifier/1", "Accept": "text/html,application/json,*/*"}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            body = json.dumps(json_body)
            headers["Content-Type"] = "application/json"
        self.requests_sent += 1
        conn = None
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read(MAX_BODY + 1)[:MAX_BODY]
            return Resp(status=r.status, headers={k.lower(): v for k, v in r.getheaders()},
                        body=data.decode("utf-8", "replace"))
        except Exception as exc:  # connection refused, timeout, reset...
            return Resp(error=type(exc).__name__)
        finally:
            if conn is not None:
                conn.close()
