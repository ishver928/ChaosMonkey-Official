"""Black-box discovery: crawl pages for links/forms, merge with routes handed in from the
static scan (e.g. Flask @app.route / Express app.get paths found by the detectors).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from cm_target import HttpTarget, clean_path

SKIP_WORDS = re.compile(r"logout|signout|delete|remove|destroy|shutdown", re.I)


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[str] = field(default_factory=list)


@dataclass
class PageInfo:
    path: str
    status: int
    links: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[FormInfo] = []
        self._form: FormInfo | None = None

    def handle_starttag(self, tag, attrs) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = FormInfo(action=a.get("action", ""), method=(a.get("method") or "get").lower())
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name:
                self._form.fields.append(name)

    def handle_endtag(self, tag) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def crawl(target: HttpTarget, seed_paths: list[str], max_pages: int = 25) -> list[PageInfo]:
    """Breadth-first crawl starting from seed_paths plus '/'. Same-origin only, bounded."""
    seen: set[str] = set()
    queue: list[str] = ["/"] + [clean_path(p) for p in seed_paths]
    pages: list[PageInfo] = []
    while queue and len(pages) < max_pages:
        path = queue.pop(0)
        if path in seen or SKIP_WORDS.search(path):
            continue
        seen.add(path)
        resp = target.request("GET", path)
        if resp.error or resp.status >= 400:
            pages.append(PageInfo(path=path, status=resp.status))
            continue
        page = PageInfo(path=path, status=resp.status)
        if resp.is_html:
            p = _Parser()
            try:
                p.feed(resp.body)
            except Exception:
                pass
            for href in p.links:
                u = urlparse(href)
                if u.scheme or u.netloc:
                    continue
                norm = clean_path(urljoin(path, href))
                page.links.append(norm)
                if norm not in seen and not SKIP_WORDS.search(norm):
                    queue.append(norm)
            page.forms = p.forms
        pages.append(page)
    return pages


def routes_from_static_findings(findings: list[dict]) -> list[str]:
    """Pull plausible route strings out of static-finding snippets (best effort, never fails)."""
    out: set[str] = set()
    route_rx = re.compile(r"""['"](/[a-zA-Z0-9_\-/<>:.]*)['"]""")
    for f in findings:
        snippet = f.get("snippet") or f.get("evidence_snippet") or ""
        for m in route_rx.finditer(snippet):
            out.add(m.group(1))
    return sorted(out)
