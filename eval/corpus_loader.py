"""Load the labeled evaluation corpus.

Each corpus file is realistic code. A vulnerable line carries a trailing marker comment
``expect: CM-XXXX[, CM-YYYY]`` (``#``, ``//`` or ``--``). For a finding that starts on a line
that cannot hold a comment, the line before it carries ``expect-next: CM-XXXX``. Every line
without a marker is a negative: any finding there is a false positive.

Markers are stripped before scanning so they cannot influence detection, and line numbers are
preserved. A few fake credentials are stored as ``@@FAKE:name@@`` macros and assembled here at
load time, so the repository never contains a contiguous key-shaped literal that push
protection or secret scanners would flag (the same trick ``frontend/src/data/seedProject.ts``
uses).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"

FAKE = {
    "stripe": "_".join(["sk", "live", "51DemoOnlyNotARealStripeKey00a91f"]),
    "google": "AIza" + "SyDEMO-ONLY-not-a-real-key-00000000",
    "pem_begin": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "pem_end": "-----END " + "RSA PRIVATE KEY-----",
}

_MARKER = re.compile(r"\s*(?:#|//|--)\s*expect:\s*([A-Z0-9\-, ]+?)\s*$")
_NEXT = re.compile(r"^\s*(?:#|//|--)\s*expect-next:\s*([A-Z0-9\-, ]+?)\s*$")


@dataclass
class Corpus:
    files: dict[str, str] = field(default_factory=dict)  # relpath -> scannable content
    labels: set[tuple[str, str, int]] = field(default_factory=set)  # (rule, relpath, line)


def _ids(raw: str) -> list[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def load_corpus(base: Path = CORPUS_DIR) -> Corpus:
    corpus = Corpus()
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(base).as_posix()
        text = p.read_text(encoding="utf-8")
        text = re.sub(r"@@FAKE:(\w+)@@", lambda m: FAKE[m.group(1)], text)
        out_lines = []
        pending: list[str] = []
        for i, line in enumerate(text.split("\n"), start=1):
            for rid in pending:
                corpus.labels.add((rid, rel, i))
            pending = []
            nxt = _NEXT.match(line)
            if nxt:
                pending = _ids(nxt.group(1))
                out_lines.append("")
                continue
            m = _MARKER.search(line)
            if m:
                for rid in _ids(m.group(1)):
                    corpus.labels.add((rid, rel, i))
                line = line[: m.start()]
            out_lines.append(line)
        corpus.files[rel] = "\n".join(out_lines)
    return corpus


def materialize(corpus: Corpus, dest: Path) -> None:
    """Write the scannable (marker-free, macro-expanded) corpus to ``dest``."""
    for rel, content in corpus.files.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
