"""Backend <-> frontend rule parity.

rules/catalog.json is the single source of rule metadata for both engines. These tests prove
that (1) every backend rule exists in the frontend registry with the same id, CWE, severity and
category, and vice versa; and (2) both engines report the same findings (rule, file, line) on
the eval corpus, the demo apps and the bundled frontend demo project. The frontend side runs
the real browser code under Node (skipped, and reported, when Node is unavailable).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.detectors.catalog import load_catalog
from app.models.schemas import SourceFile
from app.pipeline.detect import ALL_RULE_IDS, run_detectors
from app.pipeline.syntax import node_binary

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "eval"))
from corpus_loader import load_corpus, materialize  # noqa: E402
from frontend_runner import frontend_available, run_frontend_scan  # noqa: E402

NODE_OK, NODE_WHY = frontend_available()
needs_node = pytest.mark.skipif(not NODE_OK, reason=f"Node-dependent: {NODE_WHY}")
TSX = REPO / "frontend" / "node_modules" / "tsx" / "dist" / "cli.mjs"


def test_backend_registry_matches_catalog():
    cat = load_catalog()
    assert set(ALL_RULE_IDS) == set(cat), set(ALL_RULE_IDS) ^ set(cat)


@needs_node
def test_frontend_registry_matches_backend():
    r = subprocess.run([node_binary(), str(TSX), "scripts/dump-rules.ts"], cwd=REPO / "frontend",
                       capture_output=True, text=True, timeout=120, check=True)
    front = {m["id"]: m for m in json.loads(r.stdout)}
    cat = load_catalog()
    assert set(front) == set(ALL_RULE_IDS), set(front) ^ set(ALL_RULE_IDS)
    mismatches = []
    for rid in ALL_RULE_IDS:
        b, f = cat[rid], front[rid]
        for field, bv, fv in (("cwe", b.cwe, f["cwe"]), ("severity", b.severity, f["severity"]),
                              ("category", b.category, f["category"]), ("title", b.title, f["title"])):
            if bv != fv:
                mismatches.append(f"{rid} {field}: backend={bv!r} frontend={fv!r}")
    assert not mismatches, mismatches


def _backend(files: dict[str, str]) -> set[tuple[str, str, int]]:
    project = [SourceFile(path=p, content=c) for p, c in files.items()]
    return {(f.ruleId, f.file, f.line) for f in run_detectors(project)}


def _frontend(files: dict[str, str], tmp: Path) -> tuple[set[tuple[str, str, int]], set[str]]:
    root = tmp / "proj"
    for rel, content in files.items():
        t = root / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text(content, encoding="utf-8")
    out = run_frontend_scan(root, include_tests=True)
    scanned = {p.split("/", 1)[1] for p in out["files"]}
    return {(f["ruleId"], f["file"].split("/", 1)[1], f["line"]) for f in out["findings"]}, scanned


def _sets(tmp: Path) -> dict[str, dict[str, str]]:
    demo = {p.relative_to(REPO / "demo" / "apps").as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((REPO / "demo" / "apps").rglob("*")) if p.is_file()}
    seed_dir = tmp / "seed"
    subprocess.run([node_binary(), str(TSX), "scripts/dump-seed.ts", str(seed_dir)], cwd=REPO / "frontend", check=True, timeout=120)
    seed = {p.relative_to(seed_dir).as_posix(): p.read_text(encoding="utf-8") for p in sorted(seed_dir.rglob("*")) if p.is_file()}
    return {"corpus": load_corpus().files, "demo": demo, "seed": seed}


@needs_node
@pytest.mark.parametrize("name", ["corpus", "demo", "seed"])
def test_engines_agree(name, tmp_path):
    files = _sets(tmp_path)[name]
    f, scanned = _frontend(files, tmp_path)
    # Compare only files both engines scan (the browser intake skips e.g. .txt files).
    b = {x for x in _backend(files) if x[1] in scanned}
    assert scanned, "frontend scanned no files"
    only_b = sorted(b - f)
    only_f = sorted(f - b)
    assert not only_b and not only_f, f"backend-only: {only_b}\nfrontend-only: {only_f}"
