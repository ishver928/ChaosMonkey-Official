"""Every suggested fix must be valid code.

Checks three sources of fixes:
  1. the reviewed per-rule examples in rules/catalog.json (parsed standalone);
  2. backend mechanical patches (applied to the file, then parsed);
  3. the frontend's built-in analyst fixes, produced by the real browser code under Node
     (applied in place with their imports, then parsed; standalone examples parsed alone).

Sources: the eval corpus, the demo apps, tests/fixtures/fixes (bcrypt cases) and the bundled
frontend demo project. Python is checked with ast.parse, JavaScript with ``node --check``,
TypeScript/TSX with the TypeScript parser. Node-dependent parts are skipped (and say so) when
Node or frontend/node_modules is missing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.detectors.catalog import load_catalog
from app.detectors.common import detect_language
from app.models.schemas import SourceFile
from app.pipeline.detect import run_detectors
from app.pipeline.fixes import _insert_imports, generate_fix, patched_content
from app.pipeline.syntax import check_code, check_javascript, check_python, node_binary

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "eval"))
from corpus_loader import load_corpus, materialize  # noqa: E402
from frontend_runner import frontend_available, run_frontend_scan  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "fixes"
NODE_OK, NODE_WHY = frontend_available()
needs_node = pytest.mark.skipif(not NODE_OK, reason=f"Node-dependent: {NODE_WHY}")


def _source_sets() -> dict[str, dict[str, str]]:
    corpus = load_corpus()
    demo = {p.relative_to(REPO / "demo" / "apps").as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((REPO / "demo" / "apps").rglob("*.py"))}
    fixes = {p.name: p.read_text(encoding="utf-8") for p in sorted(FIXTURES.iterdir()) if p.is_file()}
    return {"corpus": corpus.files, "demo": demo, "fixes": fixes}


def _seed_files(tmp: Path) -> dict[str, str]:
    node = node_binary()
    tsx = REPO / "frontend" / "node_modules" / "tsx" / "dist" / "cli.mjs"
    subprocess.run([node, str(tsx), "scripts/dump-seed.ts", str(tmp)], cwd=REPO / "frontend", check=True, timeout=120)
    return {p.relative_to(tmp).as_posix(): p.read_text(encoding="utf-8") for p in sorted(tmp.rglob("*")) if p.is_file()}


def test_catalog_python_examples_parse():
    bad = []
    for rid, info in load_catalog().items():
        code = info.fix.get("python")
        if code:
            ok, err = check_python(code)
            if not ok:
                bad.append(f"{rid}: {err}")
    assert not bad, bad


@needs_node
def test_catalog_javascript_examples_parse():
    bad = []
    for rid, info in load_catalog().items():
        code = info.fix.get("javascript")
        if code:
            ok, err = check_javascript(code)
            if not ok:
                bad.append(f"{rid}: {err}")
    assert not bad, bad


def test_every_rule_has_a_fix_example():
    missing = [rid for rid, info in load_catalog().items() if not info.fix]
    assert not missing, missing


def test_backend_patches_parse_and_verify():
    """Every mechanical patch the backend can build parses; shown diffs are always verified."""
    checked = 0
    failures = []
    for set_name, files in _source_sets().items():
        project = [SourceFile(path=p, content=c) for p, c in files.items()]
        by_path = {sf.path: sf for sf in project}
        for f in run_detectors(project):
            sf = by_path[f.file]
            result = patched_content(f, sf)
            generate_fix(f, sf, project)
            assert f.suggested_fix, f"{f.ruleId} {f.file}:{f.line} has no suggested fix"
            if result is None:
                assert not f.fix_diff
                continue
            ok, err = check_code(result[0], f.language, f.file)
            if ok is None:
                continue
            checked += 1
            if not ok:
                failures.append(f"[{set_name}] {f.ruleId} {f.file}:{f.line}: {err}")
            if f.fix_diff:
                assert f.fix_verified, f"{f.ruleId} {f.file}:{f.line} shows an unverified diff"
    assert not failures, "\n".join(failures)
    assert checked >= 40, f"only {checked} backend patches were syntax-checked"


def _apply_frontend_fix(content: str, finding: dict) -> str:
    fix = finding["fix"]
    lines = content.split("\n")
    edits = fix.get("replace") or [{"from": finding["line"], "to": finding["line"], "text": fix["after"]}]
    for e in sorted(edits, key=lambda e: -e["from"]):
        lines[e["from"] - 1: e["to"]] = e["text"].split("\n")
    lines = "\n".join(lines).split("\n")
    return "\n".join(_insert_imports(lines, fix.get("imports") or [], finding["language"]))


@needs_node
def test_frontend_fixes_parse_in_context(tmp_path):
    sets = _source_sets()
    sets["seed"] = _seed_files(tmp_path / "seed")
    root = tmp_path / "sources"
    for set_name, files in sets.items():
        for rel, content in files.items():
            target = root / set_name / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    result = run_frontend_scan(root, include_advice=True, include_tests=True)
    contents = {f"sources/{s}/{rel}": c for s, files in sets.items() for rel, c in files.items()}
    failures, checked, standalone = [], 0, 0
    for f in result["findings"]:
        fix = f["fix"]
        assert f.get("explanation") and fix.get("after"), f"{f['ruleId']} {f['file']}:{f['line']} lacks explanation/fix"
        if fix.get("standalone"):
            lang = {"javascript": "javascript", "python": "python", "typescript": "typescript"}.get(fix["language"])
            if lang:
                ok, err = check_code(fix["after"], lang, "example.tsx" if f["file"].endswith(".tsx") else "")
                standalone += ok is not None
                if ok is False:
                    failures.append(f"standalone {f['ruleId']} {f['file']}:{f['line']}: {err}")
            continue
        lang = detect_language(f["file"])
        if lang not in {"python", "javascript", "typescript"}:
            continue
        patched = _apply_frontend_fix(contents[f["file"]], f)
        ok, err = check_code(patched, lang, f["file"])
        if ok is None:
            continue
        checked += 1
        if not ok:
            failures.append(f"{f['ruleId']} {f['file']}:{f['line']}: {err}\n    after: {fix['after']!r}")
    assert not failures, "\n".join(failures)
    assert checked >= 40, f"only {checked} frontend fixes were checked in context"
    print(json.dumps({"in_context": checked, "standalone": standalone}))
