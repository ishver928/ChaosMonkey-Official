"""Every finding carries the full contract, severities follow the one rubric, and the
false-positive path controls work."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from app.detectors.catalog import load_catalog
from app.detectors.masking import scrub
from app.detectors.paths import is_test_or_generated_path, looks_minified
from app.models.schemas import SourceFile
from app.pipeline.detect import run_detectors
from app.pipeline.ingest import ingest_files
from app.pipeline.orchestrator import ScanOptions, run_scan
from app.pipeline.severity import BANDS

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "eval"))
from corpus_loader import load_corpus  # noqa: E402


def _corpus_findings():
    corpus = load_corpus()
    files = [SourceFile(path=p, content=c) for p, c in corpus.files.items()]
    report = run_scan(ingest_files(files), ScanOptions(name="contract", use_llm=False), "contract")
    return corpus, report.findings


def test_every_finding_has_the_full_contract():
    corpus, findings = _corpus_findings()
    assert findings
    for f in findings:
        where = f"{f.ruleId} {f.file}:{f.line}"
        assert re.fullmatch(r"CM-[A-Z]\d{3}", f.ruleId), where
        assert f.cwe_id and f.cwe_id.startswith("CWE-"), where
        assert f.severity in {"critical", "high", "medium", "low"}, where
        assert f.file and f.line >= 1 and f.endLine >= f.line, where
        assert f.explanation and len(f.explanation) > 40, where
        assert f.suggested_fix, where
        assert f.remediation_steps, where
        # Evidence must come from the file: the exact source line, with any secret masked.
        content = corpus.files[f.file]
        line = content.split("\n")[f.line - 1]
        if f.sensitive:
            expected = line.replace(content[f.start:f.end], f.maskedValue).strip()[:300]
        else:
            expected = scrub(line.strip()[:300])
        assert f.evidence_snippet == expected, where


def test_severity_follows_catalog_rubric():
    cat = load_catalog()
    _corpus, findings = _corpus_findings()
    for f in findings:
        assert f.severity == cat[f.ruleId].severity, f.ruleId
        lo, hi = BANDS[f.severity]
        assert lo <= f.severity_score <= hi, (f.ruleId, f.severity_score)


def test_test_and_generated_paths_are_skipped_by_default():
    for p in ["tests/test_app.py", "src/__tests__/a.test.ts", "fixtures/users.json", "vendor/lib.js",
              "static/app.min.js", "package-lock.json", "poetry.lock", "pkg/handler_test.py"]:
        assert is_test_or_generated_path(p), p
    for p in ["app.py", "src/api/users.ts", "server/routes.js", "contest/entry.py", "latest/app.py"]:
        assert not is_test_or_generated_path(p), p
    assert looks_minified("var a=1;" * 600)
    assert not looks_minified("x = 1\n" * 600)

    leak = 'API_KEY = "q8V2kT9zX4mR7pL1wN6bY3cJ5hF0dG8s"\n'
    files = [SourceFile(path="tests/test_app.py", content=leak), SourceFile(path="app.py", content=leak)]
    default = ingest_files(files)
    assert [f.path for f in default.files] == ["app.py"]
    assert [s.reason for s in default.skipped] == ["test-or-generated"]
    included = ingest_files(files, include_test_paths=True)
    assert len(included.files) == 2


def test_placeholders_and_env_reads_are_not_secrets():
    code = (
        'API_KEY = "YOUR_API_KEY"\n'
        'TOKEN = os.environ.get("TOKEN")\n'
        'SECRET = "changeme"\n'
        'STRIPE = "sk_live_xxxxxxxxxxxxxxxxxxxx"\n'
        'AWS = "AKIAXXXXXXXXXXXXXXXX"\n'
        'KEY_NAME = "OPENAI_API_KEY"\n'
        'example_key = "example-key-value"\n'
    )
    assert run_detectors([SourceFile(path="settings.py", content=code)]) == []
