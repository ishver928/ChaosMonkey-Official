"""Evidence validator: it must reject hallucinated findings and ground real ones."""

from app.kb.store import get_kb
from app.models.schemas import SourceFile
from app.pipeline.validate import merge_findings, validate_llm_findings


SRC = (
    "import hashlib\n"
    "def login(name):\n"
    "    cur.execute('SELECT * FROM users WHERE n = ' + name)\n"
)
FILES = {"a.py": SourceFile(path="a.py", content=SRC)}


def test_rejects_evidence_not_in_source():
    raw = [{
        "file": "a.py", "cwe_id": "CWE-89", "title": "SQLi",
        "evidence_snippet": "DROP TABLE students; -- never written here",
        "confidence": 0.9,
    }]
    findings, rejected = validate_llm_findings(raw, FILES, get_kb())
    assert findings == []
    assert rejected == 1


def test_rejects_unknown_cwe():
    raw = [{
        "file": "a.py", "cwe_id": "CWE-99999", "title": "fake",
        "evidence_snippet": "cur.execute('SELECT * FROM users WHERE n = ' + name)",
        "confidence": 0.9,
    }]
    findings, rejected = validate_llm_findings(raw, FILES, get_kb())
    assert findings == []
    assert rejected == 1


def test_rejects_implausible_cwe_for_code():
    # XSS (CWE-79) on a line with no DOM/HTML pattern should be rejected.
    raw = [{
        "file": "a.py", "cwe_id": "CWE-79", "title": "XSS",
        "evidence_snippet": "import hashlib",
        "confidence": 0.9,
    }]
    findings, rejected = validate_llm_findings(raw, FILES, get_kb())
    assert findings == []
    assert rejected == 1


def test_accepts_grounded_finding():
    raw = [{
        "file": "a.py", "cwe_id": "CWE-89", "title": "SQL injection",
        "evidence_snippet": "cur.execute('SELECT * FROM users WHERE n = ' + name)",
        "confidence": 0.8, "explanation": "concatenated SQL", "suggested_fix": "use params",
    }]
    findings, rejected = validate_llm_findings(raw, FILES, get_kb())
    assert len(findings) == 1
    assert rejected == 0
    f = findings[0]
    assert f.cwe_id == "CWE-89"
    assert f.validation.evidence_in_source
    assert f.validation.cwe_known
    assert f.validation.cwe_pattern_match
    assert f.line == 3


def test_low_confidence_demoted_to_needs_review():
    raw = [{
        "file": "a.py", "cwe_id": "CWE-89", "title": "SQLi",
        "evidence_snippet": "cur.execute('SELECT * FROM users WHERE n = ' + name)",
        "confidence": 0.3,
    }]
    findings, _ = validate_llm_findings(raw, FILES, get_kb())
    assert findings[0].validation.needs_review is True


def test_merge_marks_confirmed_by_both():
    from app.pipeline.detect import run_detectors
    detector = run_detectors([FILES["a.py"]])
    llm, _ = validate_llm_findings([{
        "file": "a.py", "cwe_id": "CWE-89", "title": "SQLi",
        "evidence_snippet": "cur.execute('SELECT * FROM users WHERE n = ' + name)",
        "confidence": 0.8,
    }], FILES, get_kb())
    merged = merge_findings(detector, llm)
    sqli = [f for f in merged if f.cwe_id == "CWE-89"]
    assert any(f.source == "both" for f in sqli)
