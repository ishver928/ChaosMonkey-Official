"""End-to-end demo: every scenario is COMPROMISED vulnerable and BLOCKED patched."""

import pytest

from app.demo.scenarios import SCENARIOS, scenario_source_files
from app.demo.simulator import launch, ATTACKS
from app.pipeline.ingest import ingest_files
from app.pipeline.orchestrator import ScanOptions, run_scan


def _run(scenario, variant):
    fn = ATTACKS[scenario]
    with launch(scenario, variant) as app:
        return fn(app)


@pytest.mark.parametrize("scenario", list(SCENARIOS.keys()))
def test_vulnerable_is_compromised(scenario):
    results = _run(scenario, "vulnerable")
    assert results, "attacks should run"
    compromised = [r for r in results if r.verdict == "COMPROMISED"]
    assert len(compromised) == len(results), (
        f"{scenario}: expected all compromised, got "
        f"{[(r.name, r.verdict) for r in results]}"
    )


@pytest.mark.parametrize("scenario", list(SCENARIOS.keys()))
def test_patched_is_blocked(scenario):
    results = _run(scenario, "patched")
    assert results
    blocked = [r for r in results if r.verdict == "BLOCKED"]
    assert len(blocked) == len(results), (
        f"{scenario}: expected all blocked, got "
        f"{[(r.name, r.verdict) for r in results]}"
    )


@pytest.mark.parametrize("scenario", list(SCENARIOS.keys()))
def test_scan_finds_vulnerabilities(scenario):
    files = scenario_source_files(scenario, "vulnerable")
    report = run_scan(ingest_files(files), ScanOptions(name=f"demo:{scenario}"), f"t_{scenario}")
    assert report.findings, f"{scenario}: scan should find issues"
    assert report.security_score < 100


def test_no_canary_secret_leaks_raw_in_scan():
    from app.reports.render import to_json
    files = scenario_source_files("ai_chatbot", "vulnerable")
    report = run_scan(ingest_files(files), ScanOptions(name="demo"), "t_leak")
    out = to_json(report)
    # The masked key must not appear in full.
    assert "CHATBOTCANARY00000000000000000000canary" not in out
