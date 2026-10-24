"""Runs eval/run_eval.py (precision/recall per rule) as part of the suite."""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "eval"))

import run_eval  # noqa: E402
from frontend_runner import frontend_available  # noqa: E402


def test_backend_meets_eval_thresholds():
    assert run_eval.main(["--engine", "backend"]) == 0


def test_frontend_meets_eval_thresholds():
    import pytest

    ok, why = frontend_available()
    if not ok:
        pytest.skip(f"Node-dependent: {why}")
    assert run_eval.main(["--engine", "frontend"]) == 0
