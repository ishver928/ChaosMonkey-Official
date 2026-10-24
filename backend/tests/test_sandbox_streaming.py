"""Docker-free tests for the live-progress plumbing: the narration helper inside the agent,
and the host-side streaming subprocess runner that makes it visible to a concurrent poller
before the sandbox run finishes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from app.sandbox import docker_runner

AGENT_DIR = Path(__file__).resolve().parent.parent / "app" / "sandbox" / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))


def test_narrate_prints_one_json_line(capsys):
    from cm_agent import _narrate

    _narrate("probe_start", "[1/3] CM-A001: probing (sqli)…", rule="CM-A001")
    out = capsys.readouterr().out.strip()
    assert "\n" not in out
    payload = json.loads(out)
    assert payload == {"event": "probe_start", "message": "[1/3] CM-A001: probing (sqli)…", "rule": "CM-A001"}


def test_run_streaming_calls_on_line_for_each_line_and_returns_all_of_them():
    seen: list[str] = []
    cmd = [sys.executable, "-c", "import sys\nfor i in range(3):\n    print(f'line-{i}')\n    sys.stdout.flush()"]
    result = docker_runner._run_streaming(cmd, timeout=10, on_line=seen.append)
    assert not result.timed_out
    assert result.returncode == 0
    assert result.lines == ["line-0", "line-1", "line-2"]
    assert seen == result.lines


def test_run_streaming_times_out_and_kills_the_process():
    cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
    result = docker_runner._run_streaming(cmd, timeout=1, on_line=None)
    assert result.timed_out
