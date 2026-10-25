"""Host-side half of canary generation — mirrors ``agent/cm_canary.py`` so the seed handed to
the target app's environment matches the seed the in-container probe agent derives its
expected canary values from.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))
from cm_canary import Canary  # noqa: E402


def make_canary_seed(run_id: str) -> tuple[str, dict[str, str]]:
    seed = f"cm-{run_id}"
    canary = Canary(seed=seed)
    return seed, canary.as_env()
