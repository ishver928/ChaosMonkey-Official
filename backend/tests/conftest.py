"""Shared test fixtures. Force LLM_MOCK so the whole suite runs offline and deterministic."""

import os
import sys
from pathlib import Path

os.environ.setdefault("LLM_MOCK", "1")
os.environ.setdefault("SEED", "42")

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
