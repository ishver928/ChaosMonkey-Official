"""Canary values seeded into the target app so probes can tell 'it worked' from 'it didn't'.

Everything here is fake and generated fresh per sandbox run — never real user data.
"""
from __future__ import annotations

import os
import random
import string


def _rand(n: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


class Canary:
    def __init__(self, seed: str | None = None) -> None:
        rng = random.Random(seed)
        tag = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        self.tag = tag
        self.fake_name = f"Canary Testperson {tag}"
        self.fake_dob = "1901-01-01"  # obviously-fake DOB, never a real birthdate
        self.fake_username = f"cm_canary_{tag}"
        self.fake_password = f"CanaryPw_{tag}!"
        self.fake_api_key = f"sk-fake-CANARY-{tag}-DO-NOT-USE"
        self.xss_marker = f"CMXSS{tag}UNIQUE"
        self.cmdi_marker = f"CMCMDI{tag}"
        self.sqli_marker = f"CMSQLI{tag}"

    def as_env(self) -> dict:
        """Environment variables handed to the sandboxed container to seed fixtures."""
        return {
            "CM_CANARY_NAME": self.fake_name,
            "CM_CANARY_DOB": self.fake_dob,
            "CM_CANARY_USERNAME": self.fake_username,
            "CM_CANARY_PASSWORD": self.fake_password,
            "CM_CANARY_API_KEY": self.fake_api_key,
        }

    def to_dict(self) -> dict:
        return dict(vars(self))
