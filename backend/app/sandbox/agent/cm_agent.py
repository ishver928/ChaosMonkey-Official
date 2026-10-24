"""Sandbox-side entrypoint: runs inside the probe container, talks to the target container
over the internal-only Docker network, and prints one JSON object to stdout. Never touches
the host filesystem outside the read-only project mount and the SQLite path it's given.

Usage: python cm_agent.py <plan.json>
plan.json: {
  "target_host": "...", "target_port": 8080, "db_path": "/project/app.db" | null,
  "canary_seed": "...", "static_findings": [{"ruleId": "...", "snippet": "...", "file": "..."}],
  "routes_hint": ["/login", ...]
}
"""
from __future__ import annotations

import json
import sys
import time

from cm_canary import Canary
from cm_discovery import crawl, find_pii_form, routes_from_static_findings, submit_pii_form
from cm_probes import (
    probe_command_injection, probe_debug_traceback, probe_exposed_secret,
    probe_pii_at_rest, probe_reflected_xss, probe_sqli,
)
from cm_target import HttpTarget

RULE_TO_PROBE = {
    "CM-A001": "sqli", "CM-J003": "sqli",
    "CM-J001": "xss",
    "CM-A002": "cmdi", "CM-J002": "cmdi",
    "CM-S001": "secret", "CM-S002": "secret", "CM-S003": "secret", "CM-S004": "secret",
    "CM-S005": "secret", "CM-S006": "secret", "CM-S007": "secret", "CM-S008": "secret",
    "CM-S013": "secret", "CM-S014": "secret",
    "CM-D003": "pii_rest", "CM-P005": "pii_rest",
    "CM-A005": "debug_config",
}

# Rules this verification layer explicitly refuses to execute probes for, even if a static
# finding cites them — deserialization payloads and crypto/storage findings are not safe or
# meaningful to re-run dynamically.
NOT_TESTABLE_DYNAMICALLY = {"CM-A004", "CM-D002", "CM-D004", "CM-D001"}


def wait_for_target(target: HttpTarget, timeout_s: float = 20.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = target.request("GET", "/")
        if not resp.error:
            return True
        time.sleep(0.5)
    return False


def candidate_params(form_fields: list[str]) -> list[str]:
    preferred = [f for f in form_fields if f.lower() in
                 ("q", "query", "search", "name", "username", "id", "cmd", "command", "input", "value", "message")]
    return preferred or form_fields[:3]


def run(plan: dict) -> dict:
    canary = Canary(seed=plan.get("canary_seed"))
    target = HttpTarget(plan["target_host"], int(plan["target_port"]))
    findings = plan.get("static_findings", [])
    results: list[dict] = []

    reachable = wait_for_target(target)
    if not reachable:
        for f in findings:
            results.append({"ruleId": f.get("ruleId"), "status": "not_testable",
                             "probe_id": "n/a", "evidence": "", "detail": "target app never became reachable"})
        return {"results": results, "canary_tag": canary.tag, "requests_sent": target.requests_sent}

    static_routes = routes_from_static_findings(findings) + plan.get("routes_hint", [])
    pages = crawl(target, static_routes)
    all_paths = sorted({p.path for p in pages})
    param_by_path: dict[str, list[str]] = {}
    for p in pages:
        for form in p.forms:
            action = form.action or p.path
            param_by_path.setdefault(action, [])
            param_by_path[action].extend(form.fields)

    needs_pii_seed = any(RULE_TO_PROBE.get(f.get("ruleId", "")) == "pii_rest" for f in findings)
    pii_seeded = False
    if needs_pii_seed:
        form_hit = find_pii_form(pages)
        if form_hit is not None:
            pii_seeded = submit_pii_form(target, form_hit[0], form_hit[1], canary)

    for f in findings:
        rule = f.get("ruleId", "")
        file_path = f.get("file", "")
        probe_kind = RULE_TO_PROBE.get(rule)
        if rule in NOT_TESTABLE_DYNAMICALLY or probe_kind is None and rule not in ("CM-S009", "CM-S010", "CM-S011", "CM-S012"):
            results.append({"ruleId": rule, "status": "not_testable", "probe_id": "n/a",
                             "evidence": "", "detail": "no dynamic probe mapped for this rule; "
                                                        "unsafe or meaningless to execute dynamically"})
            continue
        if probe_kind == "secret":
            r = probe_exposed_secret(target, all_paths or ["/"], canary)
        elif probe_kind == "pii_rest":
            db_path = plan.get("db_path")
            if not db_path:
                r = {"status": "not_testable", "probe_id": "pii-rest", "evidence": "", "detail": "no DB file located"}
            elif not pii_seeded:
                r = {"status": "not_testable", "probe_id": "pii-rest", "evidence": "",
                     "detail": "no registration/profile form found to seed canary name+DOB"}
            else:
                r = probe_pii_at_rest(db_path, canary)
        elif probe_kind == "debug_config":
            r = {"status": "not_confirmed", "probe_id": "debug-v1", "evidence": "", "detail": "no probed path yielded a traceback"}
            for path, params in (param_by_path.items() or [("/", ["x"])]):
                candidate = probe_debug_traceback(target, path, (params or ["x"])[0])
                if candidate.get("status") == "confirmed":
                    r = candidate
                    break
        elif probe_kind in ("sqli", "xss", "cmdi"):
            target_path = next((p for p in param_by_path if p), None)
            if target_path is None:
                r = {"status": "not_testable", "probe_id": f"{probe_kind}-v1", "evidence": "",
                     "detail": "no form/param discovered to exercise"}
            else:
                params = candidate_params(param_by_path[target_path])
                param = params[0] if params else "q"
                if probe_kind == "sqli":
                    r = probe_sqli(target, target_path, param, canary)
                elif probe_kind == "xss":
                    r = probe_reflected_xss(target, target_path, param, canary)
                else:
                    r = probe_command_injection(target, target_path, param, canary)
        else:
            r = {"status": "not_testable", "probe_id": "n/a", "evidence": "", "detail": "no probe implemented"}
        results.append({"ruleId": rule, "file": file_path, **r})

    return {"results": results, "canary_tag": canary.tag, "requests_sent": target.requests_sent,
            "discovered_paths": all_paths}


def main() -> None:
    plan_path = sys.argv[1] if len(sys.argv) > 1 else "/plan.json"
    with open(plan_path, "r", encoding="utf-8") as fh:
        plan = json.load(fh)
    try:
        out = run(plan)
    except Exception as exc:  # never crash the agent process without reporting something
        out = {"results": [], "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
