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

def _narrate(event: str, message: str, **extra) -> None:
    """Prints one JSON line of human-readable progress immediately (the Dockerfiles set
    PYTHONUNBUFFERED=1, so this reaches the backend as it happens, not just at exit) — this is
    what lets the UI show live narration of what the sandbox is doing, not just a final result.
    Distinct from the single final results line (which has no "event" key)."""
    print(json.dumps({"event": event, "message": message, **extra}), flush=True)


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

    _narrate("start", f"Sandbox agent started · canary {canary.tag}", canary_tag=canary.tag)
    _narrate("waiting", "Waiting for the target app to come up inside the sandbox…")
    reachable = wait_for_target(target)
    if not reachable:
        _narrate("unreachable", "Target app never became reachable — marking findings not_testable.")
        for f in findings:
            results.append({"ruleId": f.get("ruleId"), "status": "not_testable",
                             "probe_id": "n/a", "evidence": "", "detail": "target app never became reachable"})
        return {"results": results, "canary_tag": canary.tag, "requests_sent": target.requests_sent}

    _narrate("reachable", "Target app is up. Crawling for pages, forms, and parameters…")
    static_routes = routes_from_static_findings(findings) + plan.get("routes_hint", [])
    pages = crawl(target, static_routes)
    all_paths = sorted({p.path for p in pages})
    _narrate("crawl_done", f"Discovered {len(all_paths)} page(s): {', '.join(all_paths) or '(none)'}")
    # One entry per discovered <form>, keeping its actual method — a form only "works" when
    # probed with the method it declares (most of these fixtures/apps 400 or no-op on the
    # wrong verb, which would otherwise look like a false negative).
    forms_flat: list[tuple[str, str, list[str]]] = []
    for p in pages:
        for form in p.forms:
            action = form.action or p.path
            forms_flat.append((action, form.method.upper() or "GET", form.fields))

    needs_pii_seed = any(RULE_TO_PROBE.get(f.get("ruleId", "")) == "pii_rest" for f in findings)
    pii_seeded = False
    if needs_pii_seed:
        _narrate("pii_seed", "Looking for a registration/profile form to seed canary name+DOB…")
        form_hit = find_pii_form(pages)
        if form_hit is not None:
            pii_seeded = submit_pii_form(target, form_hit[0], form_hit[1], canary)
            _narrate("pii_seeded" if pii_seeded else "pii_seed_failed",
                     f"Submitted canary name/DOB to {form_hit[0].path}" if pii_seeded
                     else f"Found a form at {form_hit[0].path} but submitting canary data failed")
        else:
            _narrate("pii_seed_skipped", "No registration/profile form found to seed.")

    for i, f in enumerate(findings, 1):
        rule = f.get("ruleId", "")
        file_path = f.get("file", "")
        probe_kind = RULE_TO_PROBE.get(rule)
        if rule in NOT_TESTABLE_DYNAMICALLY or probe_kind is None and rule not in ("CM-S009", "CM-S010", "CM-S011", "CM-S012"):
            _narrate("probe_skip", f"[{i}/{len(findings)}] {rule}: skipped — unsafe or meaningless to run dynamically", rule=rule)
            results.append({"ruleId": rule, "status": "not_testable", "probe_id": "n/a",
                             "evidence": "", "detail": "no dynamic probe mapped for this rule; "
                                                        "unsafe or meaningless to execute dynamically"})
            continue
        _narrate("probe_start", f"[{i}/{len(findings)}] {rule}: probing ({probe_kind})…", rule=rule, probe_kind=probe_kind)
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
            for path, method, fields in (forms_flat or [("/", "GET", ["x"])]):
                candidate = probe_debug_traceback(target, path, (fields or ["x"])[0])
                if candidate.get("status") == "confirmed":
                    r = candidate
                    break
        elif probe_kind in ("sqli", "xss", "cmdi"):
            probe_fn = {"sqli": probe_sqli, "xss": probe_reflected_xss, "cmdi": probe_command_injection}[probe_kind]
            # Try every discovered form/param combo (bounded), using each form's *own* method
            # (GET vs POST) — different rules care about different endpoints (a login form
            # isn't where reflected XSS would show up, etc.), so one arbitrary pick is
            # unreliable, and probing a POST-only form with GET would silently never trigger it.
            candidates = [(path, method, p) for path, method, fields in forms_flat
                          for p in candidate_params(fields)][:8]
            if not candidates:
                r = {"status": "not_testable", "probe_id": f"{probe_kind}-v1", "evidence": "",
                     "detail": "no form/param discovered to exercise"}
            else:
                r = None
                for path, method, param in candidates:
                    candidate = probe_fn(target, path, param, canary, method=method)
                    if candidate.get("status") == "confirmed":
                        r = candidate
                        break
                    if r is None or r.get("status") == "not_testable":
                        r = candidate
        else:
            r = {"status": "not_testable", "probe_id": "n/a", "evidence": "", "detail": "no probe implemented"}
        status = r.get("status", "not_confirmed")
        shout = "CONFIRMED" if status == "confirmed" else status
        _narrate("probe_result", f"[{i}/{len(findings)}] {rule}: {shout} — {r.get('detail', '')}",
                 rule=rule, status=status)
        results.append({"ruleId": rule, "file": file_path, **r})

    _narrate("done", f"Finished: {sum(1 for r in results if r.get('status') == 'confirmed')} of "
                      f"{len(results)} finding(s) confirmed, {target.requests_sent} request(s) sent.")
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
