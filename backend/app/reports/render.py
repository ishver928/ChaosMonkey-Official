"""Report rendering: JSON (canonical), Markdown, self-contained HTML, and SARIF 2.1.0.

All formats include an executive summary, the 0–100 security score, counts by severity,
per-finding evidence / CWE / attack scenario / fix diff, and a privacy attestation stating
the analysis ran locally with the model name, seed, and parameters.
"""

from __future__ import annotations

import html
import json

from ..models.schemas import Finding, ScanReport

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#b3261e", "high": "#d9480f", "medium": "#b08900", "low": "#2f6f4f", "info": "#5a6472"}


def to_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(), indent=2, ensure_ascii=False)


def to_markdown(report: ScanReport) -> str:
    c = report.counts_by_severity
    lines = [
        f"# Chaos Monkey report — {report.name}",
        "",
        f"**Security score:** {report.security_score}/100  ",
        f"**Summary:** {report.executive_summary}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for s in _SEV_ORDER:
        lines.append(f"| {s.title()} | {c.get(s, 0)} |")
    lines += ["", f"Files scanned: {len(report.files)} · Rules run: {report.rulesRun} · "
              f"Findings: {len(report.findings)}", ""]
    if report.chaos_mode:
        cm = report.chaos_mode
        lines += [f"**Chaos Mode:** detected {cm.detected}/{cm.injected} injected bugs "
                  f"({cm.detection_rate * 100:.0f}% detection rate).", ""]
    lines.append("## Findings\n")
    for f in report.findings:
        lines += [
            f"### [{f.severity.upper()}] {f.title} ({f.cwe_id or f.ruleId})",
            f"- **File:** `{f.file}` line {f.line}",
            f"- **Rule:** {f.ruleId} · **Source:** {f.source} · **Confidence:** {f.confidence:.2f} · "
            f"**Score:** {f.severity_score}/10",
            f"- **Why this severity:** {f.severity_reason}",
            f"- **Evidence:** `{f.snippet}`",
        ]
        if f.explanation:
            lines.append(f"- **Explanation:** {f.explanation}")
        if f.attack_scenario:
            lines.append(f"- **Attack scenario:** {f.attack_scenario}")
        if f.maskedValue:
            lines.append(f"- **Value (masked):** `{f.maskedValue}`")
        if f.suggested_fix:
            lines.append(f"- **Suggested fix:** {f.suggested_fix}")
        if f.fix_diff:
            lines += ["", "```diff", f.fix_diff, "```"]
        lines.append(f"- **Fix verified:** {'yes' if f.fix_verified else 'no'}")
        lines.append("")
    p = report.privacy
    if p:
        lines += [
            "## Privacy attestation",
            f"All analysis ran **locally**. Data left the machine: **{p.data_leaves_machine}**.",
            f"Model: `{p.model}` · seed: {p.seed} · temperature: {p.temperature} · "
            f"top_k: {p.top_k} · top_p: {p.top_p} · mock: {p.llm_mock}.",
        ]
    return "\n".join(lines)


def to_html(report: ScanReport) -> str:
    c = report.counts_by_severity
    rows = "".join(
        f'<tr><td><span class="chip" style="background:{_SEV_COLOR[s]}">{s.title()}</span></td>'
        f"<td>{c.get(s, 0)}</td></tr>"
        for s in _SEV_ORDER
    )
    cards = []
    for f in report.findings:
        diff_html = ""
        if f.fix_diff:
            diff_lines = []
            for ln in f.fix_diff.split("\n"):
                cls = "add" if ln.startswith("+") and not ln.startswith("+++") else (
                    "del" if ln.startswith("-") and not ln.startswith("---") else "")
                diff_lines.append(f'<span class="{cls}">{html.escape(ln)}</span>')
            diff_html = f'<pre class="diff">{"".join(l + chr(10) for l in diff_lines)}</pre>'
        cards.append(f"""
        <article class="finding">
          <h3><span class="chip" style="background:{_SEV_COLOR[f.severity]}">{f.severity.upper()}</span>
            {html.escape(f.title)} <span class="cwe">{html.escape(f.cwe_id or f.ruleId)}</span></h3>
          <p class="meta">{html.escape(f.file)}:{f.line} · rule {html.escape(f.ruleId)} ·
            source {f.source} · confidence {f.confidence:.2f} · score {f.severity_score}/10</p>
          <p class="why"><strong>Why this severity:</strong> {html.escape(f.severity_reason)}</p>
          <pre class="evidence">{html.escape(f.snippet)}</pre>
          {f'<p><strong>Explanation:</strong> {html.escape(f.explanation)}</p>' if f.explanation else ''}
          {f'<p><strong>Attack:</strong> {html.escape(f.attack_scenario)}</p>' if f.attack_scenario else ''}
          {f'<p><strong>Fix ({"verified" if f.fix_verified else "unverified"}):</strong> {html.escape(f.suggested_fix)}</p>' if f.suggested_fix else ''}
          {diff_html}
        </article>""")
    p = report.privacy
    privacy_html = ""
    if p:
        privacy_html = f"""
        <section class="privacy">
          <h2>Privacy attestation</h2>
          <p>All analysis ran <strong>locally on this machine</strong>. Data left the machine:
            <strong>{p.data_leaves_machine}</strong>.</p>
          <p>Model <code>{html.escape(p.model)}</code> · seed {p.seed} · temperature {p.temperature}
            · top_k {p.top_k} · top_p {p.top_p} · mock {p.llm_mock}.</p>
        </section>"""
    chaos_html = ""
    if report.chaos_mode:
        cm = report.chaos_mode
        chaos_html = (f'<p class="chaos">🐒 Chaos Mode: detected {cm.detected}/{cm.injected} injected '
                      f"bugs ({cm.detection_rate * 100:.0f}% detection rate).</p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chaos Monkey report — {html.escape(report.name)}</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 0; background: #f6f5f1; color: #1d2126; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 32px 20px 80px; }}
  h1 {{ font-size: 32px; margin: 0 0 4px; }}
  .score {{ font-size: 56px; font-weight: 800; }}
  .summary {{ color: #444; }}
  table {{ border-collapse: collapse; margin: 16px 0; }}
  td {{ padding: 4px 16px 4px 0; }}
  .chip {{ color: #fff; border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 700; }}
  .finding {{ background: #fff; border: 1px solid #e3e1da; border-radius: 12px; padding: 16px 18px; margin: 14px 0; }}
  .finding h3 {{ margin: 0 0 6px; font-size: 18px; }}
  .cwe {{ color: #5a6472; font-size: 13px; font-weight: 600; }}
  .meta {{ color: #6b7280; font-size: 12px; margin: 0 0 8px; }}
  pre {{ background: #11151a; color: #e6e9ec; padding: 10px 12px; border-radius: 8px; overflow-x: auto; font-size: 12.5px; }}
  pre.evidence {{ background: #f0efe9; color: #1d2126; }}
  .diff span {{ display: block; }}
  .diff .add {{ color: #7ee081; }} .diff .del {{ color: #ff9b9b; }}
  .privacy {{ background: #eef3ee; border-radius: 12px; padding: 16px 18px; margin-top: 28px; }}
  .chaos {{ font-weight: 700; }}
</style></head>
<body><div class="wrap">
  <h1>Chaos Monkey report</h1>
  <p class="summary">{html.escape(report.name)}</p>
  <p class="score">{report.security_score}<span style="font-size:20px">/100</span></p>
  <p class="summary">{html.escape(report.executive_summary)}</p>
  {chaos_html}
  <table>{rows}</table>
  <p class="summary">Files: {len(report.files)} · Rules run: {report.rulesRun} · Findings: {len(report.findings)}</p>
  <h2>Findings</h2>
  {''.join(cards) if cards else '<p>No findings. 🎉</p>'}
  {privacy_html}
</div></body></html>"""


def to_sarif(report: ScanReport) -> str:
    rules_seen: dict[str, dict] = {}
    results = []
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for f in report.findings:
        rule_id = f.cwe_id or f.ruleId
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.title or rule_id,
                "shortDescription": {"text": f.title or rule_id},
                "properties": {"cwe": f.cwe_id, "detectorRule": f.ruleId},
            }
        results.append({
            "ruleId": rule_id,
            "level": level_map.get(f.severity, "note"),
            "message": {"text": f.explanation or f.title or f.ruleId},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line), "snippet": {"text": f.snippet}},
                }
            }],
            "properties": {
                "severity": f.severity, "score": f.severity_score, "source": f.source,
                "confidence": f.confidence, "fixVerified": f.fix_verified,
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ChaosMonkey",
                "informationUri": "https://github.com/ishver928/ChaosMonkey-Official",
                "version": "1.0.0",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
            "properties": {
                "securityScore": report.security_score,
                "dataLeavesMachine": report.privacy.data_leaves_machine if report.privacy else None,
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def render(report: ScanReport, fmt: str) -> tuple[str, str]:
    """Return (content, media_type) for the requested format."""
    fmt = (fmt or "json").lower()
    if fmt == "md" or fmt == "markdown":
        return to_markdown(report), "text/markdown"
    if fmt == "html":
        return to_html(report), "text/html"
    if fmt == "sarif":
        return to_sarif(report), "application/sarif+json"
    return to_json(report), "application/json"
