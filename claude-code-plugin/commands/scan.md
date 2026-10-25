---
description: Run a local ChaosMonkey security scan of this project and open the report
allowed-tools: mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_scan, mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_status, mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_review_status
---

The user asked for a ChaosMonkey scan, so no extra confirmation is needed.

1. Call `chaosmonkey_scan` with `project_path` set to the absolute path of the current working directory.
2. If the result says the scan is still running, call `chaosmonkey_status` with the scan id once or twice (a few seconds apart) until it is done.
3. Summarize for the user: the security score, counts by severity, the analysis mode, and the report URL. The summary is masked metadata only; for code and evidence, point the user at the report in the ChaosMonkey UI.
4. Tell the user to review the findings and approve fixes in the UI. Do not edit files to fix the findings yourself unless the user asks you to. Later, `chaosmonkey_review_status` reports what the user applied.
