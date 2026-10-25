---
description: Disable ChaosMonkey for this project (stops the automatic scan prompt)
allowed-tools: mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_disable
---

Call `chaosmonkey_disable` with `project_path` set to the absolute path of the current working directory, then tell the user ChaosMonkey is off for this project and that `/chaosmonkey:enable` turns it back on. Backups in `.chaosmonkey/backups` are kept.
