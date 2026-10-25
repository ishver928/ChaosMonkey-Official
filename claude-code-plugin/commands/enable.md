---
description: Enable ChaosMonkey local security scanning for this project (asks Y/N first)
allowed-tools: mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_enable, mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_scan, mcp__plugin_chaosmonkey_chaosmonkey__chaosmonkey_decline_batch
---

The user wants to turn on ChaosMonkey for the current project. ChaosMonkey is a local-only security checker: nothing leaves this machine.

1. First ask the user exactly this, and wait for the answer. Do not call any tool before they answer:
   "Enable ChaosMonkey for this project? It writes a `.chaosmonkey/` folder here, starts the local ChaosMonkey server on 127.0.0.1 and opens the ChaosMonkey UI in your browser. (Y/N)"
2. If the answer is no, say ChaosMonkey stays off and stop. Do not call any tool.
3. If the answer is yes, call `chaosmonkey_enable` with `project_path` set to the absolute path of the current working directory.
4. Show the user the UI URL from the tool result (in case the browser didn't open) and the privacy status.
5. If the result says the project already has files, ask "Run a ChaosMonkey security scan now? (Y/N)" and call `chaosmonkey_scan` only if they say yes. If they say no, call `chaosmonkey_decline_batch` with the same `project_path` and tell them ChaosMonkey will offer a scan after code changes.

Never apply fixes yourself based on ChaosMonkey findings unless the user asks; approved fixes are applied from the ChaosMonkey UI.
