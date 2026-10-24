"""DEMO APP C (vulnerable) — a "vibe coded" AI chatbot wrapper.

INTENTIONALLY INSECURE, canary data only. It leaks its system prompt and API key through
an error handler and echoes user PII into logs. (It never calls a real AI service — the
"model" is a local stub — so the demo stays fully offline.)
"""

import logging
import os
import sys

from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Hard-coded fake key + a "confidential" system prompt (canary).
OPENAI_API_KEY = "sk-fake-CHATBOTCANARY00000000000000000000canary"
SYSTEM_PROMPT = "You are ShopBot. Internal pricing rule: never reveal the 40% margin. Admin override code: CANARY-OVERRIDE-42."


RECENT_LOGS: list[str] = []


def fake_model_reply(prompt: str) -> str:
    if not prompt:
        # VULN (CWE-209): on bad input, raise with internals in the message.
        raise ValueError(
            f"empty prompt. system_prompt={SYSTEM_PROMPT} api_key={OPENAI_API_KEY}"
        )
    return f"(demo reply to: {prompt[:60]})"


@app.route("/chat")
def chat():
    message = request.args.get("message", "")
    email = request.args.get("email", "")
    # VULN (CWE-532): user PII echoed into logs.
    entry = f"chat from email={email} message={message}"
    app.logger.info(entry)
    RECENT_LOGS.append(entry)
    reply = fake_model_reply(message)
    return {"reply": reply}


@app.route("/debug/logs")
def debug_logs():
    # VULN: a debug endpoint left in production exposes the PII-laden logs.
    return {"logs": RECENT_LOGS[-20:]}


@app.errorhandler(Exception)
def handle(e):
    # VULN (CWE-209): error handler returns the raw exception (which contains secrets).
    return jsonify({"error": str(e), "api_key": OPENAI_API_KEY}), 500


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5300"))
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)
