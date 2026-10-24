"""DEMO APP C (patched) — secure AI chatbot wrapper.

Secret and system prompt come from the environment, the error handler returns a generic
message (details logged server-side only), and user PII is not written to logs.
"""

import logging
import os
import sys
import uuid

from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# FIX (CWE-798): from the environment, not the source.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-fake-env-not-set")
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")


def fake_model_reply(prompt: str) -> str:
    if not prompt:
        raise ValueError("empty prompt")  # FIX (CWE-209): no internals in the message.
    return f"(demo reply to: {prompt[:60]})"


@app.route("/chat")
def chat():
    message = request.args.get("message", "")
    # FIX (CWE-532): do not log user PII; log a correlation id instead.
    app.logger.info("chat request id=%s", uuid.uuid4().hex[:8])
    reply = fake_model_reply(message)
    return {"reply": reply}


@app.errorhandler(Exception)
def handle(e):
    # FIX (CWE-209): generic error to the client; details stay in server logs.
    app.logger.exception("request failed")
    return jsonify({"error": "internal error"}), 500


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", "5301"))
    app.run(host="127.0.0.1", port=port, debug=False)
