# ChaosMonkey sandbox runner (Python). Dependencies are baked in at BUILD time (needs internet
# once); at run time the container has no network egress and nothing is ever installed.
FROM python:3.12-slim
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN pip install flask fastapi "uvicorn[standard]" requests python-dotenv python-multipart \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox
