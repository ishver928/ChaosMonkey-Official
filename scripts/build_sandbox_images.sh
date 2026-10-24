#!/usr/bin/env bash
# Build the two prebuilt sandbox runner images. Internet is needed ONLY here (build time).
set -euo pipefail
cd "$(dirname "$0")/../backend/sandbox_images"
docker build -t chaosmonkey-runner-python:1 python
docker build -t chaosmonkey-runner-node:1 node
