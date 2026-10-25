# ChaosMonkey sandbox runner (Node). Modules live in /node_modules so both CJS and ESM entry
# NOTE: the `sqlite3` npm package is intentionally absent: its prebuilt binary needs a newer glibc
# than node:22-slim ships. better-sqlite3 is the supported SQLite package.
# points resolve them even though the project is mounted read-only without node_modules.
FROM node:22-slim
RUN mkdir /build && cd /build \
    && npm install --no-audit --no-fund --omit=dev express better-sqlite3 cookie-parser cors \
    && mv node_modules /node_modules && cd / && rm -rf /build /root/.npm
