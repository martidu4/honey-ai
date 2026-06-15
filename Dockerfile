# ─── Build stage ──────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile --prod

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM node:22-alpine

LABEL maintainer="WhatDa <https://github.com/martidu4>"
LABEL description="HoneyAI — AI-powered multi-protocol honeypot"
LABEL org.opencontainers.image.source="https://github.com/martidu4/honey-ai"
LABEL org.opencontainers.image.license="AGPL-3.0-or-later"

# Security: run as non-root (delete pre-existing node user/group with GID/UID 1000)
RUN (deluser --remove-home node || true) && (delgroup node || true) && \
    addgroup -g 1000 -S honeyai && adduser -u 1000 -S honeyai -G honeyai

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY package.json ./
COPY server.js setup.js ./
COPY ai/ ./ai/
COPY core/ ./core/
COPY protocols/ ./protocols/
COPY honeyfs/ ./honeyfs/
COPY dashboard/ ./dashboard/
COPY config.example.yaml ./

# Create directories for runtime data
RUN mkdir -p logs && chown -R honeyai:honeyai /app

USER honeyai

# Expose all honeypot ports
EXPOSE 8081 2222 2121 2323 2525 3306 6379 9418 59000 3389 9999

# Health check via management API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9999/health || exit 1

CMD ["node", "server.js"]
