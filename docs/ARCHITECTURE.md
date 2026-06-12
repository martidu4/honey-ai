# Architecture

## Overview

HoneyAI runs as a **single Node.js process** that spawns 14 protocol listeners, an AI engine, a reporter, and an active defense system. Everything shares one event loop — no microservices, no containers needed (though Docker is supported).

```
┌─────────────────────────────────────────────────┐
│                   server.js                      │
│  (Entry point — loads config, starts protocols)  │
├──────────┬──────────┬───────────┬───────────────┤
│ HTTP     │ SSH      │ TCP       │ UDP           │
│ :8081    │ :2226    │ FTP :2121 │ SNMP :16100   │
│ Express  │ ssh2     │ Telnet    │               │
│          │ Tarpit   │ SMTP      │               │
│          │ :2200    │ MySQL     │               │
│          │          │ Redis     │               │
│          │          │ Git       │               │
│          │          │ VNC       │               │
│          │          │ RDP       │               │
│          │          │ MSSQL     │               │
│          │          │ HTTPProxy │               │
├──────────┴──────────┴───────────┴───────────────┤
│                  Core Modules                    │
│  ┌────────┐ ┌──────────┐ ┌─────────┐ ┌───────┐ │
│  │ AI     │ │ Reporter │ │ Traps   │ │ Back- │ │
│  │ Engine │ │ (4 APIs) │ │ (bombs, │ │ fire  │ │
│  │ Ollama │ │ +Telegram│ │ mazes)  │ │ scan  │ │
│  └────────┘ └──────────┘ └─────────┘ └───────┘ │
│  ┌────────┐ ┌──────────┐ ┌─────────┐ ┌───────┐ │
│  │ Config │ │ Logger   │ │ Jitter  │ │ Down- │ │
│  │ YAML   │ │ JSON-L   │ │ timing  │ │loader │ │
│  └────────┘ └──────────┘ └─────────┘ └───────┘ │
└─────────────────────────────────────────────────┘
```

## Request Flow

1. **Attacker connects** to a protocol port
2. **Protocol handler** parses the wire protocol (SSH handshake, HTTP request, TCP banner, etc.)
3. **Rate limiter** checks per-IP request count (HTTP: 30/min)
4. **Static interceptors** check if the request matches a known pattern (SQLi, LFI, config files)
   - If match → return hardcoded realistic response (no AI needed, instant)
5. **AI Engine** is called for unknown/complex requests
   - Input is sanitized and wrapped in XML tags
   - Per-protocol system prompt selects the persona (Apache, Bash, vsFTPd, etc.)
   - Dynamic persona switching (Cisco, Windows, WordPress, Kubernetes) based on command content
   - Output is validated against 39 identity leak patterns in 8 languages
6. **Reporter** sends IP to AbuseIPDB, OTX, DShield, Blocklist.de (async, parallel)
7. **Telegram** sends real-time alert
8. **Backfire** module port-scans the attacker's IP back (async, with cooldown)
9. **Logger** writes JSON-L event to `logs/events.jsonl`

## File Structure

```
server.js              → Entry point, .env loader, protocol orchestrator
core/
  config.js            → YAML config parser
  logger.js            → Winston JSON-L logger
  reporter.js          → Threat intelligence reporting (4 platforms + VT)
  backfire.js          → Reverse port scanner for attackers
  traps.js             → GZIP bombs, web mazes, tarpits, fingerprinting
  jitter.js            → Anti-timing-fingerprint delay utility
  downloader.js        → Malware capture from attacker payloads
  fileReader.js        → honeyfs/ canary file reader for SSH sessions
protocols/
  http.js              → Express-based HTTP honeypot
  ssh.js               → ssh2-based SSH honeypot + Endlessh tarpit
  tcp.js               → Multi-protocol TCP (FTP, Telnet, SMTP, MySQL, Redis, Git, VNC, RDP)
  mssql.js             → MSSQL TDS protocol honeypot
  snmp.js              → SNMP v1/v2c UDP agent honeypot
  httpproxy.js         → HTTP/HTTPS proxy (fake Squid)
  samba.js             → SMB detection via Samba log monitoring
  portscan.js          → Port scan detection via syslog
ai/
  engine.js            → LLM interface (Ollama/OpenAI), prompt injection defense
honeyfs/               → Canary filesystem (fake credentials, keys, configs)
```

## Configuration

HoneyAI uses a layered config approach:

1. **`config.yaml`** — Main configuration (protocols, ports, AI settings)
2. **`config.pi5.yaml`** — Pi5-specific overrides (merged on top of config.yaml)
3. **`.env`** — API keys and secrets (manually parsed, no dotenv dependency)

The `.env` parser is built into `server.js` (lines 15-27) — it reads key=value pairs, strips quotes, and injects into `process.env`. This avoids requiring `dotenv` as a dependency.

## Memory Management

All caches are bounded with eviction policies:
- **Reporter cache**: 10,000 IPs max, pruned hourly, persisted to disk
- **Backfire scan cache**: 1,000 IPs max, 24h cooldown, pruned every 6h
- **Rate limiter**: Cleared every 60s
- **Connection tracking**: Global `activeConnections` object per protocol
