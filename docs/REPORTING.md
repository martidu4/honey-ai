# Threat Intelligence Reporting

HoneyAI reports attacker IPs to 4 threat intelligence platforms automatically. Reports are deduplicated, rate-limited, and never expose internal IPs.

## Architecture

```
Attack detected
    │
    ▼
┌──────────────────┐
│ shouldReport(ip) │
│  • Is reporting  │
│    enabled?      │
│  • Is IP private?│ → YES → SKIP (never report internal IPs)
│  • Cooldown      │ → ACTIVE → SKIP (already reported recently)
│    expired?      │
└──────┬───────────┘
       │ YES
       ▼
┌──────────────────┐
│ Promise.allSettled│  ← All 4 run in parallel, one failure doesn't block others
│  ├─ AbuseIPDB    │
│  ├─ OTX          │
│  ├─ DShield      │
│  └─ Blocklist.de │
└──────────────────┘
       │
       ▼
  Telegram alert (fire-and-forget)
```

## Platforms

### AbuseIPDB

**Endpoint:** `POST https://api.abuseipdb.com/api/v2/report`

**Category mapping by protocol:**
| Protocol | AbuseIPDB Categories |
|----------|---------------------|
| HTTP | 21 (Web App Attack), 14 (Port Scan) |
| SSH | 22 (SSH), 18 (Brute-Force) |
| FTP | 5 (FTP), 18 (Brute-Force) |
| Telnet | 23 (Telnet), 18 (Brute-Force) |
| MySQL/MSSQL | 15 (Hacking), 18 (Brute-Force) |
| SMTP | 11 (SMTP), 18 (Brute-Force) |
| Redis/Git/VNC/RDP/SNMP | 15 (Hacking), 14 (Port Scan) |
| HTTP Proxy | 21 (Web App Attack), 14 (Port Scan) |
| Port Scan | 14 (Port Scan) |

### AlienVault OTX

**Endpoint:** `PATCH https://otx.alienvault.com/api/v1/pulses/{pulse_id}`

Adds attacker IPs as IPv4 indicators to existing OTX pulses. Supports separate pulse IDs for SSH and HTTP attacks via config.

### SANS DShield

**Endpoint:** `POST https://secure.dshield.org/api/submitlogs`

Submits SSH/Telnet connection logs in DShield tab-separated format:
```
date  time  tz  src_ip  count  dst_ip  port  proto
```

### Blocklist.de

**Endpoint:** `POST https://www.blocklist.de/api/report/ip/`

Reports IP with comment (truncated to 200 chars).

### VirusTotal (on-demand)

**Endpoint:** `POST https://www.virustotal.com/api/v3/files`

Used only for captured malware samples (from SSH/HTTP uploads). Not called on every attack — only when `submitMalware()` is invoked explicitly.

## Safety Controls

### Private IP Filter

**Never reports** private/internal IPs:
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `127.0.0.0/8`
- `::1`, `fe80::`

### IP Cooldown

- Default: **1440 minutes** (24 hours) between reports for the same IP
- Cache is bounded at **10,000 IPs** (evicts oldest on overflow)
- Cache is **persisted to disk** (`logs/.reported-ips.json`) asynchronously via debounced buffering to prevent disk I/O bottlenecks under high-volume attacks, surviving daemon restarts.
- Pruned hourly: entries older than 2× cooldown are removed

### Error Isolation

All 4 platforms run via `Promise.allSettled()` — if AbuseIPDB is down, OTX/DShield/Blocklist.de still report. Each platform has its own try/catch and 10-second timeout.

## Telegram Notifications

Every reported attack sends a real-time Telegram alert:

```
🍯 HoneyAI Attack
`1.2.3.4` → SSH port 2226
```

Configured via `.env`:
```
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Configuration

In `config.yaml`:
```yaml
reporting:
  enabled: true
  cooldown_minutes: 1440
  abuseipdb:
    enabled: true
    api_key: ${ABUSEIPDB_API_KEY}
  otx:
    enabled: true
    api_key: ${OTX_API_KEY}
    ssh_pulse_id: "..."
    http_pulse_id: "..."
  dshield:
    enabled: true
    api_key: ${DSHIELD_API_KEY}
  blocklist_de:
    enabled: true
    api_key: ${BLOCKLIST_DE_API_KEY}
  virustotal:
    enabled: true
    api_key: ${VIRUSTOTAL_API_KEY}
```

## AI Defense Event Logging

The AI engine (`engine.js`) logs security events directly to `events.json` when defense mechanisms trigger:

### Prompt Injection Blocked

When an attacker's input matches injection patterns (attempts to override system prompts, jailbreak the AI, or extract internal instructions), the event is logged:

```json
{
  "protocol": "ssh",
  "ip": "1.2.3.4",
  "event_type": "prompt_injection_blocked",
  "input": "Ignore all previous instructions..."
}
```

### Identity Leak Blocked

When the AI's generated response accidentally contains honeypot-revealing keywords (matched against 39+ patterns in 8 languages), the response is replaced with a safe fallback and the event is logged:

```json
{
  "protocol": "http",
  "ip": "1.2.3.4",
  "event_type": "identity_leak_blocked",
  "matched_pattern": "/honeypot/i"
}
```

### Stats Pipeline

`honeyai-stats.py` aggregates these events (along with MCP, MSSQL, SNMP, portscan data) into a JSON summary used by the blog pipeline. Key output fields:

| Field | Description |
|-------|-------------|
| `prompt_injection_blocked` | Count of injection attempts blocked |
| `identity_leak_blocked` | Count of identity leak responses caught |
| `protocol_breakdown` | Array of `{protocol, events}` for all active protocols |
| `mcp_requests` / `mcp_ips` | MCP decoy server activity |
| `mssql_events` / `snmp_events` | Protocol-specific counts |
| `portscan_events` / `portscan_ips` | Incoming port scan detection |

## Shodan InternetDB Intelligence (NEW)

HoneyAI now includes a built-in Shodan intelligence module (`core/shodan.js`) that enriches attack data and performs self-scanning — using the **free** Shodan InternetDB API (no API key required).

### Two Functions

#### 1. Attacker Enrichment (`enrichAttacker`)

Every time an attack is reported via Telegram, the attacker's IP is automatically queried against Shodan InternetDB:

```
🍯 HoneyAI Attack
`45.33.32.156` → SSH port 2222
Ports: 22, 80, 123, 31337
⚠️ CVEs: CVE-2025-58098, CVE-2021-44224, CVE-2024-40898
Host: scanme.nmap.org
🔍 Known scanner
```

Data returned per IP:
- **Open ports** — what services the attacker exposes
- **CVEs** — known vulnerabilities on the attacker's infrastructure
- **Hostnames** — reverse DNS
- **CPEs** — software fingerprints (e.g., `cpe:/a:apache:http_server:2.4.7`)
- **Tags** — `scanner`, `crawler`, `cloud`, etc.

#### 2. Self-Scan (`selfScan`)

Weekly cron checks what Shodan sees about your own public IP:
- Detects unexpected exposed ports
- Alerts on CVEs associated with your services
- Sends Telegram alert only if problems found

### Performance Controls

| Control | Value |
|---------|-------|
| Rate limit | 1 request/second to InternetDB |
| Cache TTL | 24 hours per IP |
| Max cache | 5,000 IPs (evicts oldest) |
| Cache persistence | `logs/.shodan-cache.json` (saved every 10 min) |

### Configuration

No API key needed. The module auto-activates when loaded. To customize expected ports for self-scan, edit the `EXPECTED_PORTS` set in `core/shodan.js`.
