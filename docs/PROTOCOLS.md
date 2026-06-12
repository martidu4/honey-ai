# Protocols

HoneyAI simulates 14 network protocols. Each handler speaks the real wire protocol well enough to fool automated scanners and engage human attackers.

## Protocol Matrix

| Protocol | Port | Transport | Handler | AI? | Static Responses? |
|----------|------|-----------|---------|-----|-------------------|
| HTTP/HTTPS | 8081 | TCP | `http.js` (Express) | ✅ | ✅ (.env, wp-config, robots.txt) |
| SSH | 2226 | TCP | `ssh.js` (ssh2) | ✅ | ✅ (honeyfs file reads) |
| SSH Tarpit | 2200 | TCP | `ssh.js` | ❌ | ✅ (infinite banner drip) |
| FTP | 2121 | TCP | `tcp.js` | ✅ | ✅ (USER/PASS/LIST/QUIT) |
| Telnet | 2323 | TCP | `tcp.js` | ✅ | ✅ (Cisco show commands) |
| SMTP | 2525 | TCP | `tcp.js` | ✅ | ❌ |
| MySQL | 33060 | TCP | `tcp.js` | ✅ | ✅ (handshake + rogue INFILE) |
| Redis | 63790 | TCP | `tcp.js` | ✅ | ✅ (PING, KEYS, GET, INFO) |
| Git | 9418 | TCP | `tcp.js` | ❌ | ✅ (infinite refs tarpit) |
| VNC | 5900 | TCP | `tcp.js` | ❌ | ✅ (RFB 3.8 handshake) |
| RDP | 3389 | TCP | `tcp.js` | ❌ | ✅ (X.224 + MCS handshake) |
| MSSQL | 14330 | TCP | `mssql.js` | ❌ | ✅ (TDS prelogin + login) |
| SNMP | 16100 | UDP | `snmp.js` | ❌ | ✅ (BER-encoded responses) |
| HTTP Proxy | 8180 | TCP | `httpproxy.js` | ❌ | ✅ (fake Squid CONNECT) |

## Passive Detectors

| Detector | Source | Handler |
|----------|--------|---------|
| Samba/SMB | Samba logs (`/var/log/samba/log.*`) | `samba.js` |
| Port Scans | Syslog (`/var/log/syslog`) | `portscan.js` |

---

## HTTP (`http.js`)

The main web honeypot. Uses Express to catch ALL requests.

**Request processing order:**
1. `/health` → instant OK (monitoring)
2. Anti-timing jitter → 150-800ms delay (anti-fingerprint)
3. `/api/fingerprint` → captures browser fingerprint data
4. `/robots.txt` → serves crawl trap
5. Rate limiter → 30 req/min per IP
6. Redirect loop trap → `/admin`, `/wp-admin`, `/backup`, etc. → 10x 302 → GZIP bomb
7. Sensitive files → `.env`, `wp-config.php`, `.git/config` → hardcoded decoys
8. Web maze → `/archive/*` → infinite directory listing with GZIP bomb files
9. LFI trap → `etc/passwd`, `etc/shadow` → honeyfs/ files
10. GZIP bomb → `.zip`, `.gz`, `.tar.gz` → 5GB compressed zeros
11. AI response → everything else goes to the LLM

**Fingerprinting:** HTML pages served to browsers include an obfuscated JavaScript payload that captures:
- Screen resolution
- Timezone
- CPU cores
- GPU renderer (WebGL)
- Local IPs (via WebRTC leak)

Data is sent to `/api/fingerprint` and logged.

---

## SSH (`ssh.js`)

Interactive fake bash shell with canary filesystem.

**Features:**
- Accepts ALL username/password combinations
- Interactive PTY with fake bash prompt (`root@hostname:~#`)
- File system from `honeyfs/` — contains fake AWS credentials, SSH keys, crypto wallets, Docker configs
- AI-generated responses for unknown commands
- Dynamic persona switching: Linux (default), Cisco IOS, Windows PowerShell, Kubernetes
- Tarpit commands: `ping` (infinite), `find`/`grep` (slow drip), `nmap` (fake progress)

**SSH Tarpit (Endlessh-style):**
- Separate listener on port 2200
- Sends infinite SSH banner lines (1 byte every 10s)
- Wastes scanner resources without ever completing handshake

---

## TCP Multi-Protocol (`tcp.js`)

Single handler that identifies the protocol from the first bytes received.

### FTP
- Banner: `220 (vsFTPd 3.0.5)`
- Accepts all credentials
- AI-generated directory listings
- PASV mode returns plausible public IP (203.0.113.45)

### Telnet
- Cisco IOS mode with static `show` command responses
- 17 static commands: `show running-config`, `show ip route`, `show interfaces`, etc.
- Falls through to AI for unknown commands

### SMTP
- Banner: `220 mail.example.com ESMTP Postfix`
- Accepts all EHLO/MAIL FROM/RCPT TO/DATA
- Logs complete email content

### MySQL
- Full MySQL 8.0 handshake with capability flags
- Rogue server: sends LOAD DATA LOCAL INFILE request to steal attacker files
- Target files: `/etc/passwd`, `.bash_history`, `.ssh/id_rsa`, `.my.cnf`

### Redis
- RESP protocol implementation
- Static responses for: PING, KEYS, GET, SET, DEL, INFO, AUTH, CONFIG, QUIT
- Returns fake data: session tokens, database passwords, API keys
- MONITOR command → floods fake Redis logs at 20/sec

### Git
- Git upload-pack advertisement
- Infinite refs tarpit: sends new branch refs every 2 seconds forever
- Hangs `git clone` indefinitely

### VNC
- RFB 3.8 protocol handshake
- Sends security type list and challenge

### RDP
- X.224 Connection Confirm
- MCS Connect Response with GCC Conference data

---

## MSSQL (`mssql.js`)

Fake SQL Server 2019 with TDS (Tabular Data Stream) protocol.

- TDS PRELOGIN response with version, encryption, instance info
- LOGIN7 response with LOGINACK + DONE tokens
- Fake server name: `SQLSERVER01`
- Version: 15.0.2000 (SQL Server 2019)

---

## SNMP (`snmp.js`)

UDP-based SNMP v1/v2c agent.

- BER-encoded request/response parsing
- Community string handling (`public`/`private`)
- Supported OIDs:
  - `1.3.6.1.2.1.1.1.0` → sysDescr (Debian GNU/Linux 12)
  - `1.3.6.1.2.1.1.3.0` → sysUpTime
  - `1.3.6.1.2.1.1.4.0` → sysContact
  - `1.3.6.1.2.1.1.5.0` → sysName
  - `1.3.6.1.2.1.1.6.0` → sysLocation
  - `1.3.6.1.2.1.2.1.0` → ifNumber

---

## HTTP Proxy (`httpproxy.js`)

Fake Squid 5.7 open proxy.

- Captures CONNECT tunnel requests (destination host + port)
- Returns `200 Connection Established` with Squid-style headers
- Logs proxy destination for intelligence
- Non-CONNECT requests get a Squid error page
