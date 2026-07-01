# MITRE ATT&CK Detection Coverage — HoneyAI

> Last Updated: 2026-07-01
> Platform: Linux (Raspberry Pi 5 / Debian)
> Total Techniques Monitored: 18

## Coverage by Tactic

| Tactic | Techniques Covered | Gaps | Coverage |
|--------|--------------------|------|----------|
| Initial Access | T1190, T1133 | T1195 (Supply Chain) | 66% |
| Execution | T1059.004 (Unix Shell) | T1059.006 (Python), T1059.001 (PowerShell) | 33% |
| Persistence | T1053.003 (Cron), T1098.004 (SSH Keys) | T1543 (Systemd Service) | 66% |
| Credential Access | T1110 (Brute Force) | T1558 (Kerberos), T1552 (Unsecured Creds) | 33% |
| Discovery | T1082, T1016, T1083 | T1087 (Account Discovery) | 75% |
| Lateral Movement | — | T1021 (Remote Services) | 0% |
| Command & Control | T1071, T1573 | T1572 (Tunneling) | 66% |
| Exfiltration | T1041 (Over C2) | T1048 (Alt Protocol), T1567 (Web Service) | 33% |

## Detailed Technique Mapping

### Protocols → ATT&CK Techniques

| Protocol | Port | ATT&CK Technique(s) | Detection Method |
|----------|------|----------------------|-----------------|
| SSH | 22 | T1110.001 (Password Guessing), T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer) | Auth logging + shell command capture |
| HTTP | 80/443 | T1190 (Exploit Public App), T1046 (Network Scan) | Request logging + path analysis |
| FTP | 21 | T1078 (Valid Accounts), T1110 (Brute Force) | Auth logging |
| Telnet | 23 | T1021.007 (Remote Service), T1059.004 (Unix Shell) | Auth + command capture |
| SMTP | 25 | T1071.003 (Mail Protocol), T1566.001 (Spearphishing) | HELO/MAIL FROM capture |
| MSSQL | 1433 | T1190 (Exploit DB), T1110 (Brute Force) | TDS Login7 packet parsing |
| MySQL | 3306 | T1190 (Exploit DB), T1110 (Brute Force) | Auth capture |
| Redis | 6379 | T1190 (Exposed Service) | Command capture |
| SMB/Samba | 445 | T1021.002 (SMB/Windows Admin Shares) | Share access + file ops |
| SNMP | 161 | T1046 (Network Scan), T1082 (System Info Discovery) | Community string + OID capture |
| VNC | 5900 | T1021.005 (VNC) | Connection logging |
| RDP | 3389 | T1021.001 (RDP) | Connection logging |
| MCP | 3001 | T1190 (Exploit API) | Tool call + SSE capture |
| HTTP Proxy | 8080 | T1090 (Proxy) | Hijack attempt logging |
| Portscan | — | T1046 (Network Scan) | iptables log parsing |
| Git | 9418 | T1213 (Data from Repos) | Push/pull logging |

### SSH Command → ATT&CK Auto-Mapping (engine.js)

| Command Pattern | ATT&CK Technique |
|----------------|-------------------|
| `wget/curl http://... \| sh` | T1059.004 + T1105 |
| `cat /etc/passwd` | T1003.008 |
| `chmod +x && ./` | T1059.004 |
| `crontab` | T1053.003 |
| `ssh-keygen` / `authorized_keys` | T1098.004 |
| `/dev/tcp/` / `nc -e` | T1071.001 |
| `uname -a`, `id`, `whoami` | T1082 |
| `curl ifconfig.me` | T1016 |
| `/tmp/` binary execution | T1036.005 |

## Known Gaps (Prioritized)

| Priority | Technique | Description | Mitigation Plan |
|----------|-----------|-------------|----------------|
| 🔴 HIGH | T1021 Lateral Movement | No session relay between honeypot nodes | Future: SSH relay capture |
| 🟡 MEDIUM | T1572 Tunneling | DNS/ICMP tunnels not captured | Future: DNS honeypot |
| 🟡 MEDIUM | T1048 Alt Protocol Exfil | No UDP/ICMP exfil detection | Monitor with Suricata |
| 🟡 MEDIUM | T1059.006 Python Exec | Python commands in shell not classified | Add pattern to engine.js |
| ⚪ LOW | T1195 Supply Chain | Out of scope for honeypot | N/A |
| ⚪ LOW | T1558 Kerberos | No Kerberos emulation | N/A |

## Alert Integration

Alerts are enriched with ATT&CK technique IDs in:
- **Telegram alerts**: `🎯 T1110 Brute Force` line in every alert
- **AbuseIPDB reports**: Category mapping (22=SSH, 21=Web App, etc.)
- **OTX pulses**: Protocol-routed to SSH/Web/DB/Network pulses
- **events.json**: `attack_type` field per event

## Severity Classification

| Level | Emoji | Label | Criteria |
|-------|-------|-------|----------|
| SEV1 | 🔴 | CRITICAL | Malware download, C2 callback, command execution |
| SEV2 | 🟠 | HIGH | Successful auth, exploit attempt, active shell |
| SEV3 | 🟡 | MEDIUM | Brute force, credential stuffing, recon on auth protocols |
| SEV4 | ⚪ | LOW | Passive scan, bot probe, single request |
