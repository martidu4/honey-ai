# Sample Events Dataset

Real anonymized attack data captured by HoneyAI over ~34 days.

Use this data to develop dashboards, analytics, or integrations without needing a live honeypot.

## Stats

| Metric | Value |
|--------|-------|
| Events | ~1,500 |
| Unique Attacker IPs | ~470 |
| Date Range | 2026-05-15 → 2026-06-17 |
| Protocols | 15 |

## Protocol Distribution

| Protocol | Events |
|----------|--------|
| VNC | 200 |
| MSSQL | 200 |
| Telnet | 198 |
| SSH | 196 |
| FTP | 181 |
| MySQL | 154 |
| HTTP | 108 |
| Redis | 101 |
| SMTP | 48 |
| Backfire | 42 |
| SNMP | 40 |
| Tarpit | 6 |
| MCP | 6 |
| Git | 1 |
| Shodan Self-Scan | 1 |

## Format

JSONL (one JSON object per line). Each event has:

```json
{
  "timestamp": "2026-06-17T12:00:00.000Z",
  "protocol": "ssh",
  "ip": "1.2.3.4",
  "port": 2222,
  "username": "root",
  "password_hash": "a1b2c3d4",
  "attack_type": "brute_force",
  "command": "cat /etc/passwd"
}
```

Fields vary by protocol. Common fields: `timestamp`, `protocol`, `ip`.

## Privacy

- All IPs are real attacker IPs (public internet scanners/bots)
- Internal/private IPs have been stripped
- Password hashes are truncated (first 16 chars of SHA-256)
- No operator or victim data is included

## Usage

```bash
# Count events by protocol
cat events-sample.jsonl | jq -r '.protocol' | sort | uniq -c | sort -rn

# Top 10 attacker IPs
cat events-sample.jsonl | jq -r '.ip' | sort | uniq -c | sort -rn | head -10

# SSH brute-force usernames
cat events-sample.jsonl | jq -r 'select(.protocol=="ssh") | .username' | sort | uniq -c | sort -rn
```
