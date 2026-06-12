# Active Defense Traps

HoneyAI goes beyond passive logging — it actively wastes attacker resources, exfiltrates intelligence, and makes the attacker's tools work against them.

## 1. GZIP Bomb (`streamGzipBomb`)

**What it does:** Streams 5GB of compressed zeros (~4.8MB on the wire) to the attacker's client.

**How it works:**
- Generates a stream of zero bytes in 64KB chunks
- Compresses with gzip level 9 (maximum compression)
- Sets `Content-Disposition` as a file download (e.g., `backup.sql.gz`)
- When the attacker decompresses it, their disk/memory fills with 5GB of nothing

**Triggered by:**
- Downloading `.zip`, `.gz`, `.tar.gz` files from the web maze
- Following 10 redirect loops to completion
- Requesting paths that look like backup archives

---

## 2. Infinite Web Maze (`generateWebMaze`)

**What it does:** Generates an infinite, stateless directory tree that looks like a misconfigured Apache server exposing internal files.

**How it works:**
- Seeded PRNG from the URL path (consistent on refresh, different per directory)
- Generates 10-18 subdirectories per level with realistic names (`backup-prod_a3f2c1/`, `secrets-vault_8b4e21/`)
- Includes bait files: `.env`, `config.json`, `passwords.txt`, `id_rsa`, `backup.zip` (GZIP bomb)
- Serves real decoy documents: `network_architecture.pdf`, `company_passwords.docx`
- Styled as dark-themed Apache directory listing
- **Recursive**: every subdirectory generates more subdirectories → infinite depth

**Browser fingerprinting:** All maze pages include an obfuscated JavaScript fingerprint collector (see section 9).

---

## 3. Slow-Drip Tarpit (`dripSlowResponse`)

**What it does:** Sends data back to the attacker 1 byte every 5 seconds.

**How it works:**
- Takes any data buffer and writes 1 byte at a time
- Interval: 5000ms per byte (configurable)
- Holds the attacker's connection thread open for minutes
- Cleans up on socket error/close

**Used by:**
- SSH tarpit (Endlessh-style infinite banner)
- Any TCP protocol that wants to slow-play the response

---

## 4. Redis MONITOR Flood (`floodRedisMonitor`)

**What it does:** When an attacker runs `MONITOR` on the fake Redis, floods their terminal with fake log entries at 20 lines/second.

**Fake data includes:**
- `SET session:admin_token "sk_live_51abc123def456ghi789"` (bait Stripe key)
- `GET config:dbpass` (bait DB password)
- `AUTH "secret_pass123"` (bait auth command)
- Fake PING/KEYS/INFO commands

**Purpose:** Wastes attacker's connection buffer and tricks them into thinking there's real activity on the server.

---

## 5. HTTP Redirect Loop (`generateHttpRedirectLoop`)

**What it does:** Chains 10 redirects (302) with 500ms delays each, then delivers a GZIP bomb.

**Flow:**
```
/admin → 302 /archive/loop/1
         → 302 /archive/loop/2
         → 302 /archive/loop/3
         → ... (10 hops, 500ms each = 5 seconds)
         → 302 /archive/loop/critical-db-backup.sql.gz
         → 💣 5GB GZIP bomb
```

**Triggered by:** Requests to common admin paths: `/admin`, `/wp-admin`, `/backup`, `/phpmyadmin`, `/manager`, `/cpanel`, etc.

---

## 6. SSH Command Tarpit (`tarpitSSHCommand`)

**What it does:** When an attacker runs certain commands in the SSH shell, responds with realistic but slow-dripped output.

| Command | Behavior |
|---------|----------|
| `ping` | Infinite ICMP replies (1/sec), never stops |
| `find` / `grep` | Drips 15 fake file paths at 500ms each |
| `nmap` / `masscan` | Fake scan progress 0-100% at 3s intervals |
| Other commands | Generic "Scanning database resources..." dots |

---

## 7. MySQL Rogue INFILE (`makeMySQLInfileRequest`)

**What it does:** Exploits MySQL's `LOAD DATA LOCAL INFILE` protocol to exfiltrate files from the attacker's machine.

**How it works:**
- MySQL protocol allows the server to request the client to send a local file
- After completing the fake login handshake, sends an INFILE request
- Target files: `/etc/passwd`, `.bash_history`, `.ssh/id_rsa`, `.my.cnf`
- If the attacker's MySQL client has `local-infile` enabled, we get their files

**Format:** `[3-byte length][1-byte seq][0xfb][filename]`

---

## 8. Git Infinite Clone (`streamInfiniteGitRefs`)

**What it does:** Sends infinite Git refs to a client doing `git clone`, hanging the process forever.

**How it works:**
- Sends Git smart service advertisement header
- Every 2 seconds, generates a new fake branch ref with SHA-1 hash
- Client waits for ref list to finish — it never does
- `git clone` hangs indefinitely consuming the attacker's thread

---

## 9. Browser Fingerprinting (`injectFingerprint`)

**What it does:** Injects an obfuscated JavaScript payload into HTML pages that extracts:

| Data Point | Method |
|------------|--------|
| Screen resolution | `window.screen.width` × `height` |
| Timezone | `Intl.DateTimeFormat().resolvedOptions().timeZone` |
| CPU cores | `navigator.hardwareConcurrency` |
| GPU model | `WEBGL_debug_renderer_info` extension |
| Local/VPN IPs | WebRTC `RTCPeerConnection` ICE candidates |

**Delivery:**
- Base64-encoded, injected before `</body>` via `eval(atob(...))`
- Only injected for browser User-Agents (skips curl, wget, bots)
- Data POSTed to `/api/fingerprint` and logged as JSON-L event

---

## 10. Reverse Port Scan (Backfire) (`scanAttackerBack`)

**What it does:** When an attacker connects, HoneyAI scans THEM back.

**Scanned ports:** 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS), 8080, 8443

**Safety controls:**
- 24h cooldown per IP
- Max 5 concurrent scans
- Skips private/internal IPs
- Bounded cache (1,000 IPs max, evicts oldest)

**On discovery:**
- Logs open ports to `events.jsonl`
- Performs reverse DNS (PTR) lookup
- Sends Telegram alert: `💥 Attacker 1.2.3.4 (hostname) — Open ports: 22, 80`

---

## 11. Anti-Timing Fingerprint (Jitter)

**Problem:** Static/template responses return in ~5ms, AI responses in ~8-20s. An attacker can measure response times to detect which responses are real (AI) vs templates.

**Solution:** All HTTP responses go through `addJitter()` middleware that adds 150-800ms random delay.

```
Before jitter:
  /robots.txt  →  2ms   (template — DETECTABLE)
  /random-path → 12000ms (AI)

After jitter:
  /robots.txt  → 350ms   (looks like slow PHP)
  /random-path → 12000ms  (AI — same as before)
```

This makes template responses look like a slow Apache+PHP server instead of instant static files.
