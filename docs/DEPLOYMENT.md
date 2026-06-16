# Deployment Guide

## Quick Start (Docker)

```bash
git clone https://github.com/martidu4/honey-ai.git
cd honey-ai
cp .env.example .env       # Edit with your API keys
docker compose up -d
```

## Quick Start (Bare Metal)

```bash
git clone https://github.com/martidu4/honey-ai.git
cd honey-ai
pnpm install
cp .env.example .env       # Edit with your API keys
node server.js
```

> **Note:** Only `pnpm` is used in this project. Do not use `npm`.

---

## Raspberry Pi 5 Deployment

### Prerequisites

- Raspberry Pi 5 (4GB+ RAM recommended)
- Raspberry Pi OS (Debian 12 Bookworm)
- Node.js 18+ (via NodeSource)
- Ollama installed locally (for AI responses)

### Step 1: Install Dependencies

```bash
# Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash -
sudo apt-get install -y nodejs

# pnpm
corepack enable
corepack prepare pnpm@latest --activate

# Ollama (LLM inference)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:1.7b   # or any model you prefer
```

### Step 2: Clone and Configure

```bash
cd /home/pi
git clone https://github.com/martidu4/honey-ai.git
cd honey-ai
pnpm install
```

Create `.env`:
```bash
# Required
OLLAMA_URL=http://localhost:11434

# Reporting (optional but recommended)
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
DSHIELD_API_KEY=your_key_here
BLOCKLIST_DE_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Telegram alerts (optional)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

### Step 3: Port Forwarding (iptables)

HoneyAI listens on high ports (non-privileged). To receive traffic on standard ports, use iptables to redirect:

```bash
# SSH (real SSH on 2297, honeypot SSH on 2226)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 2226

# FTP
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 21 -j REDIRECT --to-port 2121

# HTTP
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8081

# HTTPS (if using Caddy reverse proxy, skip this)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8081

# Telnet
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 23 -j REDIRECT --to-port 2323

# SMTP
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j REDIRECT --to-port 2525

# MySQL
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 3306 -j REDIRECT --to-port 33060

# Redis
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 6379 -j REDIRECT --to-port 63790

# Git
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 9418 -j REDIRECT --to-port 9418

# VNC
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 5900 -j REDIRECT --to-port 5900

# MSSQL
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 1433 -j REDIRECT --to-port 14330

# SNMP
sudo iptables -t nat -A PREROUTING -i eth0 -p udp --dport 161 -j REDIRECT --to-port 16100

# HTTP Proxy
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8080 -j REDIRECT --to-port 8180

# Persist rules across reboots
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

### Step 4: Run as Service (systemd)

Create `/etc/systemd/system/honeyai.service`:

```ini
[Unit]
Description=HoneyAI Honeypot
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/honey-ai
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
StandardOutput=append:/home/pi/honey-ai/logs/honeyai.log
StandardError=append:/home/pi/honey-ai/logs/honeyai.log
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeyai
sudo systemctl start honeyai
sudo systemctl status honeyai
```

### Step 5: Caddy Reverse Proxy (Optional, for HTTPS)

If you want HTTPS with automatic TLS:

```
your-domain.com {
    header -Via
    header Server "Apache/2.4.51 (Ubuntu)"
    header X-Powered-By "PHP/8.1.2"
    
    reverse_proxy localhost:8081 {
        header_up X-HoneyAI-Secret "your_secret_here"
    }
}
```

To make this work, you must define the corresponding secret in your `.env` file:
```env
HONEYAI_PROXY_SECRET=your_secret_here
```
The `X-HoneyAI-Secret` header tells HoneyAI to trust the `X-Forwarded-For` header from the proxy for accurate IP logging. When they match, HoneyAI logs the client's real public IP instead of the proxy/docker gateway IP.

---

## VPS Deployment (Ubuntu/Debian)

Same steps as Pi5 but:
1. Choose a VPS with 2GB+ RAM
2. Open all honeypot ports in the VPS firewall
3. Use the public IP directly (no router port forwarding needed)
4. Consider running Ollama on a separate, more powerful machine and pointing `OLLAMA_URL` to it

## Docker Deployment & Hardening

Run HoneyAI with Docker Compose:
```bash
docker compose up -d
```

### Hardening Details
The default `docker-compose.yml` implements several security layers:
- **Read-only Root Filesystem**: The root directory is mounted read-only. Writable paths `/tmp` and `/run` are mounted as memory-backed `tmpfs`.
- **Dropped Capabilities**: All Linux capabilities are dropped (`cap_drop: [ALL]`), and the container cannot gain new privileges.
- **Resource Constraints**: Limits set to 256 PIDs, 512MB memory, and 1.0 CPU to prevent Denial of Service (DoS) attacks.
- **Isolated Networks**: 
  - `ai_backend`: An internal network with no internet access where `ollama` and `honeyai` communicate securely.
  - `public_honeypot`: A bridge network (`172.30.50.0/24`) giving HoneyAI the static IP `172.30.50.10`.

---

## Passive Detectors Setup (Host)

Passive detectors (Samba and Portscan) rely on host system logs. Because the HoneyAI Docker container runs in hardened mode (read-only, no capabilities), it cannot install Samba or configure host firewall rules directly. Instead, we run helper scripts on the host and mount the logs.

### 1. Passive Samba Auditing
Run the setup script on the host to configure a bait Samba share and enable VFS audit logging:
```bash
sudo ./scripts/setup-samba-detector.sh
```
This script:
- Installs Samba and configuration tools if missing.
- Sets up a bait share `[CorporateFiles]` pointing to `/srv/samba/share_docs` (contains fake credentials and readme).
- Configures VFS logging via `vfs_full_audit` to output log entries to `/var/log/samba/full_audit.log`.
- Configures log rotation and sets appropriate read permissions so the HoneyAI container can tail the log.

### 2. Portscan Logs & Egress Firewall
Run the setup script on the host to monitor port scans and restrict honeypot outbound access:
```bash
sudo ./scripts/setup-iptables-portscan.sh
```
This script:
- Sets up custom `iptables` rules in the host `INPUT` chain to log TCP SYN packets targeting bait ports (SSH, FTP, MySQL, Samba, etc.) with the `PORTSCAN:` prefix to `/var/log/syslog`.
- Sets up egress rules in the `DOCKER-USER` chain. This locks down outbound traffic from the honeypot container (`172.30.50.10`), allowing only replies (ESTABLISHED), DNS queries (port 53), and HTTPS (port 443) for reporting and notifications.
- Configures host rsyslog permissions to allow the HoneyAI container to read `/var/log/syslog`.

---

## Monitoring

### Health Check

```bash
curl http://localhost:8081/health
# Returns: OK
```

### Logs

```bash
# Real-time events
tail -f logs/events.jsonl | jq

# Application log
tail -f logs/honeyai.log
```

### Dashboard

Access the built-in dashboard at `http://localhost:8081/dashboard` (or via your domain if using Caddy).

---

## Security Hardening Checklist

- [ ] Move real SSH to a non-standard port (e.g., 2297)
- [ ] Configure fail2ban for real SSH, exclude honeypot ports
- [ ] Enable UFW and only allow necessary ports
- [ ] Disable password auth for real SSH
- [ ] Run HoneyAI as a non-root user
- [ ] Keep iptables rules persistent
- [ ] Set up log rotation for `logs/` directory
- [ ] Monitor disk space (GZIP bombs generate large files if attacker downloads)
