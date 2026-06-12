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

The `X-HoneyAI-Secret` header tells HoneyAI to trust the `X-Forwarded-For` header from Caddy for accurate IP logging.

---

## VPS Deployment (Ubuntu/Debian)

Same steps as Pi5 but:
1. Choose a VPS with 2GB+ RAM
2. Open all honeypot ports in the VPS firewall
3. Use the public IP directly (no router port forwarding needed)
4. Consider running Ollama on a separate, more powerful machine and pointing `OLLAMA_URL` to it

---

## Docker Deployment

```bash
docker compose up -d
```

The `docker-compose.yml` includes:
- HoneyAI container with all protocols exposed
- Ollama container for LLM inference
- Volume mounts for logs and config

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
