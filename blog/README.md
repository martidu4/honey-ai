# 📰 HoneyAI Threat Intelligence Blog

**A dual-purpose website: public threat blog + web honeypot in one.**

Live at: [honey-ai.dev](https://honey-ai.dev)

---

## What Is This?

This is **not just a blog**. It serves two purposes simultaneously:

### 1. 📊 Threat Intelligence Blog
- Daily auto-generated attack reports
- AI-analyzed threat summaries (via Ollama)
- Historical data, charts, RSS feed
- Anyone can browse the real reports at `/blog` and `/reports`

### 2. 🪤 Web Honeypot (Catch-All Trap)
The blog itself acts as a **web honeypot**:

- **Canary Trap Pages**: `/wp-admin`, `/phpmyadmin`, `/cpanel`, `/login`, `/admin/dashboard` — realistic fake admin panels that log every visitor
- **Canary Files**: `/.env`, `/backup.sql`, `/config.json` — fake credentials that attackers steal and try to use → you get alerted
- **Catch-All Proxy**: ANY request that doesn't match a real page gets forwarded to a Galah-style AI proxy that generates convincing fake responses
- **API Honeypot Endpoints**: `/api/v1/users`, `/api/v1/config`, `/api/v1/export` — fake REST APIs that serve bait data (user lists, database configs, CSV exports)
- **Canary Webhooks**: `/api/canary-webhook` receives alerts when canary tokens are triggered

Every interaction is logged and reported to Telegram.

---

## Architecture

```
Internet
    │
    ├── Real visitors → /blog, /reports, /stats, /rss.xml
    │                    (Astro SSG static pages)
    │
    ├── Attackers scanning → /wp-admin, /phpmyadmin, /cpanel, /.env, /backup.sql
    │                         (Canary trap pages + files → logged + Telegram alert)
    │
    ├── Bots/scanners → /any/unknown/path
    │                    (Catch-all → galah-proxy.js → AI-generated response)
    │
    └── API probes → /api/v1/users, /api/v1/config, /api/v1/export
                      (Fake REST API → bait data with canary credentials)
```

### How the Catch-All Works

In `vercel.json`, a rewrite rule sends ALL unmatched requests to `galah-proxy.js`:

```json
{
  "rewrites": [
    { "source": "/api/:path*", "destination": "/api/:path*" },
    { "source": "/(.*)", "destination": "/api/galah-proxy" }
  ]
}
```

The proxy generates convincing fake responses for whatever path the attacker requests (WordPress, Laravel, phpMyAdmin, Jenkins, etc.), using the AI engine or static templates.

---

## Deployment Options

### Option A: Vercel (Recommended)

Deploy the blog to Vercel for free. The serverless functions handle the honeypot catch-all.

```bash
cd blog
pnpm install
vercel deploy --prod
```

Set these environment variables in Vercel Dashboard → Settings → Environment Variables:

```env
# Optional — for Telegram notifications when traps trigger
TELEGRAM_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Optional — Galah AI proxy backend (if using external AI for catch-all)
GALAH_URL=http://your-ollama-server:11434

# Optional — reporting
ABUSEIPDB_KEY=your_key
OTX_API_KEY=your_key
DSHIELD_API_KEY=your_key
```

Point your domain's DNS to Vercel.

### Option B: Self-Hosted with Caddy

If you run HoneyAI on a VPS or Raspberry Pi and want the blog on the same machine:

#### 1. Build the static site

```bash
cd blog
pnpm install
pnpm build    # Generates dist/
```

#### 2. Configure Caddy

Add to your Caddyfile:

```caddyfile
threats.yourdomain.com {
    # Serve static blog
    root * /opt/honeyai/blog/dist
    file_server

    # Catch-all: forward unknown paths to HoneyAI's HTTP honeypot
    @notfound {
        not file
        not path /blog/* /reports/* /stats /rss.xml /favicon.* /og-*
    }
    reverse_proxy @notfound localhost:8080

    # Serve canary files directly
    handle /.env {
        root * /opt/honeyai/blog/public
        file_server
    }
    handle /backup.sql {
        root * /opt/honeyai/blog/public
        file_server
    }
    handle /config.json {
        root * /opt/honeyai/blog/public
        file_server
    }

    # Security headers
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
}
```

#### 3. Open ports

```bash
# If Caddy handles TLS (port 443):
sudo ufw allow 443/tcp

# Or with iptables:
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

#### 4. DNS

Point `threats.yourdomain.com` (or your chosen subdomain) to your server's public IP. Caddy auto-provisions Let's Encrypt TLS.

### Option C: Nginx

```nginx
server {
    listen 443 ssl;
    server_name threats.yourdomain.com;

    root /opt/honeyai/blog/dist;
    index index.html;

    # Real blog pages
    location /blog { try_files $uri $uri/ =404; }
    location /reports { try_files $uri $uri/ =404; }

    # Canary files (served directly)
    location = /.env { root /opt/honeyai/blog/public; }
    location = /backup.sql { root /opt/honeyai/blog/public; }
    location = /config.json { root /opt/honeyai/blog/public; }

    # Catch-all → HoneyAI HTTP honeypot
    location / {
        try_files $uri $uri/ @honeypot;
    }
    location @honeypot {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Auto-Publishing Pipeline

Four scripts automate the daily report lifecycle:

```
┌─────────────────────────────────────────────────────────┐
│  Cron Schedule (on honeypot server):                    │
│                                                         │
│  55 23 * * *  honeypot-publish.sh     # Collect stats   │
│  10  0 * * *  honeypot-blog-ai.sh     # AI analysis     │
│  15  0 * * *  honeypot-report.sh      # Telegram summary│
│   0  * * * *  honeypot-graduate.sh    # IP graduation   │
└─────────────────────────────────────────────────────────┘
```

### scripts/honeypot-publish.sh
Collects the day's attack data from HoneyAI logs (events.json), Suricata alerts, and community report stats. Generates a Markdown report in `src/content/reports/YYYY-MM-DD.md` with frontmatter stats.

### scripts/honeypot-blog-ai.sh
Takes the stats report and sends it to a local LLM (Ollama) to generate an AI-written blog post in `src/content/blog/YYYY-MM-DD.md`. Then runs `astro build` and deploys to Vercel (or pushes to git).

### scripts/honeypot-report.sh
Sends a daily summary to Telegram with key metrics: total attacks, unique IPs, top protocols, top passwords, and notable events.

### scripts/honeypot-graduate.sh
Monitors repeat offenders. When an IP exceeds a threshold of attacks, it gets "graduated" to a permanent blocklist (via CrowdSec or iptables).

### Setting Up the Pipeline

1. Copy scripts to your server:
   ```bash
   cp blog/scripts/*.sh /opt/honeyai/scripts/
   chmod +x /opt/honeyai/scripts/*.sh
   ```

2. Create a `.env` file with your API keys:
   ```bash
   cat > /opt/honeyai/scripts/.env << 'EOF'
   TELEGRAM_TOKEN=your_bot_token
   TELEGRAM_CHAT=your_chat_id
   ABUSEIPDB_KEY=your_key
   VERCEL_TOKEN=your_vercel_token  # For auto-deploy
   EOF
   ```

3. Add to crontab:
   ```bash
   crontab -e
   # Add:
   55 23 * * * /opt/honeyai/scripts/honeypot-publish.sh
   10  0 * * * /opt/honeyai/scripts/honeypot-blog-ai.sh
   15  0 * * * /opt/honeyai/scripts/honeypot-report.sh
    0  * * * * /opt/honeyai/scripts/honeypot-graduate.sh
   ```

4. Verify the pipeline:
   ```bash
   # Test stats collection
   /opt/honeyai/scripts/honeypot-publish.sh

   # Check generated report
   ls -la /opt/honeyai/blog/src/content/reports/
   ```

---

## Canary Trap Files

The `public/` directory contains intentional honeypot files:

| File | What Attackers See | Purpose |
|------|-------------------|---------|
| `.env` | Fake DB passwords, AWS keys, Stripe keys | Credential bait |
| `backup.sql` | Fake MySQL dump with user table | Database bait |
| `config.json` | Fake app config with API keys | Configuration bait |

**⚠️ These are NOT real credentials.** They contain fake data designed to lure attackers. When stolen credentials are used, you can detect the breach via canary token services like [canarytokens.org](https://canarytokens.org/).

---

## Canary Trap Pages

| Page | Mimics | Trigger |
|------|--------|---------|
| `/wp-admin` | WordPress admin login | Logs IP + sends Telegram alert |
| `/phpmyadmin` | phpMyAdmin login | Same |
| `/cpanel` | cPanel login | Same |
| `/login` | Generic login form | Same |
| `/admin` | Admin panel entry | Same |
| `/admin/dashboard` | Full fake admin dashboard with users, stats | Logs clicks on fake user rows |

---

## API Honeypot Endpoints

| Endpoint | Returns | Purpose |
|----------|---------|---------|
| `GET /api/v1/users` | Fake user list with emails + API keys | Credential harvesting trap |
| `GET /api/v1/config` | Fake server config with DB passwords | Config leak trap |
| `GET /api/v1/export` | Fake CSV export of "customer" data | Data exfiltration trap |
| `GET /api/v1/ioc` | IoC (Indicators of Compromise) feed | Real data for defenders |
| `POST /api/canary-webhook` | Webhook receiver for canary alerts | Canarytoken integration |
| `POST /api/trap` | Catch-all trap endpoint | Logs everything |

---

## Local Development

```bash
cd blog
pnpm install
pnpm dev          # http://localhost:4321
```

Note: The catch-all proxy (`galah-proxy.js`) only works in production (Vercel serverless functions). In local dev, only the static pages are served.

---

## Tech Stack

- **[Astro](https://astro.build)** — Static site generator (zero JS by default)
- **Vanilla CSS** — No frameworks
- **[Chart.js](https://www.chartjs.org/)** — Stats visualizations
- **Vercel Serverless Functions** — API endpoints and catch-all proxy
- **Markdown** — Content in `src/content/blog/` and `src/content/reports/`
