# Sample Data

Raw honeypot event data for dashboard and stats page development. All IP addresses are anonymized.

## Files

| File | Format | Description |
|------|--------|-------------|
| `events.jsonl` | JSONL | 200 attack events across all protocols (SSH, HTTP, Telnet, FTP, MySQL, Redis, etc.) |
| `daily-stats.json` | JSON | 30 days of aggregated daily statistics |
| `top-attackers.json` | JSON | Top 50 attacker IPs with hit counts and protocols |
| `geo-distribution.json` | JSON | Attack geographic distribution by country |

## Usage

These files can be imported directly by the stats dashboard (`src/pages/stats.astro`) and Chart.js visualizations. They mirror the exact schema that HoneyAI's `logEvent()` produces in production.

```javascript
// Load events
const events = fs.readFileSync('sample-data/events.jsonl', 'utf8')
  .trim().split('\n').map(JSON.parse);

// Load daily stats
const stats = JSON.parse(fs.readFileSync('sample-data/daily-stats.json'));
```

## Data Generation

This data was generated from real honeypot captures with all attacker IPs anonymized (replaced with documentation-range IPs per RFC 5737: `192.0.2.x`, `198.51.100.x`, `203.0.113.x`).
