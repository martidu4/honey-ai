// Shared reporting helper — sends attacker IP to ALL 4 platforms
// Used by trap.js, galah-proxy.js, and /api/v1/* endpoints
//
// Platforms: AbuseIPDB, Blocklist.de, DShield/SANS, AlienVault OTX

/**
 * Report an IP to all threat intelligence platforms
 * @param {string} ip - Attacker IP address
 * @param {string} path - Path that was accessed
 * @param {string} ua - User-Agent
 * @param {object} opts - Optional: { categories, detail }
 */
export async function reportToAllPlatforms(ip, path, ua, opts = {}) {
  if (!ip || ip === 'unknown') return;

  // Skip private/LAN IPs
  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);
  if (isPrivate) return;

  const categories = opts.categories || '19,21';
  const detail = opts.detail || `Web honeypot trap at ${path}`;
  const comment = `${detail}. UA: ${ua.substring(0, 100)}`;

  const promises = [];

  // ── 1. AbuseIPDB ──
  const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
  if (ABUSEIPDB_KEY) {
    promises.push(
      fetch('https://api.abuseipdb.com/api/v2/report', {
        method: 'POST',
        headers: {
          'Key': ABUSEIPDB_KEY,
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ ip, categories, comment }).toString(),
      }).catch(() => {})
    );
  }

  // ── 2. Blocklist.de ──
  const BLOCKLIST_EMAIL = process.env.BLOCKLIST_DE_EMAIL;
  if (BLOCKLIST_EMAIL) {
    const blComment = `Web honeypot trap: ${path} from ${ip}`;
    promises.push(
      fetch('https://www.blocklist.de/en/httpreports.html', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          server: BLOCKLIST_EMAIL,
          ip_address: ip,
          attack_type: 'web',
          logs: blComment,
        }).toString(),
      }).catch(() => {})
    );
  }

  // ── 3. DShield/SANS ──
  const DSHIELD_USER = process.env.DSHIELD_USER_ID;
  const DSHIELD_KEY  = process.env.DSHIELD_API_KEY;
  if (DSHIELD_USER && DSHIELD_KEY) {
    const ts = new Date().toISOString().replace('T', ' ').replace('Z', '');
    const logLine = `${ts}\t${DSHIELD_USER}\t1\t${ip}\t80\t0.0.0.0\t443\tTCP\t${path.substring(0, 60)}`;
    const authStr = Buffer.from(`${DSHIELD_USER}:${DSHIELD_KEY}`).toString('base64');
    promises.push(
      fetch('https://www.dshield.org/submitapi/', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'Authorization': `Basic ${authStr}`,
        },
        body: logLine,
      }).catch(() => {})
    );
  }

  // ── 4. AlienVault OTX ──
  const OTX_KEY   = process.env.OTX_API_KEY;
  const OTX_PULSE = process.env.OTX_PULSE_ID;
  if (OTX_KEY && OTX_PULSE) {
    const indicator = {
      indicator: ip,
      type: 'IPv4',
      title: `Web trap: ${path.substring(0, 40)}`,
      description: comment.substring(0, 200),
    };
    promises.push(
      fetch(`https://otx.alienvault.com/api/v1/pulses/${OTX_PULSE}`, {
        method: 'PATCH',
        headers: {
          'X-OTX-API-KEY': OTX_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ indicators: { add: [indicator] } }),
      }).catch(() => {})
    );
  }

  // Fire all in parallel, don't wait for completion
  await Promise.allSettled(promises);
}

/**
 * Send Telegram alert
 */
export async function alertTelegram(ip, path, ua, opts = {}) {
  const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
  const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID;
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT) return;

  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);
  if (isPrivate) return;

  const emoji = opts.emoji ||
    (path.includes('env') || path.includes('config') ? '🔑' :
     path.includes('admin') || path.includes('wp')   ? '🚨' :
     path.includes('backup') || path.includes('sql') ? '💾' :
     path.includes('login_attempt')                  ? '🔐' :
     path.includes('dashboard')                      ? '🎭' :
     path.includes('api/v1')                         ? '🎣' : '🕵️');

  const extra = opts.extra || '';
  const msg =
    `${emoji} <b>Web Honeypot Hit</b>\n` +
    `📍 Path: <code>${path}</code>\n` +
    `🌍 IP: <code>${ip}</code>\n` +
    `🖥️ UA: <code>${ua.substring(0, 80)}</code>` +
    (extra ? `\n${extra}` : '');

  await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT, text: msg, parse_mode: 'HTML' }),
  }).catch(() => {});
}
