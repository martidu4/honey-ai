// Vercel Serverless Function — Web Honeypot Trap (Full Reporting)
// Reports to ALL 4 platforms: AbuseIPDB, Blocklist.de, DShield/SANS, AlienVault OTX
// Plus: Telegram instant alert + Galah Pi5 event logging
// Deployed at: /api/trap (Vercel native, works with static Astro site)

import { reportToAllPlatforms, alertTelegram } from './_lib/report-all.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.headers['x-real-ip'] ||
      req.socket?.remoteAddress ||
      'unknown';

    const ua      = req.headers['user-agent'] || 'unknown';
    const referer = req.headers['referer'] || '';
    const path    = req.body?.path || 'unknown';
    const extra   = req.body?.extra || '';

    // Skip private/LAN IPs
    const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);

    if (!isPrivate) {
      // Determine categories based on path
      const categories =
        path.includes('login') ? '18,21' :   // Brute-Force + Web App Attack
        path.includes('env') || path.includes('config') ? '21' : // Web App Attack
        path.includes('dashboard') ? '15,21' : // Unauthorized Access + Web App Attack
        '19,21'; // Port Scan + Web App Attack

      const detail =
        `Web honeypot trap triggered at ${path}. ` +
        `Automated scan/probe detected on threat intelligence blog` +
        (extra ? `. Detail: ${extra.substring(0, 80)}` : '');

      // Report to ALL 4 platforms with correct attacker IP
      await reportToAllPlatforms(ip, path, ua, { categories, detail });

      // Telegram instant alert
      await alertTelegram(ip, path, ua, {
        extra: extra ? `📝 <code>${extra.substring(0, 120)}</code>` : '',
      });

      // Also fire event to Galah Pi5 for blog stats (event count/paths)
      const GALAH_URL = process.env.GALAH_URL || 'http://localhost:8080';
      const trapPath = `/trap-beacon/${encodeURIComponent(path)}`;
      fetch(`${GALAH_URL}${trapPath}`, {
        method: 'GET',
        headers: { 'User-Agent': ua, 'X-Forwarded-For': ip, 'X-Real-IP': ip },
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false });
  }
}
