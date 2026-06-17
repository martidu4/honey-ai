// Vercel Serverless Function — Galah LLM Honeypot Proxy
// Cualquier path no estático en honey-ai.dev llega aquí
// y se reenvía a Galah en el Pi 5 → respuesta HTML fake generada por LLM
// Reports to ALL 4 platforms via shared helper

import { reportToAllPlatforms } from './_lib/report-all.js';
//
// Flujo: Scanner → honey-ai.dev/wp-login.php
//        → vercel.json catch-all → /api/galah-proxy
//        → Pi 5 localhost:8080 (Galah LLM)
//        → HTML fake → devuelve al scanner
//        → Loggea en event_log.json del Pi 5

const GALAH_URL = process.env.GALAH_URL || 'http://localhost:8080';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID;
const ABUSEIPDB_KEY  = process.env.ABUSEIPDB_KEY;

// Paths del blog legítimo — no proxear a Galah (son páginas reales)
const BLOG_PREFIXES = ['/reports', '/about', '/assets', '/favicon', '/_astro', '/api/', '/blog', '/rss.xml', '/stats', '/comedy', '/subscribe', '/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel', '/og-default', '/robots.txt', '/sitemap'];

// Crawlers internos de Vercel — NO alertar (falsos positivos)
const INTERNAL_UA = ['vercel-favicon', 'vercel-og', 'Vercel Edge', 'Vercel Monitoring'];

// Paths que activan el tarpit — scanner queda atrapado ~30s
const TARPIT_PATTERNS = ['.env', '.git', 'wp-login', 'wp-includes', 'wp-content', 'xmlrpc', 'wp-config', '.htaccess', '.htpasswd', 'server-status', 'phpinfo', 'shell', 'cmd', 'eval-stdin', 'vendor', 'telescope', 'debug', 'actuator', 'console', '.DS_Store', 'thumbs.db'];

// Helper: sleep ms
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Helper: report IP to AbuseIPDB
async function reportToAbuseIPDB(ip, path, ua) {
  if (!ABUSEIPDB_KEY) return;
  const comment = `HTTP tarpit triggered at ${path}. Scanner trapped for ~30s. UA: ${ua.substring(0, 100)}`;
  fetch('https://api.abuseipdb.com/api/v2/report', {
    method: 'POST',
    headers: { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ip, categories: '19,21', comment }).toString(),
  }).catch(() => {});
}

// Helper: send Telegram alert
function alertTelegram(emoji, rawPath, ip, ua, extra = '') {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT) return;
  const isPrivateIP = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);
  if (isPrivateIP) return;
  if (INTERNAL_UA.some(u => ua.includes(u))) return;
  const msg =
    `${emoji} <b>HoneyAI Web Decoy</b>\n` +
    `📍 <code>${rawPath}</code>\n` +
    `🌍 IP: <code>${ip}</code>\n` +
    `🖥️ UA: <code>${ua.substring(0, 80)}</code>` +
    (extra ? `\n${extra}` : '');
  fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT, text: msg, parse_mode: 'HTML' }),
  }).catch(() => {});
}

// Blocked abusive IPs (e.g. HostPapa Seattle scanner hammering .env every 30s)
const BLOCKED_IPS = ['192.3.53.186', '45.88.138.44'];

export default async function handler(req, res) {
  const rawPath = req.url || '/';

  // Si es una ruta del blog real, devolver 404 limpio (no honeypot)
  const isBlogPath = BLOG_PREFIXES.some(p => rawPath.startsWith(p));
  if (isBlogPath) {
    return res.status(404).json({ error: 'Not found' });
  }

  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    'unknown';

  // Return 403 instantly for blocked abusive IPs to save CPU/bandwidth
  if (BLOCKED_IPS.includes(ip)) {
    return res.status(403).send('Forbidden');
  }

  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);
  const ua = req.headers['user-agent'] || 'unknown';

  // Sanitize path: strip null bytes, double dots, and control chars
  const safePath = rawPath.replace(/\0/g, '').replace(/\.\.\//g, '').replace(/[\x00-\x1f]/g, '');

  // ── TARPIT: slow-drip response for known scanner paths ──
  const isTarpitPath = TARPIT_PATTERNS.some(p => safePath.toLowerCase().includes(p));
  if (isTarpitPath && !isPrivate) {
    // Report to ALL 4 platforms with correct attacker IP
    reportToAllPlatforms(ip, rawPath, ua, {
      categories: '19,21',
      detail: `HTTP tarpit triggered at ${rawPath}. Scanner trapped for ~30s`,
    });
    alertTelegram('🐌', rawPath, ip, ua, '⏱️ <b>TARPIT ACTIVADO</b> — scanner atrapado ~30s');

    // Fake Apache-looking response, dripped byte by byte
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Server', 'Apache/2.4.57 (Debian)');
    res.setHeader('X-Powered-By', 'PHP/8.1.2');
    res.writeHead(200);

    const fakeBody = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don\'t have permission to access this resource.</p><hr><address>Apache/2.4.57 (Debian) Server at honey-ai.dev Port 443</address></body></html>';
    // Drip response: ~800ms per character, max 8 chars = ~6.4s total (Vercel Hobby timeout is 10s)
    const chars = fakeBody.substring(0, 8);
    for (const char of chars) {
      res.write(char);
      await sleep(800);
    }
    res.end(fakeBody.substring(8));

    // Also ping Galah for blog event stats (path counts)
    fetch(`${GALAH_URL}${safePath}`, {
      method: 'GET',
      headers: { 'User-Agent': ua, 'X-Forwarded-For': ip, 'X-Real-IP': ip },
      signal: AbortSignal.timeout(5000),
    }).catch(() => {});
    return;
  }

  // ── Normal path: forward to Galah LLM ──
  const galahTarget = `${GALAH_URL}${safePath}`;

  try {
    // Reenviar la petición a Galah en el Pi 5
    const galahRes = await fetch(galahTarget, {
      method: req.method,
      headers: {
        'User-Agent': ua,
        'X-Forwarded-For': ip,          // Galah loggea esta IP real del scanner
        'X-Real-IP': ip,
        'Accept': req.headers['accept'] || 'text/html',
      },
      // Pasar body si es POST
      ...(req.method !== 'GET' && req.method !== 'HEAD'
        ? { body: JSON.stringify(req.body) }
        : {}),
      signal: AbortSignal.timeout(15000), // 15s max (Galah necesita LLM time)
    });

    const body = await galahRes.text();

    // Alerta Telegram solo para IPs externas (sin spam de bots privados)
    const isInternalCrawler = INTERNAL_UA.some(u => ua.includes(u));
    if (TELEGRAM_TOKEN && TELEGRAM_CHAT && !isPrivate && !isInternalCrawler) {
      const emoji =
        rawPath.includes('.env') || rawPath.includes('config') ? '🔑' :
        rawPath.includes('wp-') || rawPath.includes('admin')   ? '🚨' :
        rawPath.includes('.php')                               ? '⚠️' :
        rawPath.includes('backup') || rawPath.includes('.sql') ? '💾' : '🕷️';

      const msg =
        `${emoji} <b>HoneyAI Web Decoy</b>\n` +
        `📍 <code>${req.method} ${rawPath}</code>\n` +
        `🌍 IP: <code>${ip}</code>\n` +
        `🖥️ UA: <code>${ua.substring(0, 80)}</code>\n` +
        `📦 HoneyAI status: ${galahRes.status}`;

      fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT, text: msg, parse_mode: 'HTML' }),
      }).catch(() => {});
    }

    // Devolver la respuesta de Galah tal cual al scanner
    const contentType = galahRes.headers.get('content-type') || 'text/html; charset=utf-8';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Server', 'Apache/2.4.57 (Debian)'); // Camuflar Caddy/Galah
    res.setHeader('X-Powered-By', 'PHP/8.1.2');
    return res.status(galahRes.status).send(body);

  } catch (err) {
    // Si Galah no responde (Pi apagado, timeout LLM) → respuesta genérica creíble
    const isTimeout = err.name === 'TimeoutError' || err.message?.includes('timeout');
    console.error('Galah proxy error:', isTimeout ? 'timeout' : err.message);

    // Fallback: respuesta 500 de servidor Apache (creíble para scanners)
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Server', 'Apache/2.4.57 (Debian)');
    return res.status(500).send(
      '<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>' +
      '<body><h1>Internal Server Error</h1>' +
      '<p>The server encountered an internal error and was unable to complete your request.</p>' +
      '<hr><address>Apache/2.4.57 (Debian) Server at honey-ai.dev Port 80</address>' +
      '</body></html>'
    );
  }
}
