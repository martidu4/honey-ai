// Fake API — /api/v1/users
// Returns realistic-looking user data. Every request is a trap.
// Reports directly to ALL 4 platforms + Telegram

import { reportToAllPlatforms, alertTelegram } from '../_lib/report-all.js';

export default async function handler(req, res) {
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);

  if (!isPrivate) {
    // Report to ALL 4 platforms with real attacker IP
    await reportToAllPlatforms(ip, '/api/v1/users', ua, {
      categories: '15,21',
      detail: 'Accessed fake API endpoint /api/v1/users. Unauthorized data exfiltration attempt',
    });
    await alertTelegram(ip, '/api/v1/users', ua, { emoji: '🎣' });
  }

  // Dynamic timestamp
  const now = new Date().toISOString();

  // Fake user data response
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Server', 'Apache/2.4.57 (Debian)');
  res.setHeader('X-Powered-By', 'PHP/8.1.2');
  res.setHeader('X-Total-Count', '4');
  res.setHeader('X-Page', '1');
  return res.status(200).json({
    status: 'success',
    data: {
      users: [
        { id: 1, username: 'admin', email: 'admin@honeypot.internal', role: 'superadmin', last_login: now, api_key: 'sk-adm-a1b2c3d4e5f6' },
        { id: 2, username: 'operator', email: 'operator@honeypot.internal', role: 'admin', last_login: now, api_key: 'sk-usr-g7h8i9j0k1l2' },
        { id: 3, username: 'analyst1', email: 'analyst@honeypot.internal', role: 'analyst', last_login: '2026-05-04T09:15:00Z', api_key: 'sk-anl-m3n4o5p6q7r8' },
        { id: 4, username: 'viewer_bot', email: 'bot@honeypot.internal', role: 'viewer', last_login: null, api_key: null },
      ],
      pagination: { page: 1, per_page: 20, total: 4 }
    }
  });
}
