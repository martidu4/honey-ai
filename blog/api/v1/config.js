// Fake API — /api/v1/config
// Returns realistic-looking production config with canarytoken AWS keys
// Reports directly to ALL 4 platforms + Telegram

import { reportToAllPlatforms, alertTelegram } from '../_lib/report-all.js';

export default async function handler(req, res) {
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);

  if (!isPrivate) {
    await reportToAllPlatforms(ip, '/api/v1/config', ua, {
      categories: '15,21',
      detail: 'Accessed fake config API /api/v1/config. Credential exfiltration attempt',
    });
    await alertTelegram(ip, '/api/v1/config', ua, {
      emoji: '🔑',
      extra: '⚠️ Attacker trying to exfiltrate credentials!',
    });
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Server', 'Apache/2.4.57 (Debian)');
  return res.status(200).json({
    status: 'success',
    environment: 'production',
    config: {
      database: { host:'db.honeypot.internal', port:3306, user:'root', password:'S3cur3P@ss2024!', name:'production_db' },
      redis: { url:'redis://default:r3d1sP@ss@cache.honeypot.internal:6379/0' },
      aws: { access_key_id:'AKIA3J3UHE32MVZOUVYX', secret_access_key:'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', region:'eu-west-1', s3_bucket:'honeypot-prod-backups' },
      stripe: { secret_key:'sk_live_51abc123def456ghi789', webhook_secret:'whsec_1234567890abcdef' },
      jwt: { secret:'hs256-eyJhbGciOiJIUzI1NiJ9-do-not-share', expiry:'24h' },
      smtp: { host:'smtp.gmail.com', port:587, user:'operator@honeypot.internal', password:'app-specific-password-fake' },
    }
  });
}
