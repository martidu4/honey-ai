// Fake API — /api/v1/export
// Returns a CSV-looking "customer data export" — maximum bait
// Reports directly to ALL 4 platforms + Telegram

import { reportToAllPlatforms, alertTelegram } from '../_lib/report-all.js';

export default async function handler(req, res) {
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.headers['x-real-ip'] || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  const isPrivate = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(ip);

  if (!isPrivate) {
    await reportToAllPlatforms(ip, '/api/v1/export', ua, {
      categories: '15,21',
      detail: 'Accessed fake data export API /api/v1/export. Data exfiltration attempt',
    });
    await alertTelegram(ip, '/api/v1/export', ua, {
      emoji: '💾',
      extra: '🚨 Attacker trying to download "customer data"!',
    });
  }

  // Return a fake CSV export with generated data
  const csv = [
    'id,name,email,phone,plan,monthly_spend,signup_date',
    '1,Carlos Martinez,carlos.m@example.com,+34612345001,Enterprise,€2400,2025-03-15',
    '2,Laura Fernandez,laura.f@example.com,+34612345002,Pro,€89,2025-04-22',
    '3,Miguel Angel Torres,mat@example.com,+34612345003,Enterprise,€4800,2025-01-10',
    '4,Ana Garcia Lopez,ana.gl@example.com,+34612345004,Basic,€29,2025-06-01',
    '5,David Rodriguez,david.r@example.com,+34612345005,Pro,€89,2025-07-18',
    '6,Sofia Ruiz,sofia.ruiz@example.com,+34612345006,Enterprise,€3600,2025-02-28',
    '7,Pablo Jimenez,p.jimenez@example.com,+34612345007,Basic,€29,2025-08-05',
    '8,Maria Lopez,maria.l@example.com,+34612345008,Pro,€89,2025-09-12',
    '9,Javier Moreno,javier.m@example.com,+34612345009,Enterprise,€7200,2024-11-20',
    '10,Elena Sanchez,elena.s@example.com,+34612345010,Pro,€89,2025-10-01',
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="customers_export_2026-05-06.csv"');
  res.setHeader('Server', 'Apache/2.4.57 (Debian)');
  return res.status(200).send(csv);
}
