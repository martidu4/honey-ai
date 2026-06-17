// Canarytoken Webhook Receiver — Vercel Serverless Function
// canarytokens.org sends POST here when a token is triggered
// Logs to a local file on Pi via Telegram + reports to 4 platforms

import { reportToAllPlatforms, alertTelegram } from './_lib/report-all.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }

  const data = req.body || {};
  const srcIp = data.src_ip || data.ip || 'unknown';
  const tokenType = data.token_type || data.type || 'unknown';
  const memo = data.memo || '';
  const additional = data.additional_data || {};
  const awsKey = additional.aws_access_key_id || '';
  const ua = additional.useragent || data.useragent || 'canarytoken-trigger';
  const ts = new Date().toISOString();

  console.log(`[CANARYTOKEN] ${ts} | ${tokenType} | ${srcIp} | ${memo}`);

  // Report attacker IP to all 4 platforms
  const detail = `Canarytoken ${tokenType} triggered — attacker used honeypot trap credentials`;
  await reportToAllPlatforms(srcIp, `/canarytoken/${tokenType}`, ua, {
    categories: '15,19,21',  // Hacking, Web Exploit, Unauthorized access
    detail,
  });

  // Alert Telegram
  const extra = awsKey ? `🔑 AWS Key: <code>${awsKey}</code>` : '';
  await alertTelegram(srcIp, `/canarytoken/${tokenType}`, ua, {
    emoji: '🪤',
    extra: `🪤 <b>CANARYTOKEN TRIGGERED!</b>\n📋 Memo: ${memo}\n${extra}`,
  });

  return res.status(200).json({ ok: true, logged: true });
}

export const config = { api: { bodyParser: true } };
