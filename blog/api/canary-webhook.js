// Canarytoken Webhook Receiver — Vercel Serverless Function
// canarytokens.org sends POST here when a token is triggered
// Reports the attacker IP to 4 platforms + Telegram alert

import crypto from 'node:crypto';
import { reportToAllPlatforms, alertTelegram } from './_lib/report-all.js';
import { isReportableIp } from './_lib/client-ip.js';

// This endpoint takes the attacker IP from the REQUEST BODY (src_ip) — that is
// how canarytokens.org reports it, and there is no way around it. Unauthenticated,
// that makes this a public "report any IP as malicious" API: anyone could POST
// {"src_ip":"<innocent address>"} and have it pushed to AbuseIPDB, OTX, DShield
// and Blocklist.de under our account. So the shared secret is mandatory.
//
// Setup:
//   1. vercel env add CANARY_WEBHOOK_SECRET     (any long random string)
//   2. In canarytokens.org, set the webhook URL to
//        https://<blog>/api/canary-webhook?token=<that same string>
//
// Without the variable set the endpoint reports nothing — failing closed is the
// only safe default when the alternative is poisoning public blocklists.
function authorized(req) {
  const expected = process.env.CANARY_WEBHOOK_SECRET;
  if (!expected) return false;

  const url = new URL(req.url, 'https://placeholder.invalid');
  const provided =
    url.searchParams.get('token') ||
    req.headers['x-canary-token'] ||
    '';

  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  // timingSafeEqual throws on length mismatch, so compare lengths first
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }

  if (!authorized(req)) {
    if (!process.env.CANARY_WEBHOOK_SECRET) {
      console.warn('[CANARYTOKEN] CANARY_WEBHOOK_SECRET is not set — refusing to report. See blog/api/canary-webhook.js');
    }
    // Deliberately indistinguishable from a wrong token.
    return res.status(403).json({ error: 'Forbidden' });
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

  if (!isReportableIp(srcIp)) {
    return res.status(200).json({ ok: true, logged: true, reported: false });
  }

  // Report attacker IP to all 4 platforms
  const detail = `Canarytoken ${tokenType} triggered — attacker used honeypot trap credentials`;
  await reportToAllPlatforms(srcIp, `/canarytoken/${tokenType}`, ua, {
    categories: '15,19,21',  // Hacking, Web Exploit, Unauthorized access
    detail,
  });

  // Alert Telegram. memo and awsKey come from the payload, so escape them:
  // alertTelegram sends parse_mode HTML.
  const esc = (v) => String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const extra = awsKey ? `🔑 AWS Key: <code>${esc(awsKey)}</code>` : '';
  await alertTelegram(srcIp, `/canarytoken/${tokenType}`, ua, {
    emoji: '🪤',
    extra: `🪤 <b>CANARYTOKEN TRIGGERED!</b>\n📋 Memo: ${esc(memo)}\n${extra}`,
  });

  return res.status(200).json({ ok: true, logged: true, reported: true });
}

export const config = { api: { bodyParser: true } };
