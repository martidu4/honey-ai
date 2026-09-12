// Trustworthy client IP for Vercel serverless functions.
//
// Why this exists: these endpoints report the IP straight to AbuseIPDB, OTX,
// DShield and Blocklist.de. Reading `x-forwarded-for.split(',')[0]` takes the
// FIRST entry, which is whatever the client sent — Vercel appends the real
// peer address, it does not replace the header. So anyone could run
//   curl -H 'X-Forwarded-For: 8.8.8.8' https://<blog>/api/v1/config
// and get an innocent IP reported to four public blocklists under our account.
//
// protocols/http.js already refuses to trust x-forwarded-for for exactly this
// reason; these functions have to hold the same line.
//
// Order of trust:
//   1. x-vercel-forwarded-for — set by Vercel's edge, overwritten on every
//      request, so a client cannot forge it.
//   2. x-real-ip — likewise set by the platform.
//   3. the LAST entry of x-forwarded-for — the hop nearest to us, i.e. the one
//      the edge appended. Never the first.

function normalize(ip) {
  if (!ip) return '';
  return String(ip).trim().replace(/^::ffff:/i, '').replace(/^\[|\]$/g, '');
}

export function clientIp(req) {
  const h = req.headers || {};

  const vercel = normalize(h['x-vercel-forwarded-for']);
  if (vercel) return vercel.split(',').pop().trim();

  const real = normalize(h['x-real-ip']);
  if (real) return real;

  const xff = String(h['x-forwarded-for'] || '');
  if (xff) {
    const hops = xff.split(',').map(normalize).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }

  return normalize(req.socket && req.socket.remoteAddress) || 'unknown';
}

// Reject anything that is not a routable public address before reporting it.
export function isReportableIp(ip) {
  if (!ip || ip === 'unknown') return false;

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if ([a, b, Number(v4[3]), Number(v4[4])].some(n => n > 255)) return false;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return true;
  }

  if (ip.includes(':')) {
    const low = ip.toLowerCase();
    if (low === '::1' || low === '::') return false;
    if (/^f[cd]/.test(low)) return false;        // fc00::/7 unique-local
    if (low.startsWith('fe80')) return false;    // link-local
    return true;
  }

  return false;
}
