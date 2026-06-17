// Vercel serverless proxy for ip-api.com batch geolocation
// Solves mixed-content issue: client HTTPS page can't call http://ip-api.com
// This function runs server-side (HTTP allowed), returns over HTTPS to client

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  try {
    const ips = req.body;
    if (!Array.isArray(ips) || ips.length === 0 || ips.length > 100) {
      return res.status(400).json({ error: 'Invalid input: expected 1-100 IPs' });
    }
    // Validate each entry is a plausible IP string
    const ipRegex = /^[\d.:a-fA-F]+$/;
    if (!ips.every(ip => typeof ip === 'string' && ip.length < 46 && ipRegex.test(ip))) {
      return res.status(400).json({ error: 'Invalid IP format' });
    }

    // ip-api.com free tier: HTTP only, max 100 IPs per batch
    const r = await fetch('http://ip-api.com/batch?fields=query,countryCode,country', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ips.slice(0, 100).map(ip => ({ query: ip }))),
      signal: AbortSignal.timeout(5000),
    });

    if (!r.ok) return res.status(200).json([]);
    const data = await r.json();

    res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate');
    return res.status(200).json(data);
  } catch {
    return res.status(200).json([]);
  }
}
