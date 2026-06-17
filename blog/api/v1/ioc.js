// IoC Feed API — /api/v1/ioc
// Public endpoint for community threat intelligence
// Data is populated by the Pi5 dashboard generator and synced to public/ioc-data.json
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 's-maxage=1800, stale-while-revalidate=900');

  // Try to read synced IoC data from public directory
  const dataPath = join(process.cwd(), 'public', 'ioc-data.json');
  
  try {
    if (existsSync(dataPath)) {
      const raw = readFileSync(dataPath, 'utf8');
      const data = JSON.parse(raw);
      return res.status(200).json(data);
    }
  } catch (err) {
    // Fall through to fallback
  }

  // Fallback: return feed structure with metadata
  return res.status(200).json({
    feed: 'OpenClaw Threat Intelligence',
    version: '1.0',
    generated: new Date().toISOString(),
    source: 'honey-ai.dev',
    license: 'CC-BY-SA-4.0',
    description: 'Honeypot-sourced IoC feed — SSH brute force, HTTP scanners, multi-protocol traps. Updated every 30 minutes on the Pi5 collector.',
    dashboard: 'http://localhost:9090 (LAN only)',
    indicators: [],
    note: 'IoC data is synced from the Pi5 collector. If empty, the sync may be in progress.'
  });
}
