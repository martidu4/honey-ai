import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

export const GET: APIRoute = async (context) => {
  const reports = (await getCollection('reports'))
    .sort((a, b) => b.data.date.valueOf() - a.data.date.valueOf());

  return rss({
    title: 'Honeypot Daily — Threat Intelligence',
    description: 'Daily attack reports from HoneyAI and legacy honeypot decoys. SSH bruteforce, IoT botnet, multi-protocol attack data.',
    site: context.site!,
    items: reports.map(report => ({
      title: `Daily Report — ${report.data.date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} [${report.data.severity.toUpperCase()}]`,
      pubDate: report.data.date,
      description: `${report.data.cowrie_connections} SSH connections · ${report.data.cowrie_ips + report.data.opencanary_ips} unique IPs · ${report.data.abuseipdb_reported} reported to AbuseIPDB`,
      link: `/reports/${report.data.date.toISOString().slice(0, 10)}/`,
    })),
    customData: '<language>en</language>',
  });
};
