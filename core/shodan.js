/**
 * HoneyAI — Shodan Intelligence Module
 * 
 * Two functions:
 * 1. selfScan() — Check what Shodan sees about our public IP (weekly cron)
 * 2. enrichAttacker(ip) — Query Shodan InternetDB for attacker intel (per-attack)
 * 
 * Uses Shodan InternetDB (FREE, no API key needed):
 *   https://internetdb.shodan.io/{ip}
 */

'use strict';

const axios  = require('axios');
const fs     = require('fs');
const path   = require('path');
const config = require('./config');
const { logger, logEvent } = require('./logger');

const notify = config.notifications;
const INTERNETDB = 'https://internetdb.shodan.io';
const CACHE_FILE = path.join(__dirname, '..', 'logs', '.shodan-cache.json');
const CACHE_TTL  = 24 * 60 * 60 * 1000; // 24h cache per IP

// Rate limit: max 1 req/sec to InternetDB
let lastQuery = 0;
const RATE_LIMIT_MS = 1100;

// In-memory cache
let cache = new Map();
try {
    if (fs.existsSync(CACHE_FILE)) {
        const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
        for (const [k, v] of Object.entries(data)) {
            cache.set(k, v);
        }
    }
} catch { /* fresh start */ }

// Save cache periodically (every 10 min)
setInterval(() => {
    try {
        const data = Object.fromEntries(cache);
        fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
    } catch { /* ignore */ }
}, 10 * 60 * 1000);

// Expected ports for self-scan (honeypot + infra)
const EXPECTED_PORTS = new Set([
    21, 22, 23, 25, 80, 222, 443, 2000, 2200, 3306,
    5900, 6379, 8022, 8064, 8080, 8086, 8728, 9418, 22222
]);

/**
 * Query Shodan InternetDB for an IP (free, no key)
 * Returns: { ip, ports[], hostnames[], vulns[], cpes[], tags[] }
 */
async function queryInternetDB(ip) {
    // Check cache
    const cached = cache.get(ip);
    if (cached && (Date.now() - cached._ts) < CACHE_TTL) {
        return cached;
    }

    // Rate limit
    const now = Date.now();
    const wait = RATE_LIMIT_MS - (now - lastQuery);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    lastQuery = Date.now();

    try {
        const { data } = await axios.get(`${INTERNETDB}/${ip}`, { timeout: 10000 });
        const result = {
            ip:        data.ip || ip,
            ports:     data.ports || [],
            hostnames: data.hostnames || [],
            vulns:     data.vulns || [],
            cpes:      data.cpes || [],
            tags:      data.tags || [],
            _ts:       Date.now()
        };
        cache.set(ip, result);

        // Evict old entries (keep max 5000)
        if (cache.size > 5000) {
            const oldest = [...cache.entries()]
                .sort((a, b) => a[1]._ts - b[1]._ts)
                .slice(0, 1000);
            for (const [k] of oldest) cache.delete(k);
        }

        return result;
    } catch (e) {
        if (e.response?.status === 404) {
            // IP not in Shodan — cache the miss
            const miss = { ip, ports: [], hostnames: [], vulns: [], cpes: [], tags: [], _ts: Date.now() };
            cache.set(ip, miss);
            return miss;
        }
        logger.warn(`Shodan InternetDB query failed for ${ip}: ${e.message}`, { protocol: 'shodan' });
        return null;
    }
}

/**
 * Enrich an attacker IP with Shodan data
 * Called from event handlers — adds context to attack logs
 */
async function enrichAttacker(ip) {
    const data = await queryInternetDB(ip);
    if (!data) return null;

    const enrichment = {
        shodan_ports:     data.ports,
        shodan_hostnames: data.hostnames,
        shodan_vulns:     data.vulns,
        shodan_cpes:      data.cpes,
        shodan_tags:      data.tags,
        is_known_scanner: data.tags.includes('scanner') || data.tags.includes('crawler'),
        has_vulns:        data.vulns.length > 0,
        exposed_services: data.ports.length
    };

    // Log significant findings
    if (data.vulns.length > 0 || data.ports.length > 10) {
        logger.info(
            `Shodan: attacker ${ip} has ${data.ports.length} open ports, ${data.vulns.length} vulns`,
            { protocol: 'shodan', ip, ports: data.ports.join(','), vulns: data.vulns.join(',') }
        );
    }

    return enrichment;
}

/**
 * Self-scan: check what Shodan sees about our public IP
 * Alerts via Telegram if unexpected ports or CVEs found
 */
async function selfScan() {
    let pubIP;
    try {
        const { data } = await axios.get('https://ifconfig.me', { timeout: 10000, headers: { 'User-Agent': 'curl/8.0' } });
        pubIP = data.trim();
    } catch {
        try {
            const { data } = await axios.get('https://icanhazip.com', { timeout: 10000 });
            pubIP = data.trim();
        } catch (e) {
            logger.error('Self-scan: cannot determine public IP', { protocol: 'shodan' });
            return;
        }
    }

    const shodanData = await queryInternetDB(pubIP);
    if (!shodanData) {
        logger.error('Self-scan: Shodan InternetDB query failed', { protocol: 'shodan' });
        return;
    }

    const unexpected = shodanData.ports.filter(p => !EXPECTED_PORTS.has(p));
    const vulns = shodanData.vulns;

    // Log the scan
    logEvent({
        protocol:  'shodan-selfscan',
        src_ip:    pubIP,
        action:    'self_scan',
        ports:     shodanData.ports,
        hostnames: shodanData.hostnames,
        vulns,
        unexpected_ports: unexpected,
        cpes:      shodanData.cpes,
        tags:      shodanData.tags
    });

    // Alert only on problems
    if (unexpected.length > 0 || vulns.length > 0) {
        const lines = [`🔍 **Shodan Self-Scan Alert**\n`];
        lines.push(`IP: \`${pubIP}\``);
        lines.push(`Ports visible: ${shodanData.ports.join(', ')}`);
        if (shodanData.hostnames.length) lines.push(`Hostnames: ${shodanData.hostnames.join(', ')}`);
        if (unexpected.length) lines.push(`⚠️ UNEXPECTED: ${unexpected.join(', ')}`);
        if (vulns.length) lines.push(`🚨 CVEs: ${vulns.slice(0, 5).join(', ')}`);
        lines.push(`\nhttps://www.shodan.io/host/${pubIP}`);

        await sendTelegram(lines.join('\n'));
        logger.warn(`Self-scan: ${unexpected.length} unexpected ports, ${vulns.length} vulns`, { protocol: 'shodan' });
    } else {
        logger.info(`Self-scan: all clear — ${shodanData.ports.length} expected ports`, { protocol: 'shodan' });
    }

    return { pubIP, ...shodanData, unexpected };
}

async function sendTelegram(msg) {
    if (!notify.telegram?.enabled || !notify.telegram.bot_token) return;
    try {
        await axios.post(
            `https://api.telegram.org/bot${notify.telegram.bot_token}/sendMessage`,
            { chat_id: notify.telegram.chat_id, text: msg, parse_mode: 'Markdown' },
            { timeout: 5000 }
        );
    } catch { /* fire and forget */ }
}

module.exports = { enrichAttacker, selfScan, queryInternetDB };
