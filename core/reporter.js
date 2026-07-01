/**
 * HoneyAI — Threat Intelligence Reporter
 * Reports attacker IPs to: AbuseIPDB, OTX, DShield, Blocklist.de, VirusTotal
 * Handles cooldowns, deduplication, and per-platform error recovery.
 */

const axios  = require('axios');
const fs     = require('fs');
const shodan = require('./shodan');
const path   = require('path');
const config = require('./config');
const { logger } = require('./logger');

const rep    = config.reporting;
const notify = config.notifications;

// ─── IP cooldown cache — capped at 10,000 entries to prevent memory leak ─────────
const reported      = new Map(); // ip → timestamp
const MAX_REPORTED  = 10_000;
const CACHE_FILE    = path.join(__dirname, '..', 'logs', '.reported-ips.json');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
    try {
        fs.mkdirSync(logsDir, { recursive: true });
    } catch (e) {
        // Ignored, handled by server setup
    }
}

// Load cache from file at startup
if (fs.existsSync(CACHE_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
        const cutoff = Date.now() - ((rep.cooldown_minutes || 1440) * 2 * 60 * 1000);
        for (const [ip, ts] of Object.entries(data)) {
            // Only load entries that aren't excessively old
            if (ts >= cutoff) {
                reported.set(ip, ts);
            }
        }
        logger.info(`Loaded ${reported.size} IPs from persistent report cache`, { protocol: 'reporter' });
    } catch (e) {
        logger.error(`Failed to load reported IPs cache: ${e.message}`, { protocol: 'reporter' });
    }
}

// Prune entries older than 2x the cooldown period (hourly) and save cache
setInterval(() => {
    const cooldown_mins = rep.cooldown_minutes || 1440;
    const cutoff  = Date.now() - (cooldown_mins * 2 * 60 * 1000);
    let changed = false;
    for (const [ip, ts] of reported) {
        if (ts < cutoff) {
            reported.delete(ip);
            changed = true;
        }
    }
    if (changed) {
        try {
            const data = Object.fromEntries(reported);
            fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
            cacheIsDirty = false;
        } catch (e) {
            logger.error(`Failed to save reported IPs cache: ${e.message}`, { protocol: 'reporter' });
        }
    } else if (cacheIsDirty) {
        // Debounced save for markReported() changes
        try {
            const data = Object.fromEntries(reported);
            fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
            cacheIsDirty = false;
        } catch (e) {
            logger.error(`Failed to save reported IPs cache: ${e.message}`, { protocol: 'reporter' });
        }
    }
}, 60 * 60 * 1000);

const { isPrivateIP } = require('./backfire');

function shouldReport(ip) {
    if (!rep.enabled) return false;
    if (!ip || isPrivateIP(ip)) return false; // Never report private IPs
    const lastSeen = reported.get(ip);
    const cooldown = (rep.cooldown_minutes || 1440) * 60 * 1000;
    return !lastSeen || (Date.now() - lastSeen) > cooldown;
}

let cacheIsDirty = false;

function markReported(ip) {
    // Evict oldest entry if at capacity
    if (reported.size >= MAX_REPORTED) {
        const oldest = reported.keys().next().value;
        reported.delete(oldest);
    }
    reported.set(ip, Date.now());
    cacheIsDirty = true;
}

// ─── Main entry point ─────────────────────────────────────────────────────────
async function report(ip, { protocol, comment, port, categories } = {}) {
    if (!shouldReport(ip)) return;
    markReported(ip);

    const defaultComment = `Malicious activity via ${protocol?.toUpperCase() || 'UNKNOWN'} on port ${port || '?'}. Detected by automated IDS.`;
    const finalComment   = comment || defaultComment;

    logger.info(`Reporting ${ip} to threat intel platforms`, { protocol: 'reporter', ip });

    // Run all reports in parallel, don't let one failure block others
    await Promise.allSettled([
        reportAbuseIPDB(ip, finalComment, categories, protocol),
        reportOTX(ip, protocol),
        reportDShield(ip, port, protocol),
        reportBlocklistDE(ip, finalComment),
    ]);

    // Telegram notification (fire-and-forget)
    sendTelegram(ip, protocol, port).catch(() => {});
}

// ─── AbuseIPDB ────────────────────────────────────────────────────────────────
// Categories: 14=Port Scan, 15=Hacking, 18=Brute-Force, 21=Web App Attack, 22=SSH
const PROTO_CATEGORIES = {
    http:   '21,14',
    ssh:    '22,18',
    ftp:    '5,18',
    telnet: '23,18',
    mysql:  '15,18',
    smtp:   '11,18',
    redis:  '15,14',
    git:    '15,14',
    vnc:    '15,14',
    rdp:    '15,14',
    samba:  '15,14',
    portscan: '14',
    httpproxy: '21,14',
    mssql:  '15,18',
    snmp:   '15,14',
    default:'14,15'
};

async function reportAbuseIPDB(ip, comment, categories, protocol) {
    if (!rep.abuseipdb?.enabled || !rep.abuseipdb.api_key) return;
    try {
        await axios.post('https://api.abuseipdb.com/api/v2/report', null, {
            params: {
                ip,
                comment,
                categories: categories || PROTO_CATEGORIES[protocol] || PROTO_CATEGORIES.default
            },
            headers: {
                Key: rep.abuseipdb.api_key,
                Accept: 'application/json'
            },
            timeout: 10000
        });
        logger.info(`AbuseIPDB: reported ${ip}`, { protocol: 'reporter', ip });
    } catch (e) {
        logger.warn(`AbuseIPDB failed for ${ip}: ${e.response?.data?.errors?.[0]?.detail || e.message}`, { protocol: 'reporter' });
    }
}

// ─── AlienVault OTX ───────────────────────────────────────────────────────────
// Protocol → pulse category routing
const OTX_PULSE_MAP = {
    ssh:       'ssh_pulse_id',
    telnet:    'ssh_pulse_id',
    http:      'web_pulse_id',
    mcp:       'web_pulse_id',
    httpproxy: 'web_pulse_id',
    mysql:     'db_pulse_id',
    mssql:     'db_pulse_id',
    redis:     'db_pulse_id',
    ftp:       'network_pulse_id',
    smtp:      'network_pulse_id',
    git:       'network_pulse_id',
    vnc:       'network_pulse_id',
    rdp:       'network_pulse_id',
    snmp:      'network_pulse_id',
    samba:     'network_pulse_id',
    portscan:  'network_pulse_id',
};

async function reportOTX(ip, protocol) {
    if (!rep.otx?.enabled || !rep.otx.api_key) return;
    const pulseKey = OTX_PULSE_MAP[protocol] || 'network_pulse_id';
    const pulseId = rep.otx[pulseKey];
    if (!pulseId) return;
    try {
        await axios.patch(
            `https://otx.alienvault.com/api/v1/pulses/${pulseId}`,
            { indicators: { add: [{ indicator: ip, type: 'IPv4', description: `Attacked via ${protocol} service` }] } },
            { headers: { 'X-OTX-API-KEY': rep.otx.api_key }, timeout: 10000 }
        );
        logger.info(`OTX: added ${ip} to pulse ${pulseId} (${protocol})`, { protocol: 'reporter', ip });
    } catch (e) {
        logger.warn(`OTX failed for ${ip}: ${e.message}`, { protocol: 'reporter' });
    }
}

// ─── SANS DShield ─────────────────────────────────────────────────────────────
async function reportDShield(ip, port, protocol) {
    if (!rep.dshield?.enabled || !rep.dshield.api_key) return;
    const date = new Date().toISOString().split('T')[0];
    // DShield format: date\ttime\ttz\tsrc\tnatkts\tdst\tport\tproto
    const line = `${date}\t00:00:00\t0\t${ip}\t1\t0.0.0.0\t${port || 0}\t6\n`;
    try {
        await axios.post('https://secure.dshield.org/api/submitlogs', line, {
            headers: {
                'Content-Type': 'text/plain',
                'Authorization': `Bearer ${rep.dshield.api_key}`
            },
            timeout: 10000
        });
        logger.info(`DShield: reported ${ip}`, { protocol: 'reporter', ip });
    } catch (e) {
        logger.warn(`DShield failed for ${ip}: ${e.message}`, { protocol: 'reporter' });
    }
}

// ─── Blocklist.de ─────────────────────────────────────────────────────────────
async function reportBlocklistDE(ip, comment) {
    if (!rep.blocklist_de?.enabled || !rep.blocklist_de.api_key) return;
    try {
        await axios.post('https://www.blocklist.de/api/report/ip/', null, {
            params: {
                apikey: rep.blocklist_de.api_key,
                ip,
                comment: comment.substring(0, 200)
            },
            timeout: 10000
        });
        logger.info(`Blocklist.de: reported ${ip}`, { protocol: 'reporter', ip });
    } catch (e) {
        logger.warn(`Blocklist.de failed for ${ip}: ${e.message}`, { protocol: 'reporter' });
    }
}

// ─── VirusTotal (malware samples only, called explicitly) ─────────────────────
async function submitMalware(fileBuffer, filename) {
    if (!rep.virustotal?.enabled || !rep.virustotal.api_key) return null;
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', fileBuffer, filename);
    try {
        const res = await axios.post('https://www.virustotal.com/api/v3/files', form, {
            headers: { ...form.getHeaders(), 'x-apikey': rep.virustotal.api_key },
            timeout: 30000
        });
        logger.info(`VirusTotal: submitted ${filename}`, { protocol: 'reporter' });
        return res.data;
    } catch (e) {
        logger.warn(`VirusTotal failed: ${e.message}`, { protocol: 'reporter' });
        return null;
    }
}

// ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
const PROTO_ATTACK = {
    ssh:       'T1110 Brute Force',
    http:      'T1190 Exploit Public App',
    ftp:       'T1078 Valid Accounts',
    telnet:    'T1021.007 Remote Service',
    smtp:      'T1071.003 Mail Protocol',
    mssql:     'T1190 Exploit DB',
    mysql:     'T1190 Exploit DB',
    redis:     'T1190 Exposed Service',
    samba:     'T1021.002 SMB/Windows Admin',
    snmp:      'T1046 Network Scan',
    mcp:       'T1190 Exploit API',
    httpproxy: 'T1090 Proxy',
    vnc:       'T1021.005 VNC',
    rdp:       'T1021.001 RDP',
    git:       'T1213 Data from Repos',
    portscan:  'T1046 Network Scan',
};

// ─── Severity Classification ──────────────────────────────────────────────────
function classifySeverity(protocol, details = {}) {
    // SEV1: Active exploitation / malware / C2
    if (details.malware_download || details.c2_callback || details.command_exec) {
        return { sev: 1, emoji: '🔴', label: 'CRITICAL' };
    }
    // SEV2: Successful auth / known exploit / active shell
    if (details.auth_success || details.exploit_attempt || details.shell_session) {
        return { sev: 2, emoji: '🟠', label: 'HIGH' };
    }
    // SEV3: Brute force / credential stuffing / recon
    if (['ssh', 'ftp', 'telnet', 'mssql', 'mysql', 'rdp', 'vnc', 'samba'].includes(protocol)) {
        return { sev: 3, emoji: '🟡', label: 'MEDIUM' };
    }
    // SEV4: Passive scan / bot probe
    return { sev: 4, emoji: '⚪', label: 'LOW' };
}

// ─── Confidence Scoring ───────────────────────────────────────────────────────
function assessConfidence(shodanData, protocol) {
    let indicators = 0;
    // Known protocol attack
    if (PROTO_ATTACK[protocol]) indicators++;
    // Shodan enrichment available
    if (shodanData) {
        if (shodanData.shodan_vulns?.length) indicators++;
        if (shodanData.is_known_scanner) indicators++;
        if (shodanData.shodan_ports?.length > 5) indicators++;  // many open ports = likely attacker infra
    }
    // Repeated offender (in reported cache)
    // protocols with auth = higher confidence
    if (['ssh', 'mssql', 'mysql', 'ftp', 'telnet'].includes(protocol)) indicators++;

    if (indicators >= 3) return 'HIGH';
    if (indicators >= 1) return 'MEDIUM';
    return 'LOW';
}

// ─── Telegram ─────────────────────────────────────────────────────────────────
async function sendTelegram(ip, protocol, port, details = {}) {
    if (!notify.telegram?.enabled || !notify.telegram.bot_token) return;
    // Enrich with Shodan InternetDB (best-effort, non-blocking)
    let shodanInfo = '';
    let shodanData = null;
    try {
        shodanData = await shodan.enrichAttacker(ip);
        if (shodanData) {
            if (shodanData.shodan_ports.length) shodanInfo += `\nPorts: ${shodanData.shodan_ports.join(', ')}`;
            if (shodanData.shodan_vulns.length) shodanInfo += `\n⚠️ CVEs: ${shodanData.shodan_vulns.slice(0, 3).join(', ')}`;
            if (shodanData.shodan_hostnames.length) shodanInfo += `\nHost: ${shodanData.shodan_hostnames[0]}`;
            if (shodanData.is_known_scanner) shodanInfo += '\n🔍 Known scanner';
        }
    } catch { /* best effort */ }

    // Severity & confidence
    const sev = classifySeverity(protocol, details);
    const confidence = assessConfidence(shodanData, protocol);
    const attack = PROTO_ATTACK[protocol] || 'T1595 Active Scan';

    const msg = [
        `${sev.emoji} *HoneyAI Alert* \\[${sev.label}\\]`,
        `\`${ip}\` → ${protocol?.toUpperCase() || '?'} port ${port}`,
        `🎯 ${attack}`,
        `📊 Confidence: ${confidence}`,
        shodanInfo,
    ].filter(Boolean).join('\n');

    await axios.post(
        `https://api.telegram.org/bot${notify.telegram.bot_token}/sendMessage`,
        { chat_id: notify.telegram.chat_id, text: msg, parse_mode: 'Markdown' },
        { timeout: 5000 }
    );
}

module.exports = { report, submitMalware, sendTelegram, classifySeverity, assessConfidence, shodanSelfScan: shodan.selfScan };

