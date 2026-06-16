/**
 * HoneyAI — Port Scan Backfire Module
 * Performs lightweight, asynchronous reverse port scans on public attacker IPs.
 */

'use strict';

const net = require('net');
const axios = require('axios');
const config = require('./config');
const { logger, logEvent } = require('./logger');

const notify = config.notifications;

async function sendTelegramAlert(ip, openPorts, hostname) {
    if (!notify.telegram?.enabled || !notify.telegram.bot_token) return;
    const portsStr = openPorts.join(', ');
    const hostStr = hostname ? ` (${hostname})` : '';
    const msg = `💥 *[Operation Spine]*\nAttacker \`${ip}\`${hostStr} scanned.\nOpen ports: *${portsStr}* (Public services exposed on the internet).`;
    try {
        await axios.post(
            `https://api.telegram.org/bot${notify.telegram.bot_token}/sendMessage`,
            { chat_id: notify.telegram.chat_id, text: msg, parse_mode: 'Markdown' },
            { timeout: 5000 }
        );
    } catch (err) {
        logger.error(`Failed to send backfire Telegram alert: ${err.message}`, { protocol: 'backfire' });
    }
}

function convertIPv4Mapped(ip) {
    const downloader = require('./downloader');
    return downloader.convertIPv4Mapped(ip);
}

function isPrivateIP(ip) {
    const downloader = require('./downloader');
    return downloader.isPrivateIP(ip);
}


const SCANNED_IPS = new Map();
const MAX_SCANNED_IPS = 1000;
let activeScansCount = 0;
const MAX_CONCURRENT_SCANS = 5;
const COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

// Periodically clean up expired cooldowns to prevent memory leaks (LOW-A)
setInterval(() => {
    const now = Date.now();
    for (const [ip, ts] of SCANNED_IPS) {
        if (now - ts >= COOLDOWN_MS) {
            SCANNED_IPS.delete(ip);
        }
    }
}, 6 * 60 * 60 * 1000); // Clean up every 6 hours


/**
 * Performs a silent, async port scan on common ports of the attacker's IP.
 * 
 * @param {string} ip 
 */
function scanAttackerBack(ip) {
    if (isPrivateIP(ip)) {
        logger.info(`Bypassing backfire port scan for private/local IP: ${ip}`, { protocol: 'backfire' });
        return;
    }

    const now = Date.now();
    const lastScan = SCANNED_IPS.get(ip);
    if (lastScan && (now - lastScan < COOLDOWN_MS)) {
        logger.info(`Bypassing backfire port scan for ${ip} (cooldown active)`, { protocol: 'backfire', ip });
        return;
    }

    if (activeScansCount >= MAX_CONCURRENT_SCANS) {
        logger.info(`Bypassing backfire port scan for ${ip} (max concurrent scans reached: ${activeScansCount})`, { protocol: 'backfire', ip });
        return;
    }

    // Evict oldest scanned IP if at capacity to prevent memory leaks (LOW-A)
    if (SCANNED_IPS.size >= MAX_SCANNED_IPS) {
        const oldest = SCANNED_IPS.keys().next().value;
        SCANNED_IPS.delete(oldest);
    }
    SCANNED_IPS.set(ip, now);
    activeScansCount++;

    const ports = [22, 23, 80, 443, 8080, 8443];
    const openPorts = [];

    logger.info(`Starting backfire port scan on attacker ${ip} (active scans: ${activeScansCount})...`, { protocol: 'backfire', ip });

    let completed = 0;
    ports.forEach(port => {
        const socket = new net.Socket();
        socket.setTimeout(1500);

        socket.on('connect', () => {
            openPorts.push(port);
            socket.destroy();
            checkDone();
        });

        socket.on('timeout', () => {
            socket.destroy();
            checkDone();
        });

        socket.on('error', () => {
            socket.destroy();
            checkDone();
        });

        socket.connect(port, ip);
    });

    function checkDone() {
        completed++;
        if (completed === ports.length) {
            activeScansCount = Math.max(0, activeScansCount - 1);
            if (openPorts.length > 0) {
                logger.warn(`Backfire scan complete for ${ip}: Open ports: ${openPorts.join(', ')}`, { protocol: 'backfire', ip });
                
                // Perform Reverse DNS (PTR) lookup
                const dns = require('dns');
                dns.reverse(ip, (err, hostnames) => {
                    const reverse_dns = (!err && hostnames && hostnames.length > 0) ? hostnames[0] : '';
                    
                    logEvent({
                        protocol: 'backfire',
                        ip,
                        reverse_dns,
                        open_ports: openPorts,
                        attack_type: 'port_scan_backfire_completed'
                    });

                    // Send Telegram notification
                    sendTelegramAlert(ip, openPorts, reverse_dns).catch(() => {});
                });
            } else {
                logger.info(`Backfire scan complete for ${ip}: No common open ports found.`, { protocol: 'backfire', ip });
            }
        }
    }
}

function resetBackfireCache() {
    SCANNED_IPS.clear();
    activeScansCount = 0;
}

module.exports = {
    scanAttackerBack,
    isPrivateIP,
    resetBackfireCache
};
