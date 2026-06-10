/**
 * OpenClaw HoneyAI — Port Scan Backfire Module
 * Performs lightweight, asynchronous reverse port scans on public attacker IPs.
 */

'use strict';

const net = require('net');
const { logger, logEvent } = require('./logger');

function convertIPv4Mapped(ip) {
    const downloader = require('./downloader');
    return downloader.convertIPv4Mapped(ip);
}

function isPrivateIP(ip) {
    const downloader = require('./downloader');
    return downloader.isPrivateIP(ip);
}


const SCANNED_IPS = new Map();
let activeScansCount = 0;
const MAX_CONCURRENT_SCANS = 5;
const COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

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
                logEvent({
                    protocol: 'backfire',
                    ip,
                    open_ports: openPorts,
                    attack_type: 'port_scan_backfire_completed'
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
