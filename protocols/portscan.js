/**
 * HoneyAI — Portscan Log Monitor
 * Tails syslog/kern.log, parses iptables LOG packets, and reports scanner IPs.
 */

'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const net = require('net');
const config = require('../core/config');
const loggerModule = require('../core/logger');
const reporter = require('../core/reporter');
const backfire = require('../core/backfire');

let tailProcess = null;
let restartTimeout = null;
let retryCount = 0;
const MAX_RETRIES = 3;

function start() {
    const cfg = config.protocols.portscan;
    if (!cfg || !cfg.enabled) return;

    const logPath = cfg.log_path || '/var/log/syslog';
    loggerModule.logger.info(`Portscan log monitor active on log path: ${logPath}`, { protocol: 'portscan' });

    retryCount = 0;
    startTailing(logPath);
}

function startTailing(logPath) {
    if (tailProcess) {
        try { tailProcess.kill(); } catch (_) {}
        tailProcess = null;
    }
    if (restartTimeout) {
        clearTimeout(restartTimeout);
        restartTimeout = null;
    }

    if (!fs.existsSync(logPath)) {
        loggerModule.logger.warn(`Portscan log file does not exist: ${logPath}. Retry ${retryCount + 1}/${MAX_RETRIES}.`, { protocol: 'portscan' });
        retryCount++;
        if (retryCount >= MAX_RETRIES) {
            loggerModule.logger.error(`Portscan log file still missing after ${MAX_RETRIES} attempts. Disabling Portscan log monitor.`, { protocol: 'portscan' });
            return;
        }
        restartTimeout = setTimeout(() => {
            startTailing(logPath);
        }, 30000);
        return;
    }

    retryCount = 0;
    tailProcess = spawn('tail', ['-n', '0', '-F', logPath]);

    let lineBuffer = '';

    tailProcess.stdout.on('data', (data) => {
        lineBuffer += data.toString('utf8');
        let newlineIdx;
        while ((newlineIdx = lineBuffer.indexOf('\n')) !== -1) {
            const line = lineBuffer.slice(0, newlineIdx).trim();
            lineBuffer = lineBuffer.slice(newlineIdx + 1);
            if (line) {
                parsePortscanLine(line);
            }
        }
    });

    tailProcess.stderr.on('data', (data) => {
        const msg = data.toString('utf8').trim();
        if (msg) {
            loggerModule.logger.warn(`Portscan tail stderr: ${msg}`, { protocol: 'portscan' });
        }
    });

    tailProcess.on('error', (err) => {
        loggerModule.logger.error(`Portscan tail error: ${err.message}`, { protocol: 'portscan' });
    });

    tailProcess.on('exit', (code) => {
        loggerModule.logger.warn(`Portscan tail process exited with code ${code}. Restarting in 5s...`, { protocol: 'portscan' });
        restartTimeout = setTimeout(() => {
            startTailing(logPath);
        }, 5000);
    });
}

function stop() {
    if (tailProcess) {
        tailProcess.removeAllListeners('exit');
        try { tailProcess.kill(); } catch (_) {}
        tailProcess = null;
    }
    if (restartTimeout) {
        clearTimeout(restartTimeout);
        restartTimeout = null;
    }
}

function parsePortscanLine(line) {
    const cfg = config.protocols.portscan || {};
    const prefix = cfg.prefix || 'PORTSCAN:';

    if (!line.includes(prefix)) return;

    const srcMatch = line.match(/\bSRC=([0-9a-fA-F.:]+)\b/);
    const dstMatch = line.match(/\bDST=([0-9a-fA-F.:]+)\b/);
    const sptMatch = line.match(/\bSPT=(\d+)\b/);
    const dptMatch = line.match(/\bDPT=(\d+)\b/);
    const protoMatch = line.match(/\bPROTO=(TCP|UDP)\b/);

    if (srcMatch && dptMatch) {
        const ip = srcMatch[1].trim();
        const dstIp = dstMatch ? dstMatch[1].trim() : 'unknown';
        const dpt = parseInt(dptMatch[1], 10);
        const spt = sptMatch ? parseInt(sptMatch[1], 10) : null;
        const proto = protoMatch ? protoMatch[1].toUpperCase() : 'TCP';

        if (net.isIP(ip)) {
            loggerModule.logger.warn(`Portscan detected: ${ip} → dst=${dstIp} dpt=${dpt} proto=${proto}`, { protocol: 'portscan', ip });

            if (global.activeConnections && global.activeConnections.portscan !== undefined) {
                global.activeConnections.portscan++;
                setTimeout(() => {
                    if (global.activeConnections && global.activeConnections.portscan !== undefined) {
                        global.activeConnections.portscan--;
                    }
                }, 1000);
            }

            loggerModule.logEvent({
                protocol: 'portscan',
                ip,
                dst_ip: dstIp,
                dst_port: dpt,
                src_port: spt,
                proto: proto.toLowerCase(),
                attack_type: 'port_scan'
            });

            const comment = `Portscan attempt: ${ip} scanned port ${dpt} over ${proto}.`;
            reporter.report(ip, {
                protocol: 'portscan',
                port: dpt,
                comment
            }).catch(() => {});

            backfire.scanAttackerBack(ip);
        }
    }
}

module.exports = { start, stop, parsePortscanLine };
