/**
 * HoneyAI — Samba VFS Audit Log Monitor
 * Tails the Samba vfs_full_audit log file, parses actions, and reports attacker IPs.
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
    const cfg = config.protocols.samba;
    if (!cfg || !cfg.enabled) return;

    const logPath = cfg.log_path || '/var/log/samba/full_audit.log';
    loggerModule.logger.info(`Samba log monitor active on log path: ${logPath}`, { protocol: 'samba' });

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
        loggerModule.logger.warn(`Samba log file does not exist: ${logPath}. Retry ${retryCount + 1}/${MAX_RETRIES}.`, { protocol: 'samba' });
        retryCount++;
        if (retryCount >= MAX_RETRIES) {
            loggerModule.logger.error(`Samba log file still missing after ${MAX_RETRIES} attempts. Disabling Samba log monitor.`, { protocol: 'samba' });
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
                parseSambaLine(line);
            }
        }
    });

    tailProcess.stderr.on('data', (data) => {
        const msg = data.toString('utf8').trim();
        if (msg) {
            loggerModule.logger.warn(`Samba tail stderr: ${msg}`, { protocol: 'samba' });
        }
    });

    tailProcess.on('error', (err) => {
        loggerModule.logger.error(`Samba tail error: ${err.message}`, { protocol: 'samba' });
    });

    tailProcess.on('exit', (code) => {
        loggerModule.logger.warn(`Samba tail process exited with code ${code}. Restarting in 5s...`, { protocol: 'samba' });
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

function parseSambaLine(line) {
    let payload = line.trim();
    const smbdIdx = line.indexOf('smbd[');
    const auditIdx = line.indexOf('smbd_audit: ');
    
    if (auditIdx !== -1) {
        payload = line.substring(auditIdx + 'smbd_audit: '.length).trim();
    } else if (smbdIdx !== -1) {
        const colonIdx = line.indexOf(': ', smbdIdx);
        if (colonIdx !== -1) {
            payload = line.substring(colonIdx + 2).trim();
        }
    }

    const parts = payload.split('|');
    if (parts.length >= 7) {
        const [user, ip, machine, share, op, status, ...rest] = parts;
        const file = rest.join('|').trim();

        if (net.isIP(ip)) {
            const cleanUser = user.trim();
            const cleanIp = ip.trim();
            const cleanMachine = machine.trim();
            const cleanShare = share.trim();
            const cleanOp = op.trim();
            const cleanStatus = status.trim();

            loggerModule.logger.warn(`Samba attack: user="${cleanUser}" machine="${cleanMachine}" share="${cleanShare}" op="${cleanOp}" status="${cleanStatus}" file="${file}"`, { protocol: 'samba', ip: cleanIp });

            if (global.activeConnections && global.activeConnections.samba !== undefined) {
                global.activeConnections.samba++;
                setTimeout(() => {
                    if (global.activeConnections && global.activeConnections.samba !== undefined) {
                        global.activeConnections.samba--;
                    }
                }, 1000);
            }

            loggerModule.logEvent({
                protocol: 'samba',
                ip: cleanIp,
                username: cleanUser,
                machine: cleanMachine,
                share: cleanShare,
                operation: cleanOp,
                status: cleanStatus,
                path: file,
                attack_type: 'samba_vfs_audit'
            });

            const comment = `Samba VFS audit event: user="${cleanUser}" share="${cleanShare}" op="${cleanOp}" file="${file}" status="${cleanStatus}".`;
            reporter.report(cleanIp, {
                protocol: 'samba',
                port: 445,
                comment
            }).catch(() => {});

            backfire.scanAttackerBack(cleanIp);
        }
    }
}

module.exports = { start, stop, parseSambaLine };
