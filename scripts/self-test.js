#!/usr/bin/env node
/**
 * HoneyAI Self-Test — Anti-Fingerprinting Checker (Medal 3)
 * 
 * Connects to the local honeypot via SSH and HTTP, runs the 7 checks
 * from the Vetterl/Clayton honeypot detection paper (BlackHat EU 2023).
 * 
 * Usage:
 *   node scripts/self-test.js [host] [ssh-port] [http-port]
 *   
 * Defaults:
 *   host     = 127.0.0.1
 *   ssh-port = 2222
 *   http-port = 8080
 */

'use strict';

const { Client } = require('ssh2');
const http = require('http');
const net  = require('net');

const HOST      = process.argv[2] || '127.0.0.1';
const SSH_PORT  = parseInt(process.argv[3] || '2222', 10);
const HTTP_PORT = parseInt(process.argv[4] || '8080', 10);

let passed = 0;
let warned = 0;
let failed = 0;

function log(status, msg) {
    const icon = status === 'PASS' ? '\x1b[32m[PASS]\x1b[0m'
               : status === 'WARN' ? '\x1b[33m[WARN]\x1b[0m'
               : '\x1b[31m[FAIL]\x1b[0m';
    console.log(`${icon} ${msg}`);
    if (status === 'PASS') passed++;
    else if (status === 'WARN') warned++;
    else failed++;
}

// ─── Check 1: SSH Banner Fingerprinting ───────────────────────────────────────
function checkSSHBanner() {
    return new Promise((resolve) => {
        const socket = net.createConnection(SSH_PORT, HOST, () => {
            socket.once('data', (data) => {
                const banner = data.toString().trim();
                socket.destroy();
                
                // Real Debian 12 OpenSSH banner should be OpenSSH_9.2p1
                if (banner.includes('OpenSSH_9.2p1')) {
                    log('PASS', `SSH banner matches Debian 12: "${banner}"`);
                } else if (banner.includes('OpenSSH')) {
                    log('WARN', `SSH banner has OpenSSH but wrong version: "${banner}" (expected 9.2p1)`);
                } else {
                    log('FAIL', `SSH banner doesn't look like OpenSSH: "${banner}"`);
                }
                resolve();
            });
        });
        socket.on('error', (err) => {
            log('FAIL', `SSH banner check: cannot connect to ${HOST}:${SSH_PORT} — ${err.message}`);
            resolve();
        });
        socket.setTimeout(5000, () => {
            log('FAIL', 'SSH banner check: timeout (5s)');
            socket.destroy();
            resolve();
        });
    });
}

// ─── Check 2: SSH Command Timing Analysis ─────────────────────────────────────
function sshExec(conn, cmd) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        conn.exec(cmd, (err, stream) => {
            if (err) return reject(err);
            let output = '';
            stream.on('data', (d) => output += d.toString());
            stream.stderr.on('data', (d) => output += d.toString());
            stream.on('close', () => resolve({ output: output.trim(), ms: Date.now() - start }));
        });
    });
}

async function checkTiming(conn) {
    const commands = ['ls', 'whoami', 'id', 'uname -a', 'cat /etc/passwd'];
    for (const cmd of commands) {
        try {
            const { output, ms } = await sshExec(conn, cmd);
            if (ms < 100) {
                log('PASS', `Timing "${cmd}": ${ms}ms (< 100ms — fast, realistic)`);
            } else if (ms < 500) {
                log('WARN', `Timing "${cmd}": ${ms}ms (< 500ms — acceptable but slow for a real server)`);
            } else {
                log('FAIL', `Timing "${cmd}": ${ms}ms (> 500ms — attackers will notice the delay)`);
            }
        } catch (err) {
            log('FAIL', `Timing "${cmd}": exec failed — ${err.message}`);
        }
    }
}

// ─── Check 3: Filesystem Consistency ──────────────────────────────────────────
async function checkFilesystem(conn) {
    // /proc/self/exe should exist and point to /usr/bin/bash
    try {
        const { output } = await sshExec(conn, 'readlink /proc/self/exe');
        if (output.includes('/usr/bin/bash') || output.includes('/bin/bash')) {
            log('PASS', `/proc/self/exe → ${output}`);
        } else if (output.length > 0) {
            log('WARN', `/proc/self/exe → "${output}" (expected /usr/bin/bash)`);
        } else {
            log('FAIL', `/proc/self/exe returned empty (honeypot fingerprint!)`);
        }
    } catch (err) {
        log('FAIL', `/proc/self/exe check failed: ${err.message}`);
    }

    // ls /proc should have entries
    try {
        const { output } = await sshExec(conn, 'ls /proc');
        if (output.length > 10) {
            log('PASS', `ls /proc returns entries (${output.substring(0, 50)}...)`);
        } else {
            log('FAIL', `ls /proc returned too little: "${output}"`);
        }
    } catch (err) {
        log('FAIL', `ls /proc check failed: ${err.message}`);
    }
}

// ─── Check 4: Command Consistency ─────────────────────────────────────────────
async function checkConsistency(conn) {
    try {
        const { output: uname } = await sshExec(conn, 'uname -a');
        const { output: osRelease } = await sshExec(conn, 'cat /etc/os-release');
        
        const unameHasDebian = uname.toLowerCase().includes('debian');
        const osReleaseHasDebian = osRelease.toLowerCase().includes('debian');
        
        if (unameHasDebian && osReleaseHasDebian) {
            log('PASS', 'uname -a and /etc/os-release both report Debian');
        } else {
            log('FAIL', `Inconsistency: uname says "${uname.substring(0, 40)}", os-release says "${osRelease.substring(0, 40)}"`);
        }

        // Check kernel version consistency
        const unameKernel = uname.match(/\d+\.\d+\.\d+-\d+-amd64/);
        const procVersion = (await sshExec(conn, 'cat /proc/version')).output;
        const procKernel = procVersion.match(/\d+\.\d+\.\d+-\d+-amd64/);
        
        if (unameKernel && procKernel && unameKernel[0] === procKernel[0]) {
            log('PASS', `Kernel version consistent: ${unameKernel[0]}`);
        } else {
            log('WARN', `Kernel version mismatch: uname="${unameKernel?.[0]}" vs /proc/version="${procKernel?.[0]}"`);
        }
    } catch (err) {
        log('FAIL', `Consistency check failed: ${err.message}`);
    }
}

// ─── Check 5: Docker Detection ────────────────────────────────────────────────
async function checkDocker(conn) {
    try {
        const { output } = await sshExec(conn, 'ls -la /.dockerenv');
        if (output.includes('No such file')) {
            log('PASS', '/.dockerenv correctly denied (not a Docker container)');
        } else {
            log('FAIL', `/.dockerenv exists — reveals it's running in Docker: "${output}"`);
        }
    } catch (err) {
        log('FAIL', `Docker check failed: ${err.message}`);
    }

    // Also check cgroup for docker traces
    try {
        const { output } = await sshExec(conn, 'cat /proc/self/cgroup');
        if (output.includes('docker') || output.includes('containerd')) {
            log('WARN', `/proc/self/cgroup leaks container info: "${output.substring(0, 60)}"`);
        } else {
            log('PASS', `/proc/self/cgroup clean — no container fingerprint`);
        }
    } catch (err) {
        log('WARN', `cgroup check failed: ${err.message}`);
    }
}

// ─── Check 6: Process Tree ────────────────────────────────────────────────────
async function checkProcessTree(conn) {
    try {
        const { output } = await sshExec(conn, 'cat /proc/1/cmdline');
        if (output.includes('init') || output.includes('systemd')) {
            log('PASS', `PID 1 is ${output} (realistic)`);
        } else {
            log('FAIL', `PID 1 is "${output}" — real Linux has /sbin/init or systemd`);
        }
    } catch (err) {
        log('FAIL', `Process tree check failed: ${err.message}`);
    }

    // Check ps output for reasonable processes
    try {
        const { output } = await sshExec(conn, 'ps aux');
        const hasInit = output.includes('init') || output.includes('systemd');
        const hasSshd = output.includes('sshd');
        const hasBash = output.includes('bash');
        
        if (hasInit && hasSshd && hasBash) {
            log('PASS', 'ps aux shows init/sshd/bash — realistic process tree');
        } else {
            const missing = [];
            if (!hasInit) missing.push('init/systemd');
            if (!hasSshd) missing.push('sshd');
            if (!hasBash) missing.push('bash');
            log('WARN', `ps aux missing: ${missing.join(', ')}`);
        }
    } catch (err) {
        log('FAIL', `ps aux check failed: ${err.message}`);
    }
}

// ─── Check 7: HTTP Fingerprinting ─────────────────────────────────────────────
function httpGet(path) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: HOST,
            port: HTTP_PORT,
            path,
            method: 'GET',
            timeout: 5000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; SelfTest/1.0)',
            }
        }, (res) => {
            let body = '';
            res.on('data', (d) => body += d.toString());
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        });
        req.on('error', (err) => resolve({ error: err.message }));
        req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
        req.end();
    });
}

async function checkHTTP() {
    // Check Server header consistency
    const res = await httpGet('/');
    if (res.error) {
        log('FAIL', `HTTP check: cannot connect to ${HOST}:${HTTP_PORT} — ${res.error}`);
        return;
    }

    const server = res.headers['server'] || '';
    if (server.includes('Apache')) {
        log('PASS', `HTTP Server header: "${server}" (looks like Apache)`);
    } else if (server.includes('nginx')) {
        log('PASS', `HTTP Server header: "${server}" (looks like nginx)`);
    } else if (server) {
        log('WARN', `HTTP Server header: "${server}" (unusual)`);
    } else {
        log('WARN', 'HTTP Server header missing');
    }

    // Check identity leak — search for honeypot keywords
    const body = res.body.toLowerCase();
    const leakWords = ['honeypot', 'honeyai', 'decoy', 'trap', 'simulation', 'fake server'];
    for (const word of leakWords) {
        if (body.includes(word)) {
            log('FAIL', `HTTP response leaks identity keyword: "${word}"`);
        }
    }

    // Check that .git/config doesn't reveal real repo
    const gitRes = await httpGet('/.git/config');
    if (gitRes.error) {
        log('WARN', `/.git/config check: ${gitRes.error}`);
    } else {
        const gitBody = gitRes.body.toLowerCase();
        if (gitBody.includes('honeyai') || gitBody.includes('openclaw') || gitBody.includes('honeypot')) {
            log('FAIL', `/.git/config leaks real repo name`);
        } else {
            log('PASS', '/.git/config does not leak real project name');
        }
    }

    // Check that /.env doesn't say "honeyai" or "ollama"
    const envRes = await httpGet('/.env');
    if (!envRes.error) {
        const envBody = envRes.body.toLowerCase();
        if (envBody.includes('ollama') || envBody.includes('honeyai') || envBody.includes('honeypot')) {
            log('FAIL', `/.env leaks honeypot infrastructure keywords`);
        } else {
            log('PASS', '/.env does not leak infrastructure keywords');
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║  HoneyAI Self-Test — Anti-Fingerprinting Checker           ║');
    console.log('║  Based on Vetterl/Clayton honeypot detection techniques     ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`Target: ${HOST}  SSH:${SSH_PORT}  HTTP:${HTTP_PORT}`);
    console.log('');

    // Check 1: SSH Banner
    console.log('── Check 1: SSH Banner Fingerprinting ──');
    await checkSSHBanner();
    console.log('');

    // Checks 2-6: SSH interactive
    console.log('── Check 2-6: SSH Interactive Tests ──');
    const conn = new Client();
    
    await new Promise((resolve) => {
        conn.on('ready', async () => {
            try {
                console.log('── Check 2: Command Timing ──');
                await checkTiming(conn);
                console.log('');

                console.log('── Check 3: Filesystem Consistency ──');
                await checkFilesystem(conn);
                console.log('');

                console.log('── Check 4: Command Consistency ──');
                await checkConsistency(conn);
                console.log('');

                console.log('── Check 5: Docker Detection ──');
                await checkDocker(conn);
                console.log('');

                console.log('── Check 6: Process Tree ──');
                await checkProcessTree(conn);
                console.log('');
            } catch (err) {
                log('FAIL', `SSH test suite error: ${err.message}`);
            }
            conn.end();
            resolve();
        });

        conn.on('error', (err) => {
            log('FAIL', `SSH connection failed: ${err.message}`);
            resolve();
        });

        conn.connect({
            host: HOST,
            port: SSH_PORT,
            username: 'root',
            password: 'toor',
            readyTimeout: 10000,
            algorithms: {
                kex: ['diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1', 'ecdh-sha2-nistp256'],
            }
        });
    });

    // Check 7: HTTP
    console.log('── Check 7: HTTP Fingerprinting ──');
    await checkHTTP();
    console.log('');

    // Summary
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Results: \x1b[32m${passed} PASS\x1b[0m  \x1b[33m${warned} WARN\x1b[0m  \x1b[31m${failed} FAIL\x1b[0m`);
    console.log('═══════════════════════════════════════════════════════');
    
    process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
    console.error('Self-test crashed:', err);
    process.exit(2);
});
