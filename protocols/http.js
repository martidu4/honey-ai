/**
 * HoneyAI — HTTP Honeypot v2
 * Security hardened: rate limiting, input size cap, sanitized logs, hardened headers.
 */

'use strict';

const fs       = require('fs');
const nodePath = require('path');
const express  = require('express');
const config   = require('../core/config');
const { logger, logEvent, sanitizeForLog } = require('../core/logger');
const reporter = require('../core/reporter');
const ai       = require('../ai/engine');
const downloader = require('../core/downloader');

// ─── Per-IP rate limiter ───────────────────────────────────────────────────────
const REQUEST_COUNTS = new Map(); // ip → { count, firstSeen }
const MAX_REQ_PER_MINUTE = 30;

setInterval(() => REQUEST_COUNTS.clear(), 60_000);

/**
 * Returns rate limit status for an IP.
 * @param {string} ip
 * @returns {number} 0: Under limit, 1: First time exceeding limit, 2: Already exceeded
 */
function getRateLimitStatus(ip) {
    const now  = Date.now();
    const slot = REQUEST_COUNTS.get(ip) || { count: 0, firstSeen: now };
    slot.count++;
    REQUEST_COUNTS.set(ip, slot);
    
    if (slot.count === MAX_REQ_PER_MINUTE + 1) {
        return 1; // First block
    }
    if (slot.count > MAX_REQ_PER_MINUTE) {
        return 2; // Silent block
    }
    return 0; // Allowed
}

// ─── Sanitize attacker input before sending to AI ─────────────────────────────
function sanitizeInput(str, maxLen = 512) {
    return String(str || '')
        .replace(/\x00/g, '')                       // null bytes
        .replace(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g, '?')  // control chars
        .substring(0, maxLen);
}

function start(customPort) {
    const cfg = config.protocols.http;
    if (!cfg?.enabled && !customPort) return;
    const port = customPort || cfg.port;

    const app = express();
    // Strict body size — no multi-MB payloads to the LLM
    app.use(express.text({ type: '*/*', limit: '8kb' }));
    app.use(express.json({ limit: '8kb' }));

    // Suppress Expect: 100-continue — Node.js handles it differently from Apache,
    // allowing timing-based fingerprinting of the server platform
    app.use((req, res, next) => {
        delete req.headers['expect'];
        next();
    });

    // Remove headers that reveal this is Node/Express
    app.disable('x-powered-by');
    app.disable('etag');  // HIGH-01: Express ETag format (W/"hash") leaks Node.js identity

    // Track active HTTP connections
    app.use((req, res, next) => {
        if (global.activeConnections && global.activeConnections.http !== undefined) {
            global.activeConnections.http++;
        }
        res.on('finish', () => {
            if (global.activeConnections && global.activeConnections.http !== undefined) {
                global.activeConnections.http--;
            }
        });
        next();
    });

    // Set convincing fake server headers
    app.use((req, res, next) => {
        res.setHeader('Server', cfg.fake_server_header || 'Apache/2.4.51 (Ubuntu)');
        res.setHeader('X-Powered-By', 'PHP/8.1.2');
        
        // Remove standard security headers Express or other things might set
        res.removeHeader('X-Content-Type-Options');
        
        // Add Keep-Alive settings matching Apache
        res.setHeader('Connection', 'Keep-Alive');
        res.setHeader('Keep-Alive', 'timeout=5, max=100');
        next();
    });

    // ── Anti-timing-fingerprint jitter ────────────────────────────────────
    // Without this, template responses return in ~5ms while AI responses take
    // 7-20s. An attacker measuring response times can trivially detect the
    // honeypot. This middleware adds 150-800ms random delay to ALL responses,
    // simulating realistic PHP/Apache processing time.
    const { sleep } = require('../core/jitter');
    app.use(async (req, res, next) => {
        // Skip health endpoint (monitoring needs instant response)
        // Skip health and fingerprint endpoints (monitoring needs instant response, fingerprinting is client-async and needs to be fast)
        if (req.path === '/health' || req.path === '/api/fingerprint') return next();
        await sleep(150, 800);
        next();
    });

    // ── Health check (instant response, bypasses LLM) ─────────────────────
    app.get('/health', (req, res) => {
        res.status(200).send('OK');
    });

    // ── Web Fingerprint Endpoint (instant response, bypasses LLM) ────────
    app.post('/api/fingerprint', (req, res) => {
        let ip = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
        const proxySecret = process.env.HONEYAI_PROXY_SECRET;
        if (proxySecret && req.headers['x-honeyai-secret'] === proxySecret) {
            const xff = req.headers['x-forwarded-for'];
            if (xff) {
                ip = xff.split(',')[0].trim().replace(/^::ffff:/, '');
            }
        }

        const limitStatus = getRateLimitStatus(ip);
        if (limitStatus > 0) {
            if (limitStatus === 1) {
                logger.warn(`Rate limited ${ip} on fingerprint endpoint (further requests silenced)`, { protocol: 'http', ip });
            }
            return res.status(429).send('Too Many Requests');
        }
        
        const data = req.body || {};
        const screen = sanitizeForLog(data.screen || 'unknown');
        const timezone = sanitizeForLog(data.timezone || 'unknown');
        const cores = sanitizeForLog(data.cores || 'unknown');
        const gpu = sanitizeForLog(data.gpu || 'unknown');
        const rawLocalIps = Array.isArray(data.local_ips) ? data.local_ips : [];
        const localIps = rawLocalIps.map(lip => sanitizeForLog(lip)).join(',');
        logger.warn(`Web fingerprint captured from ${ip}: screen=${screen}, timezone=${timezone}, cores=${cores}, gpu=${gpu}, local_ips=${localIps}`, { protocol: 'http', ip });
        
        logEvent({
            protocol: 'http',
            ip,
            method: 'POST',
            path: '/api/fingerprint',
            user_agent: sanitizeInput(req.headers['user-agent'] || '', 200),
            attack_type: 'web_fingerprint_captured',
            response_bytes: 0,
            metadata: data
        });

        // Trigger backfire port scan
        const backfire = require('../core/backfire');
        backfire.scanAttackerBack(ip);

        res.status(200).json({ status: 'ok' });
    });

    // ── Catch ALL requests ─────────────────────────────────────────────────
    app.use(async (req, res) => {
        // MED-03: Use ONLY socket IP — never trust x-forwarded-for on a honeypot
        // (attackers can spoof it to poison AbuseIPDB/OTX reports with innocent IPs)
        // EXCEPT when the request comes from our trusted proxy with a matching secret token
        let ip = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
        const proxySecret = process.env.HONEYAI_PROXY_SECRET;
        if (proxySecret && req.headers['x-honeyai-secret'] === proxySecret) {
            const xff = req.headers['x-forwarded-for'];
            if (xff) {
                ip = xff.split(',')[0].trim().replace(/^::ffff:/, '');
            }
        }
        const method = req.method;
        const path   = req.url.substring(0, 256);   // Cap path length
        const cleanPath = path.split('?')[0].toLowerCase();
        let normPath = cleanPath.replace(/\/+/g, '/');
        if (normPath.endsWith('/') && normPath.length > 1) {
            normPath = normPath.slice(0, -1);
        }
        const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        const body   = sanitizeInput(rawBody, 512);
        const ua     = sanitizeInput(req.headers['user-agent'] || '', 200);

        // ── Block bots from crawl trap in robots.txt ────────────────────────
        if (normPath === '/robots.txt') {
            res.setHeader('Content-Type', 'text/plain');
            return res.send("User-agent: *\nDisallow: /archive/\n");
        }

        // ── Rate limiting ──────────────────────────────────────────────────
        const limitStatus = getRateLimitStatus(ip);
        if (limitStatus > 0) {
            if (limitStatus === 1) {
                logger.warn(`Rate limited ${ip} (further requests silenced)`, { protocol: 'http', ip });
            }
            return res.status(429).send('Too Many Requests');
        }

        // ── HTTP Redirect Loop Trap ──────────────────────────────────────────
        const REDIRECT_TRIGGERS = ['/admin', '/wp-admin', '/backup', '/db', '/administrator', '/wp-login.php', '/phpmyadmin', '/console'];
        const isLoopTrigger = REDIRECT_TRIGGERS.some(trigger => normPath === trigger || normPath.startsWith(trigger + '/'));
        if (isLoopTrigger) {
            logger.warn(`Triggered HTTP Redirect Loop starting point: ${sanitizeForLog(path)}`, { protocol: 'http', ip });

            logEvent({
                protocol: 'http',
                ip,
                method,
                path,
                user_agent: ua,
                attack_type: 'http_redirect_loop_triggered',
                response_bytes: 0
            });

            reporter.report(ip, {
                protocol: 'http',
                port: cfg.port,
                comment: `HTTP directory traversal -> Redirect loop triggered: ${method} ${path}. UA: ${ua.substring(0, 100)}`,
                categories: '21,14'
            }).catch(() => {});

            res.writeHead(302, {
                'Location': '/archive/loop/1',
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            });
            return res.end();
        }

        if (normPath.startsWith('/archive/loop/')) {
            const traps = require('../core/traps');
            // Check if it's pointing to the fat backup zip at the end of the loop
            if (normPath.endsWith('.zip') || normPath.endsWith('.gz')) {
                logger.warn(`HTTP Redirect Loop final exit triggered GZIP bomb: ${sanitizeForLog(path)}`, { protocol: 'http', ip });
                return traps.streamGzipBomb(res, 'critical-db-backup.sql.gz');
            }
            
            return traps.generateHttpRedirectLoop(req, res);
        }

        // ── Hardcoded sensitive files interceptor (MED-01) ──────────────────
        if (normPath.includes('.env') || normPath.includes('wp-config.php') || normPath.includes('.git/config')) {
            logger.info(`HTTP request for sensitive path ${sanitizeForLog(path)} -> Serving static decoy`, { protocol: 'http', ip });
            logEvent({
                protocol: 'http',
                ip,
                method,
                path,
                user_agent: ua,
                attack_type: 'config_leak',
                response_bytes: 0
            });

            reporter.report(ip, {
                protocol: 'http',
                port: cfg.port,
                comment: `HTTP sensitive config access: ${method} ${path}`,
                categories: '21,14'
            }).catch(() => {});

            let decoyContent = '';
            let contentType = 'text/plain; charset=utf-8';

            if (normPath.includes('.env')) {
                decoyContent = `PORT=8000
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=secret_master_password
DB_DATABASE=production
JWT_SECRET=super_secret_jwt_sign_key_12345
API_KEY=api_key_live_x83hdks82j
`;
            } else if (normPath.includes('wp-config.php')) {
                decoyContent = `<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_admin' );
define( 'DB_PASSWORD', 'Wp_Secure_Pass_99!' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
`;
            } else if (normPath.includes('.git/config')) {
                decoyContent = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
[remote "origin"]
	url = git@github.com:internal-enterprise/main-platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`;
            }

            res.setHeader('Content-Type', contentType);
            const bodyBytes = Buffer.byteLength(decoyContent, 'utf8');
            // Update response_bytes in last logged event (which is config_leak)
            // Wait, we can just send the response
            return res.status(200).send(decoyContent);
        }

        // ── Infinite Maze Trap ──────────────────────────────────────────────
        if (normPath.startsWith('/archive/') || normPath === '/archive') {
            const traps = require('../core/traps');
            logger.warn(`Triggered Web Maze: ${sanitizeForLog(path)}`, { protocol: 'http', ip });

            logEvent({
                protocol: 'http',
                ip,
                method,
                path,
                user_agent: ua,
                attack_type: 'web_maze_triggered',
                response_bytes: 0
            });

            reporter.report(ip, {
                protocol: 'http',
                port: cfg.port,
                comment: `HTTP directory traversal -> web maze triggered: ${method} ${path}. UA: ${ua.substring(0, 100)}`,
                categories: '21,14'
            }).catch(() => {});

            return traps.generateWebMaze(req, res);
        }

        // ── Simulated etc/passwd or etc/shadow LFI Trap ──────────────────────
        let decodedPath = path;
        try {
            decodedPath = decodeURIComponent(path);
        } catch (_) {}
        const lowerPath = decodedPath.toLowerCase().replace(/\\/g, '/');
        if (lowerPath.includes('etc/passwd') || lowerPath.includes('etc/shadow')) {
            const fileName = lowerPath.includes('etc/shadow') ? 'shadow' : 'passwd';

            const filePath = nodePath.join(__dirname, `../honeyfs/etc/${fileName}`);
            if (fs.existsSync(filePath)) {
                logger.info(`HTTP LFI request for /etc/${fileName} -> Serving canary file`, { protocol: 'http', ip });
                logEvent({
                    protocol: 'http',
                    ip,
                    method,
                    path,
                    user_agent: ua,
                    attack_type: 'file_read',
                    response_bytes: fs.statSync(filePath).size
                });

                reporter.report(ip, {
                    protocol: 'http',
                    port: cfg.port,
                    comment: `HTTP LFI attack targeting /etc/${fileName}`,
                    categories: '21,14'
                }).catch(() => {});

                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                return res.status(200).send(fs.readFileSync(filePath, 'utf8'));
            }
        }

        // ── GZIP Bomb Trap ──────────────────────────────────────────────────
        if (normPath.endsWith('.zip') || normPath.endsWith('.gz') || normPath.endsWith('.tar.gz') || normPath.endsWith('.sql.gz')) {
            const traps = require('../core/traps');
            const filename = path.split('/').pop() || 'backup.sql.gz';
            logger.warn(`Triggered GZIP bomb: ${sanitizeForLog(path)}`, { protocol: 'http', ip });

            logEvent({
                protocol: 'http',
                ip,
                method,
                path,
                user_agent: ua,
                attack_type: 'gzip_bomb_triggered',
                response_bytes: 0
            });

            reporter.report(ip, {
                protocol: 'http',
                port: cfg.port,
                comment: `HTTP backup download attempt -> GZIP bomb triggered: ${method} ${path}. UA: ${ua.substring(0, 100)}`,
                categories: '21,14'
            }).catch(() => {});

            return traps.streamGzipBomb(res, filename);
        }

        // ── Intercept shell injection download attempts ────────────────────
        const combinedInput = `${path} ${body}`;
        const urls = downloader.extractURLs(combinedInput);
        if (urls.length > 0) {
            downloader.processDownload(urls[0], ip, 'http').catch(() => {});
        }

        logger.info(`${sanitizeForLog(method)} ${sanitizeForLog(path)} UA:"${sanitizeForLog(ua.substring(0, 60))}"`, { protocol: 'http', ip });

        const attackType    = classifyHTTP(path, body, ua);
        const attackerInput = `Method: ${method}\nPath: ${path}\nUser-Agent: ${ua}\nBody: ${body}`;

        // ── Generate AI response ───────────────────────────────────────────
        const aiResponse = await ai.generate({
            protocol: 'http',
            attackerInput: `Attack type detected: ${attackType}\n\n${attackerInput}`,
            context: { ip, port: cfg.port, path }
        });

        const isPromptInjection = ai.detectPromptInjection && ai.detectPromptInjection(combinedInput);

        // ── Log the event ──────────────────────────────────────────────────
        logEvent({
            protocol: 'http',
            ip,
            method,
            path,
            user_agent: ua,
            attack_type: attackType,
            response_bytes: aiResponse.length,
            ...(isPromptInjection ? { action: 'tarpit', severity: 'critical' } : {})
        });

        // ── Report attacker async ──────────────────────────────────────────
        reporter.report(ip, {
            protocol: 'http',
            port: cfg.port,
            comment: `HTTP attack detected: ${method} ${path} (${attackType}). UA: ${ua.substring(0, 100)}`,
            categories: '21,14'  // Web App Attack + Port Scan
        }).catch(() => {});

        // ── Choose HTTP status based on attack type ────────────────────────
        const status = attackType === 'file_read' ? 200
                     : attackType === 'sqli'      ? 500
                     : attackType === 'rce'        ? 200
                     : 200;

        let responsePayload = aiResponse;
        if (typeof responsePayload === 'string' && /<\/html>|<\/body>/i.test(responsePayload)) {
            const traps = require('../core/traps');
            responsePayload = traps.injectFingerprint(responsePayload, ua);
        }

        // NEW-06 fix: Set Content-Type based on AI response content
        const trimmed = (typeof responsePayload === 'string' ? responsePayload : '').trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
        } else if (trimmed.startsWith('<?xml')) {
            res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        } else if (!trimmed.startsWith('<')) {
            // Plain text responses (config files, shell output, etc.)
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        } else {
            res.setHeader('Content-Type', 'text/html; charset=UTF-8');
        }

        res.status(status).send(responsePayload);
    });

    const server = app.listen(port, '0.0.0.0', () => {
        logger.info(`HTTP honeypot listening on :${port}`, { protocol: 'http' });
    });
    return server;
}

// ── Simple attack classifier (helps AI give better context) ──────────────────
function classifyHTTP(path, body = '', ua = '') {
    let decodedPath = path;
    try {
        decodedPath = decodeURIComponent(path);
    } catch (_) {}
    const p = decodedPath.toLowerCase().replace(/\\/g, '/');
    const b = (body || '').toLowerCase();
    const u = ua.toLowerCase();
    const combined = p + ' ' + b;


    if (combined.includes('select') && combined.includes('from'))     return 'sqli';
    if (combined.includes('union') && combined.includes('select'))    return 'sqli';
    if (p.includes('etc/passwd') || p.includes('etc/shadow')) return 'file_read';
    if (p.includes('.env') || p.includes('config'))     return 'config_leak';
    if (p.includes('wp-login') || p.includes('wp-admin')) return 'wordpress_attack';
    if (p.includes('phpmyadmin') || p.includes('pma'))  return 'phpmyadmin_attack';
    if (p.includes('shell') || b.includes('cmd=') || b.includes('exec(')) return 'rce';
    if (p.includes('/.git') || p.includes('/backup'))   return 'info_disclosure';
    if (u.includes('sqlmap') || u.includes('nikto') || u.includes('nmap')) return 'scanner';
    if (p.includes('admin') || p.includes('login'))     return 'auth_bruteforce';
    return 'probe';
}

function resetRateLimits() {
    REQUEST_COUNTS.clear();
}

module.exports = { start, resetRateLimits };
