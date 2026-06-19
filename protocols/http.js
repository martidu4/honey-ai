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
const { sleep } = require('../core/jitter');
const backfire = require('../core/backfire');
const traps = require('../core/traps');
const { normalizeIP } = require('../core/utils');
// ── Static HTTP Cache (from Galah) — serve known paths without Ollama ────
const HTTP_CACHE_FILE = nodePath.join(__dirname, "../data/http-cache.json");
let _httpStaticCache = null;
function getHttpCache() {
    if (_httpStaticCache) return _httpStaticCache;
    try {
        _httpStaticCache = JSON.parse(fs.readFileSync(HTTP_CACHE_FILE, "utf8"));
        logger.info("Loaded " + Object.keys(_httpStaticCache).length + " static HTTP cache entries");
    } catch (e) { _httpStaticCache = {}; }
    return _httpStaticCache;
}


// ─── Per-IP rate limiter ───────────────────────────────────────────────────────
const REQUEST_COUNTS = new Map(); // ip → { count, firstSeen }
const MAX_REQ_PER_MINUTE = 30;

setInterval(() => REQUEST_COUNTS.clear(), 60_000).unref();

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

        const limitStatus = getRateLimitStatus(normalizeIP(ip));
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
        const limitStatus = getRateLimitStatus(normalizeIP(ip));
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

            let contentType = 'text/plain; charset=utf-8';
            const decoyContent = ai.getFallback('http', { path: normPath });

            res.setHeader('Content-Type', contentType);
            const bodyBytes = Buffer.byteLength(decoyContent, 'utf8');
            // Update response_bytes in last logged event (which is config_leak)
            // Wait, we can just send the response
            return res.status(200).send(decoyContent);
        }

        // ── Infinite Maze Trap ──────────────────────────────────────────────
        if (normPath.startsWith('/archive/') || normPath === '/archive') {

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

        // ── Check static cache first (0% CPU) ──────────────────────────────
        const staticCache = getHttpCache();
        const cachedResponse = staticCache[path] || staticCache[normPath];
        if (cachedResponse) {
            logger.info("HTTP cache hit: " + path, { protocol: "http", ip });
            logEvent({ protocol: "http", ip, method, path, user_agent: ua, attack_type: attackType, response_bytes: cachedResponse.length, cache_hit: true });
            reporter.report(ip, { protocol: "http", port: cfg.port, comment: "HTTP " + method + " " + path + " (" + attackType + ", cached). UA: " + ua.substring(0, 100), categories: "21,14" }).catch(function(){});
            res.setHeader("Content-Type", "text/html; charset=UTF-8");
            return res.status(200).send(cachedResponse);
        }

        // ── WordPress catch-all — skip Ollama for any wp-* path ─────────
        if (normPath.startsWith('/wp-') || normPath.startsWith('/wp/') || normPath.includes('/wp-content/') || normPath.includes('/wp-includes/') || normPath.includes('/wp-json/')) {
            logger.info("WP static fallback: " + path, { protocol: "http", ip });
            logEvent({ protocol: "http", ip, method, path, user_agent: ua, attack_type: attackType, response_bytes: 0, cache_hit: true });
            reporter.report(ip, { protocol: "http", port: cfg.port, comment: "HTTP " + method + " " + path + " (wordpress, static). UA: " + ua.substring(0, 100), categories: "21,14" }).catch(function(){});
            res.setHeader("Content-Type", "text/html; charset=UTF-8");
            res.setHeader("Server", "Apache/2.4.57 (Debian)");
            res.setHeader("X-Powered-By", "PHP/8.1.27");
            return res.status(404).send('<!DOCTYPE html>\n<html><head><title>Page not found &#8211; Site</title></head><body><div class="wp-die-message"><h1>Not Found</h1><p>The requested URL was not found on this server.</p></div></body></html>');
        }

        // ── Scanner catch-all — static responses for common probe paths (0% CPU) ──
        // These paths were bypassing WordPress filter and hitting Ollama on every request
        const SCANNER_PHPINFO_PATHS = ['phpinfo', 'phpinfo.php', '_phpinfo.php', 'info.php', 'test.php', 'php_info.php', 'pi.php', 'i.php', 'php.php'];
        const SCANNER_PATTERNS = {
            // Yii2 debug panel
            debug_panel: (p) => p.includes('/debug/default/view') || p.includes('/debug/default/index'),
            // Symfony profiler
            symfony: (p) => p.includes('/_profiler') || p.includes('/app_dev.php'),
            // phpinfo — check any segment of the path
            phpinfo: (p) => {
                const segments = p.split('/').filter(Boolean);
                return segments.some(s => SCANNER_PHPINFO_PATHS.includes(s)) || p.includes('phpinfo');
            },
            // OwnCloud / Nextcloud
            cloud_storage: (p) => p.includes('/owncloud/') || p.includes('/nextcloud/') || p.includes('/remote.php/') || p.includes('/ocm-provider/'),
            // Common CMS
            cms: (p) => p.includes('/joomla/') || p.includes('/drupal/') || p.includes('/magento/') || p.includes('/moodle/') || p.includes('/typo3/'),
            // Java / Spring
            java_spring: (p) => p.includes('/actuator') || p.includes('/jolokia') || p.includes('/heapdump') || p.includes('/env') && p.includes('/actuator'),
            // Laravel / PHP frameworks
            php_framework: (p) => p.includes('/telescope/') || p.includes('/horizon/') || p.includes('/vendor/') || p.includes('/laravel/') || p.includes('/artisan'),
            // Server status / info
            server_info: (p) => p === '/server-status' || p === '/server-info' || p === '/.htaccess' || p === '/.htpasswd',
            // CGI / legacy
            cgi: (p) => p.startsWith('/cgi-bin/') || p.startsWith('/cgi/') || p.includes('.cgi'),
            // API probes / config
            api_probe: (p) => p.includes('/api/v1/') || p.includes('/api/v2/') || p.includes('/graphql') || p === '/swagger.json' || p === '/openapi.json' || p.includes('/swagger-ui'),
            // ASP.NET / Windows
            aspnet: (p) => p.includes('/elmah.axd') || p.includes('/trace.axd') || p.includes('/web.config') || p.includes('.aspx') || p.includes('.asmx'),
            // Node.js / Express
            nodejs: (p) => p === '/package.json' || p === '/package-lock.json' || p === '/node_modules/' || p === '/.npmrc',
            // Docker / DevOps
            devops: (p) => p.includes('/docker-compose') || p === '/Dockerfile' || p === '/.dockerenv' || p.includes('/kubernetes/') || p.includes('/helm/'),
            // Database
            database: (p) => p.includes('/adminer') || p.includes('/db.php') || p.includes('/sql.php') || p.includes('/dbadmin'),
            // WebDAV
            webdav: (p) => p.includes('/webdav/') || p.includes('/_vti_bin/') || p.includes('/_vti_inf.html'),
            // Tomcat
            tomcat: (p) => p.includes('/manager/html') || p.includes('/host-manager/') || p === '/status' || p.includes('.jsp') || p.includes('.do'),
            // Common files scanners look for
            misc_files: (p) => p === '/robots.txt.bak' || p === '/sitemap.xml' || p === '/crossdomain.xml' || p === '/clientaccesspolicy.xml' || p === '/.DS_Store' || p === '/Thumbs.db' || p === '/.well-known/security.txt',
            // SDK / API config leaks
            sdk_leaks: (p) => p.includes('/SDK/') || p.includes('/sdk/') || p.includes('/webLanguage'),
        };

        const matchedScanner = Object.entries(SCANNER_PATTERNS).find(([, testFn]) => testFn(normPath));
        if (matchedScanner) {
            const scannerType = matchedScanner[0];
            logger.info(`Scanner static (${scannerType}): ${sanitizeForLog(path)}`, { protocol: 'http', ip });
            logEvent({ protocol: 'http', ip, method, path, user_agent: ua, attack_type: attackType, response_bytes: 0, cache_hit: true });
            reporter.report(ip, { protocol: 'http', port: cfg.port, comment: `HTTP ${method} ${path} (${scannerType}, static). UA: ${ua.substring(0, 100)}`, categories: '21,14' }).catch(() => {});

            res.setHeader('Server', 'Apache/2.4.57 (Debian)');
            res.setHeader('X-Powered-By', 'PHP/8.1.27');

            // Return realistic response based on scanner type
            if (scannerType === 'phpinfo') {
                res.setHeader('Content-Type', 'text/html; charset=UTF-8');
                return res.status(200).send('<!DOCTYPE html><html><head><title>phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head><body><div class="center"><table><tr class="h"><td><a href="http://www.php.net/"><img border="0" src="/phpinfo.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42" alt="PHP Logo" /></a><h1 class="p">PHP Version 8.1.27</h1></td></tr></table><table><tr><td class="e">System</td><td class="v">Linux debian 6.1.0-18-amd64 #1 SMP x86_64</td></tr><tr><td class="e">Build Date</td><td class="v">Dec 19 2023 17:14:12</td></tr><tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr><tr><td class="e">Document Root</td><td class="v">/var/www/html</td></tr><tr><td class="e">DOCUMENT_ROOT</td><td class="v">/var/www/html</td></tr><tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.57 (Debian)</td></tr><tr><td class="e">REMOTE_ADDR</td><td class="v">' + ip + '</td></tr></table></div></body></html>');
            }
            if (scannerType === 'debug_panel' || scannerType === 'symfony' || scannerType === 'server_info') {
                res.setHeader('Content-Type', 'text/html; charset=UTF-8');
                return res.status(403).send('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don\'t have permission to access this resource.</p><hr><address>Apache/2.4.57 (Debian) Server at ' + req.headers.host + ' Port 80</address></body></html>');
            }
            // Default: 404 Not Found (Apache style)
            res.setHeader('Content-Type', 'text/html; charset=iso-8859-1');
            return res.status(404).send('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>Apache/2.4.57 (Debian) Server at ' + req.headers.host + ' Port 80</address></body></html>');
        }

        // ── Generate AI response (fallback for unknown paths) ───────────
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
