/**
 * HoneyAI — HTTP Proxy Honeypot
 * Emulates a Squid web proxy, traps hijack attempts, and alerts.
 */

'use strict';

const http = require('http');
const config = require('../core/config');
const loggerModule = require('../core/logger');
const reporter = require('../core/reporter');
const backfire = require('../core/backfire');

let server = null;

function start(customPort) {
    const cfg = config.protocols.httpproxy;
    if (!cfg?.enabled && !customPort) return;

    const port = customPort || cfg.port || 8080;

    server = http.createServer((req, res) => {
        const ip = req.socket.remoteAddress.replace(/^::ffff:/, '');
        const targetUrl = req.url;

        loggerModule.logger.warn(`Proxy hijack attempt (HTTP GET) from ${ip} targeting ${targetUrl}`, { protocol: 'httpproxy', ip });

        if (global.activeConnections && global.activeConnections.httpproxy !== undefined) {
            global.activeConnections.httpproxy++;
            setTimeout(() => {
                if (global.activeConnections && global.activeConnections.httpproxy !== undefined) {
                    global.activeConnections.httpproxy--;
                }
            }, 1000);
        }

        loggerModule.logEvent({
            protocol: 'httpproxy',
            ip,
            port,
            method: req.method,
            target: targetUrl,
            attack_type: 'http_proxy_hijack'
        });

        reporter.report(ip, {
            protocol: 'httpproxy',
            port,
            comment: `HTTP Proxy hijack attempt: ${req.method} ${targetUrl.substring(0, 100)}`
        }).catch(() => {});

        backfire.scanAttackerBack(ip);

        // Serve a fake Squid error page
        res.writeHead(403, { 
            'Content-Type': 'text/html; charset=utf-8',
            'Server': 'squid/4.15',
            'X-Cache': 'MISS from squid-proxy'
        });
        res.end(getSquidErrorPage(targetUrl));
    });

    server.on('connect', (req, socket, head) => {
        const ip = socket.remoteAddress.replace(/^::ffff:/, '');
        const targetHost = req.url;

        loggerModule.logger.warn(`Proxy hijack attempt (HTTP CONNECT) from ${ip} targeting ${targetHost}`, { protocol: 'httpproxy', ip });

        if (global.activeConnections && global.activeConnections.httpproxy !== undefined) {
            global.activeConnections.httpproxy++;
            setTimeout(() => {
                if (global.activeConnections && global.activeConnections.httpproxy !== undefined) {
                    global.activeConnections.httpproxy--;
                }
            }, 1000);
        }

        loggerModule.logEvent({
            protocol: 'httpproxy',
            ip,
            port,
            method: 'CONNECT',
            target: targetHost,
            attack_type: 'http_proxy_connect'
        });

        reporter.report(ip, {
            protocol: 'httpproxy',
            port,
            comment: `HTTP Proxy CONNECT tunnel attempt targeting: ${targetHost.substring(0, 100)}`
        }).catch(() => {});

        backfire.scanAttackerBack(ip);

        // Terminate connection with a Squid-like HTTP response
        socket.write(
            'HTTP/1.1 403 Forbidden\r\n' +
            'Server: squid/4.15\r\n' +
            'Content-Type: text/html; charset=utf-8\r\n' +
            'Connection: close\r\n\r\n' +
            getSquidErrorPage(targetHost)
        );
        socket.end();
    });

    server.listen(port, '0.0.0.0', () => {
        loggerModule.logger.info(`HTTP Proxy honeypot listening on :${port}`, { protocol: 'httpproxy' });
    });
}

function stop() {
    if (server) {
        try { server.close(); } catch (_) {}
        server = null;
    }
}

function getSquidErrorPage(target) {
    const safeTarget = (target || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>ERROR: The requested URL could not be retrieved</title>
<style type="text/css"><!-- 
body { font-family: verdana, sans-serif; background-color: #efefef; color: #101010; }
#content { margin: 40px; background-color: #ffffff; padding: 20px; border: 1px solid #c0c0c0; }
--></style>
</head><body>
<div id="content">
<h2>ERROR</h2>
<h3>The requested URL could not be retrieved</h3>
<hr>
<p>The following error was encountered while trying to retrieve the URL: <a href="${safeTarget}">${safeTarget}</a></p>
<blockquote id="error">
<p><b>Access Denied.</b></p>
</blockquote>
<p>Access control configuration prevents your request from being allowed at this time. Please contact your service provider if you feel this is incorrect.</p>
<hr>
<p>Generated Fri, 12 Jun 2026 12:00:00 GMT by squid/4.15 (Squid)</p>
</div>
</body></html>`;
}

module.exports = { start, stop, getSquidErrorPage };
