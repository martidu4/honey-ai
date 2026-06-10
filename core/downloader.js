/**
 * OpenClaw HoneyAI — Malware Downloader & Analyzer
 * Safe, SSRF-resistant download agent with VirusTotal integration
 */

'use strict';

const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const axios    = require('axios');
const dns      = require('dns');
const net      = require('net');
const http     = require('http');
const https    = require('https');
const config   = require('./config');
const { logger, logEvent } = require('./logger');

const DOWNLOADS_DIR = path.join(__dirname, '../logs/downloads');
if (!fs.existsSync(DOWNLOADS_DIR)) {
    fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
}

// SSRF prevention: reject private/local IP ranges and internal hostnames
const PRIVATE_IP_REG = /^(localhost|127\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|169\.254\.\d+\.\d+|fc00::|fe80::|::1|::|0:0:0:0:0:0:0:0|0\.0\.0\.0)$/i;

function parseIPv6(ip) {
    if (typeof ip !== 'string') return null;
    let clean = ip.toLowerCase().trim();
    if (clean.startsWith('[') && clean.endsWith(']')) {
        clean = clean.slice(1, -1);
    }
    
    let ipv4Part = null;
    const lastColon = clean.lastIndexOf(':');
    if (lastColon !== -1) {
        const potentialIpv4 = clean.substring(lastColon + 1);
        if (potentialIpv4.includes('.')) {
            const octets = potentialIpv4.split('.');
            if (octets.length === 4 && octets.every(o => {
                const n = Number(o);
                return !isNaN(n) && n >= 0 && n <= 255 && o.trim() !== '';
            })) {
                ipv4Part = potentialIpv4;
                if (lastColon > 0 && clean[lastColon - 1] === ':') {
                    clean = clean.substring(0, lastColon + 1);
                } else {
                    clean = clean.substring(0, lastColon);
                }
            } else {
                return null;
            }
        }
    }

    const expectedBlocks = ipv4Part ? 6 : 8;

    const doubleColons = clean.split('::');
    if (doubleColons.length > 2) return null;

    let blocks = [];
    if (doubleColons.length === 2) {
        const leftParts = doubleColons[0].split(':').filter(p => p !== '');
        const rightParts = doubleColons[1].split(':').filter(p => p !== '');
        const missingCount = expectedBlocks - (leftParts.length + rightParts.length);
        
        blocks = blocks.concat(leftParts.map(p => parseInt(p, 16)));
        for (let i = 0; i < missingCount; i++) {
            blocks.push(0);
        }
        blocks = blocks.concat(rightParts.map(p => parseInt(p, 16)));
    } else {
        const parts = clean.split(':');
        if (parts.length !== expectedBlocks) return null;
        blocks = parts.map(p => parseInt(p, 16));
    }

    if (blocks.some(isNaN)) return null;

    if (ipv4Part) {
        const ip4parts = ipv4Part.split('.').map(Number);
        blocks.push((ip4parts[0] << 8) + ip4parts[1]);
        blocks.push((ip4parts[2] << 8) + ip4parts[3]);
    }

    return blocks;
}

function convertIPv4Mapped(ip) {
    if (typeof ip !== 'string') return ip;
    const blocks = parseIPv6(ip);
    if (blocks) {
        const isMapped = (
            blocks[0] === 0 &&
            blocks[1] === 0 &&
            blocks[2] === 0 &&
            blocks[3] === 0 &&
            (
                (blocks[4] === 0 && blocks[5] === 0) || // compatible ::x.y.z.w
                (blocks[4] === 0 && blocks[5] === 0xffff) || // mapped ::ffff:x.y.z.w
                (blocks[4] === 0xffff && blocks[5] === 0) // translated ::ffff:0:x.y.z.w
            )
        );
        if (isMapped) {
            return `${blocks[6] >> 8}.${blocks[6] & 0xff}.${blocks[7] >> 8}.${blocks[7] & 0xff}`;
        }
    }
    return ip;
}

function isPrivateIP(ipAddress) {
    if (!ipAddress) return true;
    ipAddress = convertIPv4Mapped(ipAddress);

    if (!net.isIP(ipAddress)) return true; // block invalid IPs

    if (net.isIPv4(ipAddress)) {
        const parts = ipAddress.split('.').map(Number);
        const first = parts[0];
        const second = parts[1];

        // 127.0.0.0/8 (loopback)
        if (first === 127) return true;
        // 10.0.0.0/8 (private)
        if (first === 10) return true;
        // 192.168.0.0/16 (private)
        if (first === 192 && second === 168) return true;
        // 172.16.0.0/12 (private)
        if (first === 172 && (second >= 16 && second <= 31)) return true;
        // 169.254.0.0/16 (link-local)
        if (first === 169 && second === 254) return true;
        // 0.0.0.0/8 (local network)
        if (first === 0) return true;
        // 100.64.0.0/10 (carrier-grade NAT)
        if (first === 100 && second >= 64 && second <= 127) return true;
        // 198.18.0.0/15 (benchmark testing)
        if (first === 198 && second >= 18 && second <= 19) return true;
        // 192.0.2.0/24 (TEST-NET-1)
        if (first === 192 && second === 0 && parts[2] === 2) return true;
        // 198.51.100.0/24 (TEST-NET-2)
        if (first === 198 && second === 51 && parts[2] === 100) return true;
        // 203.0.113.0/24 (TEST-NET-3)
        if (first === 203 && second === 0 && parts[2] === 113) return true;
        // >= 224.0.0.0 (Class D/E multicast & reserved)
        if (first >= 224) return true;

        return false;
    }

    if (net.isIPv6(ipAddress)) {
        const blocks = parseIPv6(ipAddress);
        if (!blocks) return true; // block invalid formats

        // ::1 or ::
        const isLoopback = blocks.every(b => b === 0) || (blocks.slice(0, 7).every(b => b === 0) && blocks[7] === 1);
        if (isLoopback) return true;

        // fe80::/10 (link-local)
        if ((blocks[0] & 0xffc0) === 0xfe80) return true;

        // fc00::/7 (unique local address)
        if ((blocks[0] & 0xfe00) === 0xfc00) return true;

        return false;
    }

    return true;
}

function ssrfSafeLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }

    dns.lookup(hostname, options, (err, address, family) => {
        if (err) return callback(err);

        if (isPrivateIP(address)) {
            return callback(new Error('DNS lookup resolved to a private/local IP address (SSRF blocked)'));
        }

        callback(null, address, family);
    });
}

const httpAgent = new http.Agent({ lookup: ssrfSafeLookup });
const httpsAgent = new https.Agent({ lookup: ssrfSafeLookup });

function isPrivateTarget(hostname) {
    const cleanHost = hostname.startsWith('[') && hostname.endsWith(']')
        ? hostname.slice(1, -1)
        : hostname;

    if (PRIVATE_IP_REG.test(cleanHost)) return true;
    if (cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) return true;
    if (net.isIP(cleanHost) && isPrivateIP(cleanHost)) return true;
    return false;
}

/**
 * Parses input for http/https URLs
 */
function extractURLs(text) {
    const regex = /https?:\/\/[^\s'";\)\<\>\`]+/gi;
    return text.match(regex) || [];
}

/**
 * Downloads a file, saves it, hashes it, checks VT, and reports
 */
async function processDownload(urlString, ip, sourceProtocol = 'ssh') {
    let url;
    try {
        url = new URL(urlString);
    } catch (_) {
        return null;
    }

    let currentUrl = url;
    let redirectCount = 0;
    const maxRedirects = 5;
    let response;

    logger.info(`Trapping malware download from ${url.href} (source IP: ${ip})`, { protocol: sourceProtocol });

    const tempFile = path.join(DOWNLOADS_DIR, `temp_${crypto.randomBytes(8).toString('hex')}`);
    const hash = crypto.createHash('sha256');
    let totalBytes = 0;
    const maxBytes = 10 * 1024 * 1024; // 10MB limit

    try {
        while (redirectCount <= maxRedirects) {
            if (isPrivateTarget(currentUrl.hostname)) {
                logger.warn(`SSRF Blocked: Attacker ${ip} tried to download from internal target: ${currentUrl.hostname}`, { protocol: sourceProtocol });
                return null;
            }

            response = await axios({
                method: 'get',
                url: currentUrl.href,
                responseType: 'stream',
                timeout: 15000,
                headers: {
                    'User-Agent': 'Wget/1.21.1-3 (linux-gnu)'
                },
                maxRedirects: 0,
                validateStatus: (status) => status >= 200 && status < 400,
                httpAgent,
                httpsAgent
            });

            if (response.status >= 300 && response.status < 400) {
                const location = response.headers['location'];
                if (!location) {
                    throw new Error(`Redirect status ${response.status} returned without Location header`);
                }
                const nextUrl = new URL(location, currentUrl.href);
                currentUrl = nextUrl;
                redirectCount++;
                logger.info(`Following redirect ${redirectCount}/${maxRedirects} to ${currentUrl.href}`, { protocol: sourceProtocol });
                response.data.destroy();
                continue;
            }

            break;
        }

        if (redirectCount > maxRedirects) {
            throw new Error('Too many redirects');
        }

        const filename = path.basename(currentUrl.pathname) || 'downloaded_file';
        const writer = fs.createWriteStream(tempFile);

        await new Promise((resolve, reject) => {
            const downloadTimeout = setTimeout(() => {
                response.data.destroy();
                writer.end();
                reject(new Error('Download timed out (overall limit of 20 seconds exceeded)'));
            }, 20000);

            response.data.on('data', (chunk) => {
                totalBytes += chunk.length;
                if (totalBytes > maxBytes) {
                    clearTimeout(downloadTimeout);
                    response.data.destroy();
                    reject(new Error('File exceeds maximum download size of 10MB'));
                }
                hash.update(chunk);
                writer.write(chunk);
            });

            response.data.on('end', () => {
                clearTimeout(downloadTimeout);
                writer.end();
                resolve();
            });

            response.data.on('error', (err) => {
                clearTimeout(downloadTimeout);
                writer.end();
                reject(err);
            });
        });

        const sha256 = hash.digest('hex');
        const finalPath = path.join(DOWNLOADS_DIR, sha256);

        // Rename temp file to its hash if it doesn't exist yet
        if (fs.existsSync(finalPath)) {
            fs.unlinkSync(tempFile); // Duplicate binary, delete temp
        } else {
            fs.renameSync(tempFile, finalPath);
        }

        logger.info(`Malware trapped! Saved to logs/downloads/${sha256} (${totalBytes} bytes)`, { protocol: sourceProtocol });

        // Scan contents of text scripts for nested downstream C2 URLs
        let c2Urls = [];
        if (totalBytes < 200000) {
            try {
                const fileContent = fs.readFileSync(finalPath, 'utf8');
                const potentialUrls = extractURLs(fileContent);
                for (const nestedUrlStr of potentialUrls) {
                    try {
                        const nestedUrl = new URL(nestedUrlStr);
                        if (!isPrivateTarget(nestedUrl.hostname) && nestedUrlStr !== url.href) {
                            c2Urls.push(nestedUrlStr);
                        }
                    } catch (_) {}
                }
            } catch (_) {}
        }
        if (c2Urls.length > 0) {
            logger.info(`Extracted ${c2Urls.length} downstream C2 URLs from payload`, { protocol: sourceProtocol });
        }

        // Query VirusTotal by hash
        let vtResult = null;
        const vtKey = process.env.VT_KEY;
        if (vtKey && vtKey !== 'your_key_here') {
            try {
                const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
                    headers: { 'x-apikey': vtKey },
                    timeout: 5000
                });
                const stats = vtResponse.data?.data?.attributes?.last_analysis_stats;
                if (stats) {
                    vtResult = {
                        malicious: stats.malicious || 0,
                        suspicious: stats.suspicious || 0,
                        undetected: stats.undetected || 0
                    };
                    logger.info(`VirusTotal result for ${sha256}: ${vtResult.malicious} malicious reports`, { protocol: sourceProtocol });
                }
            } catch (err) {
                if (err.response?.status === 404) {
                    logger.info(`VirusTotal: hash ${sha256} is unknown/new`, { protocol: sourceProtocol });
                    vtResult = { status: 'unknown_sample' };

                    // Auto-upload the binary sample if VT_UPLOAD_ENABLED is true
                    if (process.env.VT_UPLOAD_ENABLED === 'true') {
                        try {
                            logger.info(`VirusTotal: uploading new sample binary for ${sha256}...`, { protocol: sourceProtocol });
                            const fileBuffer = fs.readFileSync(finalPath);
                            const boundary = `----WebKitFormBoundary${crypto.randomBytes(16).toString('hex')}`;
                            const multipartBody = Buffer.concat([
                                Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
                                fileBuffer,
                                Buffer.from(`\r\n--${boundary}--\r\n`)
                            ]);
                            await axios.post('https://www.virustotal.com/api/v3/files', multipartBody, {
                                headers: {
                                    'x-apikey': vtKey,
                                    'Content-Type': `multipart/form-data; boundary=${boundary}`
                                },
                                timeout: 15000
                            });
                            logger.info(`VirusTotal: upload complete for sample ${sha256}`, { protocol: sourceProtocol });
                            vtResult.status = 'uploaded_for_analysis';
                        } catch (uploadErr) {
                            logger.error(`VirusTotal upload failed: ${uploadErr.message}`, { protocol: sourceProtocol });
                        }
                    }
                } else {
                    logger.error(`VirusTotal API error: ${err.message}`, { protocol: sourceProtocol });
                }
            }
        }

        // Send Telegram alert
        const telegramToken = process.env.TELEGRAM_TOKEN;
        const telegramChat  = process.env.TELEGRAM_CHAT;
        if (telegramToken && telegramChat) {
            try {
                let text = `⚠️ *[HoneyAI - Malware Trapped]*\n` +
                           `• *Origin IP:* \`${ip}\`\n` +
                           `• *Protocol:* \`${sourceProtocol.toUpperCase()}\`\n` +
                           `• *Source URL:* \`${url.href}\`\n` +
                           `• *SHA256:* \`${sha256}\`\n` +
                           `• *Size:* \`${totalBytes} bytes\`\n`;
                
                if (vtResult) {
                    if (vtResult.status) {
                        text += `• *VirusTotal:* \`Unknown / ${vtResult.status}\`\n`;
                    } else {
                        text += `• *VirusTotal:* \`${vtResult.malicious} malicious / ${vtResult.suspicious} suspicious\`\n`;
                    }
                } else {
                    text += `• *VirusTotal:* \`Not checked\`\n`;
                }

                if (c2Urls.length > 0) {
                    text += `• *Downstream C2:* ${c2Urls.map(u => `\`${u}\``).join(', ')}\n`;
                }
                
                await axios.post(`https://api.telegram.org/bot${telegramToken}/sendMessage`, {
                    chat_id: telegramChat,
                    text,
                    parse_mode: 'Markdown'
                });
            } catch (err) {
                logger.error(`Failed to send Telegram alert: ${err.message}`);
            }
        }

        // Log the download event
        logEvent({
            protocol: sourceProtocol,
            ip,
            event_type: 'malware_download',
            url: url.href,
            filename,
            sha256,
            file_size: totalBytes,
            vt_result: vtResult,
            c2_urls: c2Urls
        });

        return { filename, size: totalBytes, sha256, url: url.href };

    } catch (err) {
        if (fs.existsSync(tempFile)) {
            try { fs.unlinkSync(tempFile); } catch (_) {}
        }
        logger.error(`Malware download failed: ${err.message} (${url.href})`, { protocol: sourceProtocol });
        return null;
    }
}

/**
 * Simulates a realistic Wget or Curl CLI output
 */
function getFakeCLIOutput(urlStr, filename, size, downloadSeconds = 1.2) {
    let host = 'example.com';
    let ip = '93.184.216.34';
    try {
        const u = new URL(urlStr);
        host = u.hostname;
    } catch (_) {}

    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const sizeFormatted = size.toLocaleString();
    const sizeKB = (size / 1024).toFixed(1);
    const speed = (size / (1024 * 1024 * downloadSeconds)).toFixed(2);

    return `--${timestamp}--  ${urlStr}\r\n` +
           `Resolving ${host} (${host})... ${ip}\r\n` +
           `Connecting to ${host} (${host})|${ip}|:80... connected.\r\n` +
           `HTTP request sent, awaiting response... 200 OK\r\n` +
           `Length: ${size} (${sizeKB}K) [application/octet-stream]\r\n` +
           `Saving to: '${filename}'\r\n\r\n` +
           `     0K .......... .......... .......... .......... ..........  5%\r\n` +
           `    50K .......... .......... .......... .......... .......... 10%\r\n` +
           `   100K .......... .......... .......... .......... .......... 15%\r\n` +
           `   [... progress bars simulated ...]\r\n` +
           `   100% [==================================================>] 100%\r\n\r\n` +
           `${timestamp} (${speed} MB/s) - '${filename}' saved [${size}/${size}]`;
}

module.exports = {
    extractURLs,
    processDownload,
    getFakeCLIOutput,
    isPrivateIP,
    convertIPv4Mapped
};
