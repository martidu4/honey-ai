/**
 * HoneyAI — Generic TCP Protocol Handler v2
 * Fixed: command queue (no parallel AI calls), proper line buffering,
 * input sanitization, rate limiting, memory-safe logging.
 */

'use strict';

const net      = require('net');
const fs       = require('fs');
const path     = require('path');
const config   = require('../core/config');
const { logger, logEvent, sanitizeForLog } = require('../core/logger');
const reporter = require('../core/reporter');
const ai       = require('../ai/engine');
const crypto   = require('crypto');
const traps    = require('../core/traps');
const backfire = require('../core/backfire');
const { sleep } = require('../core/jitter');

// ─── Protocol definitions ─────────────────────────────────────────────────────
const PROTOCOLS = {
    ftp: {
        key:        'ftp',
        port:       21,
        banner:     '220 (vsFTPd 3.0.5)\r\n',
        prompt:     null,         // FTP has no persistent prompt
        categories: '5,18',
        hardcoded: {
            'USER':     '331 Please specify the password.\r\n',
            'PASS':     '230 Login successful.\r\n',
            'SYST':     '215 UNIX Type: L8\r\n',
            'PWD':      '257 "/" is the current directory\r\n',
            'QUIT':     '221 Goodbye.\r\n',
            'PORT':     '200 PORT command successful.\r\n',
            'FEAT':     "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n",
            'OPTS':     "200 Always in UTF8 mode.\r\n",
            'NOOP':     '200 NOOP ok.\r\n',
            'CWD':      '250 Directory successfully changed.\r\n',
            'CDUP':     '250 Directory successfully changed.\r\n',
            'MKD':      '257 "/new" created\r\n',
            'DELE':     '250 Delete operation successful.\r\n',
            'RMD':      '250 Remove directory operation successful.\r\n',
            'SIZE':     '213 45321\r\n',
            'MDTM':     '213 20240115102400\r\n'
        },
        // MED-03 + LOW-01: Dynamic FTP responses that need runtime logic
        dynamicHardcoded: {
            'TYPE': (args) => {
                const mode = (args || '').toUpperCase();
                if (mode === 'A') return '200 Switching to ASCII mode.\r\n';
                return '200 Switching to Binary mode.\r\n';
            },
            'PASV': (args, socket) => {
                const p1 = Math.floor(Math.random() * 200) + 30;
                const p2 = Math.floor(Math.random() * 255);
                // Use socket local address or fallback to a generic public-looking IP
                let localIp = '0,0,0,0';
                if (socket && socket.localAddress) {
                    localIp = socket.localAddress.replace(/^::ffff:/, '').split('.').join(',');
                }
                return `227 Entering Passive Mode (${localIp},${p1},${p2}).\r\n`;
            },
            'LIST': () => '150 Here comes the directory listing.\r\n-rw-r--r-- 1 root root 45321 Jan 15 backup_db.sql\r\n-rw-r--r-- 1 root root 12890 Feb 03 passwords.txt\r\n-rw-r--r-- 1 root root 89234 Mar 22 .ssh_keys.tar.gz\r\n226 Directory send OK.\r\n',
            'RETR': () => '550 Failed to open file.\r\n'
        }
    },
    telnet: {
        key:        'telnet',
        port:       23,
        // IAC DO SUPPRESS-GO-AHEAD, IAC WILL ECHO — proper telnet negotiation for nmap
        // LOW-03: Matches Debian ident from SSH to avoid cross-protocol fingerprinting
        banner:     '\xff\xfd\x03\xff\xfb\x01\r\nDebian GNU/Linux 12\r\n\r\nlogin: ',
        prompt:     '$ ',
        categories: '23,18'
    },
    smtp: {
        key:        'smtp',
        port:       25,
        banner:     '220 mail.example.com ESMTP Postfix (Ubuntu)\r\n',
        prompt:     null,
        categories: '11,18',
        hardcoded: {
            'HELO':     '250 mail.example.com\r\n',
            'EHLO':     '250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250 HELP\r\n',
            'MAIL':     '250 2.1.0 Ok\r\n',
            'RCPT':     '250 2.1.5 Ok\r\n',
            'RSET':     '250 2.0.0 Ok\r\n',
            'VRFY':     '252 2.1.5 Send mail to address anyway\r\n',
            'NOOP':     '250 2.0.0 OK\r\n',
            'QUIT':     '221 2.0.0 Bye\r\n',
            'DATA':     '354 End data with <CR><LF>.<CR><LF>\r\n'
        }
    },
    mysql: {
        key:        'mysql',
        port:       3306,
        banner:     Buffer.from('4a0000000a382e302e333500010000003132333435363738008f8221020008001500000000000000000000313233343536373839303132006d7973716c5f6e61746976655f70617373776f726400', 'hex'),
        binary:     true,
        prompt:     null,
        categories: '15,18'
    },
    redis: {
        key:        'redis',
        port:       6379,
        banner:     null,
        prompt:     null,
        categories: '15,14',
        // Redis uses request-response: hardcoded responses for known commands
        hardcoded: {
            'PING':     '+PONG\r\n',
            'INFO':     '$169\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.1.0 x86_64\r\narch_bits:64\r\ntcp_port:6379\r\nuptime_in_seconds:864000\r\nuptime_in_days:10\r\n\r\n# Clients\r\nconnected_clients:3\r\n\r\n# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\n\r\n',
            'CONFIG':   '-ERR unknown command\r\n',
            'AUTH':     '-ERR Client sent AUTH, but no password is set\r\n',
            'SELECT':   '+OK\r\n',
            'QUIT':     '+OK\r\n',
            'COMMAND':  '+OK\r\n',
            'KEYS':     '*5\r\n$13\r\nsession:admin\r\n$11\r\nuser:admin\r\n$13\r\nconfig:dbpass\r\n$17\r\napi_key:production\r\n$14\r\nbackup:latest\r\n',
            'CLIENT':   '$0\r\n\r\n',
            'CLUSTER':  '$19\r\ncluster_enabled:0\r\n',
            'DBSIZE':   ':5\r\n',
            'FLUSHALL': '+OK\r\n',
            'FLUSHDB':  '+OK\r\n',
            'RANDOMKEY':'$13\r\nsession:admin\r\n',
            'TIME':     '*2\r\n$10\r\n1718534400\r\n$6\r\n123456\r\n',
            'TYPE':     '+string\r\n'
        }
    },
    git: {
        key:        'git',
        port:       9418,
        banner:     null,
        prompt:     null,
        categories: '15,14'
    },
    vnc: {
        key:        'vnc',
        port:       5900,
        banner:     'RFB 003.008\n',
        prompt:     null,
        categories: '15,14'
    },
    rdp: {
        key:        'rdp',
        port:       3389,
        banner:     null,
        prompt:     null,
        categories: '15,14'
    }
};

// ─── Per-IP connection rate limit ─────────────────────────────────────────────
const CONNECTION_COUNTS = new Map(); // ip → count
const MAX_CONNECTIONS_PER_IP = 10;

setInterval(() => CONNECTION_COUNTS.clear(), 60 * 1000).unref(); // Reset every minute

/**
 * Returns connection rate limit status for an IP.
 * @param {string} ip
 * @returns {number} 0: Under limit, 1: First time exceeding limit, 2: Already exceeded
 */
function getRateLimitStatus(ip) {
    const count = (CONNECTION_COUNTS.get(ip) || 0) + 1;
    CONNECTION_COUNTS.set(ip, count);
    
    if (count === MAX_CONNECTIONS_PER_IP + 1) {
        return 1; // First block
    }
    if (count > MAX_CONNECTIONS_PER_IP) {
        return 2; // Silent block
    }
    return 0; // Allowed
}

function start() {
    const cfg = config.protocols;
    const servers = [];
    Object.values(PROTOCOLS).forEach(proto => {
        const protoCfg = cfg[proto.key];
        if (!protoCfg?.enabled) return;
        const port = protoCfg.port || proto.port;
        const server = startServer(proto, port);
        if (server) servers.push(server);
    });
    return servers;
}

function startServer(proto, port) {
    if (proto.key === 'vnc') {
        return startVncServer(proto, port);
    }
    if (proto.key === 'rdp') {
        return startRdpServer(proto, port);
    }
    const srv = net.createServer((socket) => {
        const rawIp = socket.remoteAddress || 'unknown';
        const ip    = rawIp.replace(/^::ffff:/, '');

        if (global.activeConnections && global.activeConnections[proto.key] !== undefined) {
            global.activeConnections[proto.key]++;
        }
        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections[proto.key] !== undefined) {
                    global.activeConnections[proto.key]--;
                }
            }
        };
        socket.on('close', decrement);
        socket.on('error', decrement);

        // ── Rate limiting ──────────────────────────────────────────────────
        const limitStatus = getRateLimitStatus(ip);
        if (limitStatus > 0) {
            if (limitStatus === 1) {
                logger.warn(`Rate limit hit for ${ip} (further connections silenced)`, { protocol: proto.key, ip });
            }
            socket.destroy();
            return;
        }

        const count = CONNECTION_COUNTS.get(ip) || 0;
        logger.info(`New connection (${count} this minute)`, { protocol: proto.key, ip });

        socket.setTimeout(120_000);
        socket.on('timeout', () => socket.destroy());
        socket.on('error',   () => {});

        // Send banner
        if (proto.banner) socket.write(proto.banner);

        // ── Command queue — ensures AI responses are sequential ────────────
        let processing = false;
        const queue    = [];
        let lineBuffer = '';

        function enqueue(line) {
            queue.push(line);
            if (!processing) drainQueue();
        }

        async function drainQueue() {
            if (queue.length === 0) { processing = false; return; }
            processing = true;

            const line = queue.shift();
            if (!line || line.length < 1) { drainQueue(); return; }

            try {
                // Check for config-defined custom commands first (low-code option)
                const cleanCmd = line.trim();
                if (config.custom_commands && Array.isArray(config.custom_commands)) {
                    let matched = false;
                    for (const item of config.custom_commands) {
                        if (!item.trigger) continue;
                        // Restrict by protocol if specified
                        if (item.protocol && item.protocol !== proto.key) continue;

                        if (item.regex) {
                            try {
                                if (item.trigger.length > 200) continue; // Guard against ReDoS
                                const re = new RegExp(item.trigger, 'i');
                                const match = cleanCmd.match(re);
                                if (match) {
                                    let resp = item.response || '';
                                    // Replace backreferences {1}, {2}...
                                    for (let i = 1; i < match.length; i++) {
                                        resp = resp.replaceAll(`{${i}}`, match[i]);
                                    }
                                    // Ensure proper line endings for text protocols
                                    if (proto.key !== 'redis' && !resp.endsWith('\r\n')) {
                                        resp = resp.replace(/\r?\n/g, '\r\n') + '\r\n';
                                    }
                                    if (!socket.destroyed) socket.write(resp);
                                    matched = true;
                                    break;
                                }
                            } catch (e) {
                                logger.error(`Error parsing custom command regex trigger "${item.trigger}": ${e.message}`, { protocol: proto.key });
                            }
                        } else if (cleanCmd.toLowerCase() === item.trigger.trim().toLowerCase()) {
                            let resp = item.response || '';
                            if (proto.key !== 'redis' && !resp.endsWith('\r\n')) {
                                resp = resp.replace(/\r?\n/g, '\r\n') + '\r\n';
                            }
                            if (!socket.destroyed) socket.write(resp);
                            matched = true;
                            break;
                        }
                    }
                    if (matched) {
                        drainQueue();
                        return;
                    }
                }

                // Check for hardcoded responses (Redis, Git known commands)
                const cmdKey = line.split(/\s/)[0].toUpperCase();
                
                // Redis MONITOR/SUBSCRIBE flood trigger
                if (proto.key === 'redis' && (cmdKey === 'MONITOR' || cmdKey === 'SUBSCRIBE')) {

                    logger.warn(`Redis MONITOR flood triggered from ${ip}`, { protocol: 'redis', ip });
                    
                    logEvent({
                        protocol: 'redis',
                        ip,
                        port,
                        input: cmdKey,
                        attack_type: 'redis_monitor_flood_triggered'
                    });

                    reporter.report(ip, {
                        protocol: 'redis',
                        port,
                        comment: `Redis MONITOR command executed -> flood trap triggered`,
                        categories: '15,14'
                    }).catch(() => {});

                    traps.floodRedisMonitor(socket, ip);
                    return; // exit command queue loop, the flooder takes over the socket
                }

                if (proto.hardcoded && proto.hardcoded[cmdKey]) {
                    if (!socket.destroyed) socket.write(proto.hardcoded[cmdKey]);
                    if (cmdKey === 'QUIT') { socket.end(); return; }
                    drainQueue();
                    return;
                }

                // MED-03 + LOW-01: Dynamic FTP responses (TYPE A/I, PASV with random port)
                if (proto.dynamicHardcoded && proto.dynamicHardcoded[cmdKey]) {
                    const args = line.split(/\s+/).slice(1).join(' ');
                    const dynamicResponse = proto.dynamicHardcoded[cmdKey](args, socket);
                    if (!socket.destroyed) socket.write(dynamicResponse);
                    drainQueue();
                    return;
                }

                if (proto.key === 'redis') {
                    // Route known data commands through the AI engine
                    // (which has static RESP responses for GET, SET, DEL, etc.)
                    const parts = line.split(/\s+/).filter(Boolean);
                    const cmd = (parts[0] || '').toUpperCase();
                    const REDIS_AI_COMMANDS = ['MGET', 'HGET', 'HGETALL', 'HSET', 'LRANGE', 'SMEMBERS', 'TTL', 'EXISTS', 'SCAN'];
                    
                    // MED-02: Handle GET with static RESP — known keys return data, unknown return $-1
                    if (cmd === 'GET') {
                        const key = (parts[1] || '').toLowerCase();
                        const KNOWN_KEYS = {
                            'session:admin': '$36\r\n{"user":"admin","role":"superadmin","token":"abc"}\r\n',
                            'user:admin': '$28\r\n{"name":"admin","level":"root"}\r\n',
                            'config:dbpass': '$22\r\nPostgres!Pr0d#2024@db1\r\n',
                            'api_key:production': '$40\r\nsk_live_51abc123def456ghi789jkl012mno345\r\n',
                            'backup:latest': '$19\r\n2024-06-15T03:00:00Z\r\n'
                        };
                        const resp = KNOWN_KEYS[key] || '$-1\r\n';
                        if (!socket.destroyed) socket.write(resp);
                        drainQueue();
                        return;
                    }
                    // Handle SET/DEL statically
                    if (cmd === 'SET' || cmd === 'DEL' || cmd === 'SETNX' || cmd === 'SETEX' || cmd === 'EXPIRE') {
                        if (!socket.destroyed) socket.write(cmd === 'DEL' ? ':1\r\n' : '+OK\r\n');
                        drainQueue();
                        return;
                    }
                    
                    if (REDIS_AI_COMMANDS.includes(cmd)) {
                        // Let the AI engine handle — it has static RESP responses
                        const redisResponse = await ai.generate({
                            protocol: 'redis',
                            attackerInput: line,
                            context: { ip, port }
                        });
                        if (!socket.destroyed) {
                            let formatted = redisResponse;
                            if (!formatted.endsWith('\r\n')) formatted += '\r\n';
                            socket.write(formatted);
                        }
                        drainQueue();
                        return;
                    }
                    // Truly unknown commands → ERR
                    const args = parts.slice(1).map(arg => `'${arg}'`).join(' ');
                    const errResponse = `-ERR unknown command '${cmd.toLowerCase()}', with args beginning with: ${args ? args + ' ' : ''}\r\n`;
                    if (!socket.destroyed) socket.write(errResponse);
                    drainQueue();
                    return;
                }

                const response = await ai.generate({
                    protocol:     proto.key,
                    attackerInput: line,
                    context:      { ip, port }
                });

                if (!socket.destroyed) {
                    const isSQLi = proto.key === 'mysql' && /union\s+select|select\s+@@|or\s+1\s*=\s*1|information_schema/i.test(line);
                    const isScanner = isSQLi || /nmap|masscan|zgrab|sqlmap|exploit|nessus|nikto|wpscan/i.test(line);
                    const isLocal = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
                    const lineDelay = isLocal ? 10 : (isScanner ? 8000 : 2000);

                    if (isSQLi) {
                        logger.warn(`MySQL SQL Injection tarpit triggered from ${ip} with query: "${line.substring(0, 100)}"`, { protocol: 'mysql', ip });
                        logEvent({
                            protocol: 'mysql',
                            ip,
                            port,
                            input: line.substring(0, 200),
                            attack_type: 'mysql_sql_tarpit_triggered'
                        });
                        reporter.report(ip, {
                            protocol: 'mysql',
                            port,
                            comment: `MySQL SQL injection query: "${line.substring(0, 100)}" -> slow drip tarpit triggered`,
                            categories: '15,18'
                        }).catch(() => {});
                    }

                    let formatted = response.replace(/\r\n/g, '\n');
                    if (!formatted.endsWith('\n')) {
                        formatted += '\n';
                    }
                    formatted = formatted.replace(/\n/g, '\r\n');
                    const lines = formatted.split('\r\n');

                    for (let i = 0; i < lines.length - 1; i++) {
                        if (socket.destroyed || !socket.writable) break;
                        socket.write(lines[i] + '\r\n');
                        // Drip delay between lines if multiline
                        if (lines.length > 2) {
                            await new Promise(resolve => setTimeout(resolve, lineDelay + Math.random() * 500));
                        } else {
                            await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 50));
                        }
                    }

                    const lowerLine = line.trim().toLowerCase();
                    const shouldDisconnect = lowerLine === 'exit' || lowerLine === 'quit' || response.includes('Connection closed by foreign host.');
                    if (shouldDisconnect) {
                        socket.end();
                        return;
                    }

                    if (!socket.destroyed && socket.writable && proto.prompt) {
                        socket.write(proto.prompt);
                    }
                }
            } catch (err) {
                logger.error(`TCP command execution error (${proto.key}): ${err.message}`, { protocol: proto.key, ip, error: err.stack });
                if (!socket.destroyed) socket.write('Connection error.\r\n');
            }

            drainQueue(); // Process next command
        }

        // ── MySQL Rogue Server variables ───────────────────────────────────
        let mysqlState = 0; // 0: Handshake sent, 1: Auth OK sent, 2: Waiting query, 3: Requested infile
        let mysqlExfilFile = '/etc/passwd';
        let mysqlSeqNum = 0;
        let mysqlFileBuffer = Buffer.alloc(0);

        // ── Redis RESP variables ───────────────────────────────────────────
        let redisBuffer = '';

        // ── SMTP state variables ───────────────────────────────────────────
        let smtpDataMode = false;
        let smtpDataBuffer = '';

        // ── Telnet state variables ──────────────────────────────────────────
        let telnetBuffer = Buffer.alloc(0);
        let telnetState = 'awaitingUsername';
        let telnetUsername = '';

        function processRedisCommand(line) {
            const safeInput = sanitizeForLog(line);
            logger.info(`Command: "${safeInput}"`, { protocol: 'redis', ip });

            logEvent({
                protocol: 'redis',
                ip,
                port,
                input: safeInput.substring(0, 200)
            });

            reporter.report(ip, {
                protocol: 'redis',
                port,
                comment: `Redis unauthorized command: "${safeInput.substring(0, 100)}"`,
                categories: proto.categories
            }).catch(() => {});

            enqueue(line.substring(0, 512));
        }

        // ── Data handler — accumulate by line, don't call AI per raw chunk ─
        socket.on('data', async (data) => {
            // Telnet state machine interceptor (strip Telnet IAC options / negotiations)
            if (proto.key === 'telnet') {
                if (telnetBuffer.length + data.length > 65536) {
                    logger.warn(`Telnet input overflow from ${ip}, disconnecting`, { protocol: 'telnet', ip });
                    socket.destroy();
                    return;
                }
                telnetBuffer = Buffer.concat([telnetBuffer, data]);

                let cleanData = Buffer.alloc(telnetBuffer.length);
                let cleanLen = 0;
                let i = 0;
                let processedLen = 0;

                while (i < telnetBuffer.length) {
                    if (telnetBuffer[i] === 255) { // IAC
                        if (i + 1 >= telnetBuffer.length) {
                            break; // Wait for more data
                        }
                        const cmd = telnetBuffer[i + 1];
                        if (cmd === 251 || cmd === 252 || cmd === 253 || cmd === 254) { // WILL, WONT, DO, DONT
                            if (i + 2 >= telnetBuffer.length) {
                                break; // Wait for more data
                            }
                            const opt = telnetBuffer[i + 2];
                            if (cmd === 253) { // DO
                                socket.write(Buffer.from([255, 252, opt]));
                            } else if (cmd === 251) { // WILL
                                socket.write(Buffer.from([255, 254, opt]));
                            }
                            i += 3;
                            processedLen = i;
                        } else if (cmd === 250) { // SB (Subnegotiation Begin)
                            let seIdx = -1;
                            for (let j = i + 2; j < telnetBuffer.length - 1; j++) {
                                if (telnetBuffer[j] === 255 && telnetBuffer[j + 1] === 240) {
                                    seIdx = j + 1;
                                    break;
                                }
                            }
                            if (seIdx === -1) {
                                break; // Wait for more data (se is missing)
                            }
                            i = seIdx + 1;
                            processedLen = i;
                        } else {
                            // 2-byte command (e.g. AYT, NOP)
                            i += 2;
                            processedLen = i;
                        }
                    } else {
                        cleanData[cleanLen++] = telnetBuffer[i];
                        i++;
                        processedLen = i;
                    }
                }

                telnetBuffer = telnetBuffer.slice(processedLen);
                data = cleanData.slice(0, cleanLen);
                if (data.length === 0) {
                    return; // No clean data to process yet
                }
            }

            // Redis RESP state machine interceptor
            if (proto.key === 'redis') {
                if (redisBuffer.length + data.length > 65536) {
                    logger.warn(`Redis input overflow from ${ip}, disconnecting`, { protocol: 'redis', ip });
                    socket.destroy();
                    return;
                }
                redisBuffer += data.toString('utf8');

                while (redisBuffer.length > 0) {
                    if (redisBuffer.startsWith('*')) {
                        const firstNewline = redisBuffer.indexOf('\r\n');
                        if (firstNewline === -1) break;

                        const countStr = redisBuffer.slice(1, firstNewline);
                        const count = parseInt(countStr, 10);
                        if (isNaN(count) || count < 0) {
                            socket.destroy();
                            return;
                        }

                        let idx = firstNewline + 2;
                        const args = [];
                        let incomplete = false;

                        for (let i = 0; i < count; i++) {
                            if (idx >= redisBuffer.length) {
                                incomplete = true;
                                break;
                            }
                            if (redisBuffer[idx] !== '$') {
                                socket.destroy();
                                return;
                            }
                            const lenNewline = redisBuffer.indexOf('\r\n', idx);
                            if (lenNewline === -1) {
                                incomplete = true;
                                break;
                            }
                            const lenStr = redisBuffer.slice(idx + 1, lenNewline);
                            const len = parseInt(lenStr, 10);
                            if (isNaN(len) || len < 0) {
                                socket.destroy();
                                return;
                            }
                            const argStart = lenNewline + 2;
                            const argEnd = argStart + len;
                            if (argEnd + 2 > redisBuffer.length) {
                                incomplete = true;
                                break;
                            }
                            if (redisBuffer.slice(argEnd, argEnd + 2) !== '\r\n') {
                                socket.destroy();
                                return;
                            }
                            const arg = redisBuffer.slice(argStart, argEnd);
                            args.push(arg);
                            idx = argEnd + 2;
                        }

                        if (incomplete) {
                            break;
                        }

                        redisBuffer = redisBuffer.slice(idx);
                        const commandLine = args.join(' ');
                        if (commandLine.length > 0) {
                            processRedisCommand(commandLine);
                        }
                    } else {
                        const newlineIdx = redisBuffer.indexOf('\n');
                        if (newlineIdx === -1) break;

                        const line = redisBuffer.slice(0, newlineIdx).replace(/\r$/, '').trim();
                        redisBuffer = redisBuffer.slice(newlineIdx + 1);

                        if (line.length > 0) {
                            processRedisCommand(line);
                        }
                    }
                }
                return;
            }

            // SMTP state machine interceptor
            if (proto.key === 'smtp') {
                if (lineBuffer.length + data.length > 65536) {
                    logger.warn(`SMTP input overflow from ${ip}, disconnecting`, { protocol: 'smtp', ip });
                    socket.destroy();
                    return;
                }
                lineBuffer += data.toString('utf8');

                let newlineIdx;
                while ((newlineIdx = lineBuffer.indexOf('\n')) !== -1) {
                    const line = lineBuffer.slice(0, newlineIdx).replace(/\r$/, '');
                    lineBuffer = lineBuffer.slice(newlineIdx + 1);

                    if (smtpDataMode) {
                        if (line.trim() === '.') {
                            smtpDataMode = false;
                            logger.info(`SMTP Mail Data received (${smtpDataBuffer.length} bytes)`, { protocol: 'smtp', ip });
                            
                            logEvent({
                                protocol: 'smtp',
                                ip,
                                port,
                                attack_type: 'smtp_mail_data_received',
                                input: smtpDataBuffer.substring(0, 500)
                            });

                            socket.write('250 2.0.0 Ok: queued as ' + crypto.randomBytes(8).toString('hex').toUpperCase() + '\r\n');
                            smtpDataBuffer = '';
                        } else {
                            if (smtpDataBuffer.length + line.length > 1048576) { // 1MB limit
                                logger.warn(`SMTP mail data limit exceeded from ${ip}, disconnecting`, { protocol: 'smtp', ip });
                                if (!socket.destroyed) {
                                    socket.write('552 Message size exceeds fixed maximum message size\r\n');
                                    socket.end();
                                }
                                return;
                            }
                            smtpDataBuffer += line + '\n';
                        }
                    } else {
                        const cmdLine = line.trim();
                        if (cmdLine.length === 0) continue;

                        const cmdKey = cmdLine.split(/\s/)[0].toUpperCase();
                        
                        if (cmdKey === 'DATA') {
                            smtpDataMode = true;
                            smtpDataBuffer = '';
                            socket.write('354 Start mail input; end with <CR><LF>.<CR><LF>\r\n');
                        } else {
                            const safeInput = sanitizeForLog(cmdLine);
                            logger.info(`Command: "${safeInput}"`, { protocol: 'smtp', ip });

                            logEvent({
                                protocol: 'smtp',
                                ip,
                                port,
                                input: safeInput.substring(0, 200)
                            });

                            reporter.report(ip, {
                                protocol: 'smtp',
                                port,
                                comment: `SMTP abuse detected: "${safeInput.substring(0, 100)}"`,
                                categories: proto.categories
                            }).catch(() => {});

                            enqueue(cmdLine.substring(0, 512));
                        }
                    }
                }
                return;
            }

            // Git protocol state machine interceptor (client-speaks-first & command parser)
            if (proto.key === 'git') {
                try {
                    const dataStr = data.toString('utf8');
                    const makeGitError = (msg) => {
                        const line = `ERR ${msg}\n`;
                        const lenHex = (line.length + 4).toString(16).padStart(4, '0');
                        return lenHex + line;
                    };

                    const hexPrefix = dataStr.substring(0, 4);
                    const isValidPkt = /^[0-9a-fA-F]{4}$/.test(hexPrefix);

                    if (isValidPkt) {
                        const pktLen = parseInt(hexPrefix, 16);
                        if (pktLen > 4 && pktLen <= data.length) {
                            const payload = dataStr.substring(4, pktLen);
                            
                            if (payload.includes('git-upload-pack')) {
                                const repoMatch = payload.match(/git-upload-pack\s+([^\s\0]+)/);
                                const repoName = repoMatch ? repoMatch[1] : '/test.git';

                                logger.warn(`Git clone attempt for ${sanitizeForLog(repoName)} from ${ip} -> triggering Infinite Clone tarpit`, { protocol: 'git', ip });
                                
                                logEvent({
                                    protocol: 'git',
                                    ip,
                                    port,
                                    attack_type: 'git_infinite_clone_triggered',
                                    repository: repoName
                                });

                                reporter.report(ip, {
                                    protocol: 'git',
                                    port,
                                    comment: `Git clone attempt for ${repoName} -> infinite clone tarpit triggered`,
                                    categories: '15,14'
                                }).catch(() => {});


                                traps.streamInfiniteGitRefs(socket);
                                return;
                            }
                            
                            if (payload.includes('git-receive-pack')) {
                                logger.info(`Git push attempt from ${ip}`, { protocol: 'git', ip });
                                socket.write(makeGitError("repository read-only"));
                                socket.end();
                                return;
                            }
                        }
                    }

                    // Fallback for non-git scanner/probe
                    logger.info(`Git non-protocol query or probe from ${ip}`, { protocol: 'git', ip });
                    socket.write(makeGitError("no such repository: /test.git"));
                    socket.end();
                } catch (err) {
                    logger.error(`Git parser error: ${err.message}`, { protocol: 'git', ip });
                    socket.destroy();
                }
                return;
            }

            // MySQL Rogue Server state machine interceptor
            if (proto.key === 'mysql') {
                if (data.length < 4) {
                    socket.destroy();
                    return;
                }
                try {
                    mysqlSeqNum = data[3]; // grab sequence number
                    
                    if (mysqlState === 0) {
                        // Client Authentication Packet received -> send OK response
                        const okPacket = Buffer.from([
                            0x07, 0x00, 0x00, 0x02, // Header: len 7, seq 2
                            0x00, // OK header
                            0x00, 0x00, // Affected rows 0, insert ID 0
                            0x02, 0x00, // Server status: AUTOCOMMIT
                            0x00, 0x00 // Warnings 0
                        ]);
                        socket.write(okPacket);
                        mysqlState = 2; // Auth complete, wait for query
                        return;
                    }
                    
                     if (mysqlState === 2) {
                        // Wait for COM_QUERY (0x03) packet
                        if (data.length >= 5 && data[4] === 0x03) {
                            const query = data.slice(5).toString('utf8').trim();
                            const queryLower = query.toLowerCase();
                            logger.info(`MySQL COM_QUERY query: "${sanitizeForLog(query)}"`, { protocol: 'mysql', ip });

                            logEvent({
                                protocol: 'mysql',
                                ip,
                                port,
                                input: query.substring(0, 200),
                                attack_type: 'mysql_query'
                            });

                            const seq = mysqlSeqNum + 1;

                            // Helper: build a simple MySQL text result set (1 column, 1 row)
                            const makeSingleResult = (colName, value, seqStart) => {
                                const bufs = [];
                                // Column count packet (1 column)
                                bufs.push(Buffer.from([0x01, 0x00, 0x00, seqStart, 0x01]));
                                // Column definition (simplified)
                                const colNameBuf = Buffer.from(colName, 'utf8');
                                const colBody = Buffer.concat([
                                    Buffer.from([0x03]), Buffer.from('def'),  // catalog
                                    Buffer.from([0x00]),                       // schema
                                    Buffer.from([0x00]),                       // table
                                    Buffer.from([0x00]),                       // org_table
                                    Buffer.from([colNameBuf.length]), colNameBuf, // name
                                    Buffer.from([0x00]),                       // org_name
                                    Buffer.from([0x0c, 0x21, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xfd, 0x01, 0x00, 0x1f, 0x00, 0x00])
                                ]);
                                const colPkt = Buffer.alloc(4 + colBody.length);
                                colPkt.writeUIntLE(colBody.length, 0, 3);
                                colPkt[3] = seqStart + 1;
                                colBody.copy(colPkt, 4);
                                bufs.push(colPkt);
                                // EOF
                                bufs.push(Buffer.from([0x05, 0x00, 0x00, seqStart + 2, 0xfe, 0x00, 0x00, 0x02, 0x00]));
                                // Row data
                                const valBuf = Buffer.from(value, 'utf8');
                                const rowBody = Buffer.alloc(1 + valBuf.length);
                                rowBody[0] = valBuf.length;
                                valBuf.copy(rowBody, 1);
                                const rowPkt = Buffer.alloc(4 + rowBody.length);
                                rowPkt.writeUIntLE(rowBody.length, 0, 3);
                                rowPkt[3] = seqStart + 3;
                                rowBody.copy(rowPkt, 4);
                                bufs.push(rowPkt);
                                // EOF (end of rows)
                                bufs.push(Buffer.from([0x05, 0x00, 0x00, seqStart + 4, 0xfe, 0x00, 0x00, 0x02, 0x00]));
                                return Buffer.concat(bufs);
                            };

                            // Helper: OK packet
                            const makeOkPacket = (seqNum) => Buffer.from([
                                0x07, 0x00, 0x00, seqNum,
                                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
                            ]);

                            // ── Safe queries: respond with realistic MySQL data ──
                            if (queryLower.includes('@@version_comment')) {
                                socket.write(makeSingleResult('@@version_comment', 'Debian', seq));
                                return;
                            }
                            if (queryLower.match(/select\s+@@version\b/) || queryLower === 'select version()') {
                                socket.write(makeSingleResult('@@version', '8.0.35-0ubuntu0.22.04.1', seq));
                                return;
                            }
                            if (queryLower.includes('@@hostname')) {
                                socket.write(makeSingleResult('@@hostname', 'db-prod-01', seq));
                                return;
                            }
                            if (queryLower.includes('@@datadir')) {
                                socket.write(makeSingleResult('@@datadir', '/var/lib/mysql/', seq));
                                return;
                            }
                            if (queryLower.includes('@@version_compile_os')) {
                                socket.write(makeSingleResult('@@version_compile_os', 'Linux', seq));
                                return;
                            }
                            if (queryLower.includes('@@global.') || queryLower.includes('@@session.')) {
                                socket.write(makeSingleResult('Value', 'OFF', seq));
                                return;
                            }
                            if (queryLower.startsWith('set ') || queryLower.startsWith('use ')) {
                                socket.write(makeOkPacket(seq));
                                return;
                            }
                            if (queryLower === 'select 1' || queryLower === 'select 1;') {
                                socket.write(makeSingleResult('1', '1', seq));
                                return;
                            }
                            if (queryLower.startsWith('select database()')) {
                                socket.write(makeSingleResult('database()', 'production', seq));
                                return;
                            }
                            if (queryLower.startsWith('select user()') || queryLower.startsWith('select current_user()')) {
                                socket.write(makeSingleResult('user()', 'root@%', seq));
                                return;
                            }

                            // ── Suspicious queries → trigger INFILE trap ──
                            const isSuspicious = queryLower.startsWith('show databases') ||
                                queryLower.startsWith('show tables') ||
                                queryLower.startsWith('show schemas') ||
                                queryLower.match(/select\s+\*\s+from/) ||
                                queryLower.match(/select\s+.*from\s+(mysql|information_schema|performance_schema)/) ||
                                queryLower.includes('information_schema') ||
                                queryLower.includes('load data') ||
                                queryLower.includes('into outfile') ||
                                queryLower.includes('into dumpfile') ||
                                queryLower.includes('union') ||
                                queryLower.match(/select\s+.*password/) ||
                                queryLower.match(/select\s+.*from\s+/);

                            if (isSuspicious) {

                                mysqlExfilFile = Math.random() > 0.5 ? '/etc/passwd' : 'C:\\Windows\\win.ini';
                                logger.warn(`MySQL Rogue INFILE triggered by: "${query.substring(0, 80)}" from ${ip}`, { protocol: 'mysql', ip });

                                logEvent({
                                    protocol: 'mysql',
                                    ip,
                                    port,
                                    input: query.substring(0, 100),
                                    attack_type: 'mysql_rogue_infile_triggered',
                                    target_file: mysqlExfilFile,
                                    action: 'tarpit',
                                    severity: 'critical'
                                });

                                reporter.report(ip, {
                                    protocol: 'mysql',
                                    port,
                                    comment: `MySQL enumeration query → Rogue INFILE trap: "${query.substring(0, 100)}"`,
                                    categories: '15,18'
                                }).catch(() => {});

                                const requestPacket = traps.makeMySQLInfileRequest(mysqlExfilFile, seq);
                                socket.write(requestPacket);
                                mysqlState = 3;
                                return;
                            }

                            // Fallback: generic OK for unknown queries
                            socket.write(makeOkPacket(seq));
                            return;
                        }

                        // COM_QUIT (0x01)
                        if (data.length >= 5 && data[4] === 0x01) {
                            socket.end();
                            return;
                        }

                        // COM_PING (0x0e)
                        if (data.length >= 5 && data[4] === 0x0e) {
                            const okPkt = Buffer.from([0x07, 0x00, 0x00, mysqlSeqNum + 1, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
                            socket.write(okPkt);
                            return;
                        }

                        // COM_INIT_DB (0x02)
                        if (data.length >= 5 && data[4] === 0x02) {
                            const dbName = data.slice(5).toString('utf8');
                            logger.info(`MySQL COM_INIT_DB: ${sanitizeForLog(dbName)}`, { protocol: 'mysql', ip });
                            const okPkt = Buffer.from([0x07, 0x00, 0x00, mysqlSeqNum + 1, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
                            socket.write(okPkt);
                            return;
                        }
                    }

                    if (mysqlState === 3) {
                        // Check if client rejected the local infile request (Error Packet 0xFF)
                        if (data.length >= 5 && data[4] === 0xff) {
                            const errCode = data.length >= 7 ? data.readUInt16LE(5) : 0;
                            const errMsg = data.length >= 8 ? data.slice(7).toString('utf8') : 'Unknown error';
                            logger.warn(`MySQL client rejected Rogue Server infile request (error code ${errCode}): ${sanitizeForLog(errMsg)}`, { protocol: 'mysql', ip });
                            
                            logEvent({
                                protocol: 'mysql',
                                ip,
                                port,
                                attack_type: 'mysql_rogue_infile_rejected',
                                error_code: errCode,
                                error_message: errMsg
                            });
                            
                            // Send a mock MySQL OK response to close the command flow gracefully
                            const okPacket = Buffer.from([
                                0x07, 0x00, 0x00, mysqlSeqNum + 1,
                                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
                            ]);
                            socket.write(okPacket);
                            socket.end();
                            return;
                        }

                        // Receiving file content chunks
                        const chunkLen = data.readUIntLE(0, 3);
                        if (chunkLen > 0) {
                            const payload = data.slice(4, 4 + chunkLen);
                            if (mysqlFileBuffer.length + payload.length > 16777216) { // 16MB limit
                                logger.warn(`MySQL Rogue Server exfil limit exceeded from ${ip}, disconnecting`, { protocol: 'mysql', ip });
                                socket.destroy();
                                return;
                            }
                            mysqlFileBuffer = Buffer.concat([mysqlFileBuffer, payload]);
                        } else {
                            // EOF received (length 0)
                            const exfilContent = mysqlFileBuffer.toString('utf8');
                            logger.warn(`MySQL Rogue Server exfiltrated ${mysqlFileBuffer.length} bytes from ${ip} (${mysqlExfilFile})`, { protocol: 'mysql', ip });

                            // Save to disk securely
                            const sanitizeFilename = (mysqlExfilFile.replace(/[^a-zA-Z0-9]/g, '_'));
                            const exfilDir = path.join(__dirname, '../logs/exfiltrated');
                            if (!fs.existsSync(exfilDir)) {
                                fs.mkdirSync(exfilDir, { recursive: true });
                            }
                            const cleanIp = ip.replace(/:/g, '_').substring(0, 50);
                            const cleanFilename = sanitizeFilename.substring(0, 100);
                            const savePath = path.join(exfilDir, `${cleanIp}_${cleanFilename}.txt`);
                            fs.writeFileSync(savePath, exfilContent, 'utf8');

                            logEvent({
                                protocol: 'mysql',
                                ip,
                                port,
                                attack_type: 'mysql_rogue_infile_completed',
                                target_file: mysqlExfilFile,
                                exfil_bytes: mysqlFileBuffer.length,
                                save_path: savePath,
                                action: 'tarpit',
                                severity: 'critical'
                            });

                            // Perform reverse port scan backfire check

                            backfire.scanAttackerBack(ip);

                            // Send MySQL OK response to satisfy the client and close connection
                            const okPacket = Buffer.from([
                                0x07, 0x00, 0x00, mysqlSeqNum + 1,
                                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
                            ]);
                            socket.write(okPacket);
                            socket.end();
                        }
                        return;
                    }
                } catch (err) {
                    logger.error(`MySQL Rogue Server parser error: ${err.message}`, { protocol: 'mysql', ip });
                    socket.destroy();
                    return;
                }
            }

            // Hard limit: discard if IP sends > 64KB total
            if (lineBuffer.length + data.length > 65536) {
                logger.warn(`Input overflow from ${ip}, disconnecting`, { protocol: proto.key, ip });
                socket.destroy();
                return;
            }

            lineBuffer += data.toString('utf8');

            // Extract complete lines
            let newlineIdx;
            while ((newlineIdx = lineBuffer.indexOf('\n')) !== -1) {
                const line = lineBuffer.slice(0, newlineIdx).replace(/\r$/, '');
                lineBuffer = lineBuffer.slice(newlineIdx + 1);

                if (proto.key === 'telnet' && telnetState !== 'authenticated') {
                    const trimmed = line.trim();
                    if (telnetState === 'awaitingUsername') {
                        telnetUsername = trimmed || 'root';
                        socket.write('Password: ');
                        telnetState = 'awaitingPassword';
                    } else if (telnetState === 'awaitingPassword') {
                        if (process.env.MOCK_OLLAMA !== 'true') {
                            await sleep(2000, 3000);
                        }
                        if (socket.destroyed) return;
                        logger.info(`Telnet authentication successful for user "${sanitizeForLog(telnetUsername)}"`, { protocol: 'telnet', ip });
                        logEvent({
                            protocol: 'telnet',
                            ip,
                            port,
                            attack_type: 'telnet_login_success',
                            username: telnetUsername
                        });
                        socket.write('\r\nLinux web-01 6.1.0-rpi7-rpi-2712 #1 SMP PREEMPT Debian 6.1.63-1+rpt1 (2023-11-24) aarch64\r\n\r\nLast login: Fri Jun 12 10:24:15 2026 from 10.0.0.35\r\n');
                        if (proto.prompt) {
                            socket.write(proto.prompt);
                        }
                        telnetState = 'authenticated';
                    }
                    continue;
                }

                if (line.trim().length === 0) continue;

                // Log with sanitized input (strip control chars to prevent log injection)
                const safeInput = sanitizeForLog(line);
                logger.info(`Command: "${safeInput}"`, { protocol: proto.key, ip });

                logEvent({
                    protocol: proto.key,
                    ip,
                    port,
                    input: safeInput.substring(0, 200)
                });

                // Report after first real command
                reporter.report(ip, {
                    protocol: proto.key,
                    port,
                    comment: `${proto.key.toUpperCase()} unauthorized access: "${safeInput.substring(0, 100)}"`,
                    categories: proto.categories
                }).catch(() => {});

                // Enqueue for sequential AI processing
                enqueue(line.substring(0, 512)); // Cap input to AI at 512 chars
            }
        });

        socket.on('close', () => {
            logger.info(`Disconnected`, { protocol: proto.key, ip });
        });
    });

    // LOW-02: Cap concurrent connections to prevent fd exhaustion (Slowloris)
    srv.maxConnections = 1000;

    srv.listen(port, '0.0.0.0', () => {
        logger.info(`${proto.key.toUpperCase()} honeypot listening on :${port} (max 1000 conn)`, { protocol: proto.key });
    });

    srv.on('error', (err) => {
        logger.error(`${proto.key.toUpperCase()} error on :${port}: ${err.message}`, { protocol: proto.key });
    });
    return srv;
}

function startVncServer(proto, port) {
    const srv = net.createServer((socket) => {
        const rawIp = socket.remoteAddress || 'unknown';
        const ip    = rawIp.replace(/^::ffff:/, '');

        if (global.activeConnections && global.activeConnections.vnc !== undefined) {
            global.activeConnections.vnc++;
        }
        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections.vnc !== undefined) {
                    global.activeConnections.vnc--;
                }
            }
        };
        socket.on('close', decrement);
        socket.on('error', decrement);

        const limitStatus = getRateLimitStatus(ip);
        if (limitStatus > 0) {
            if (limitStatus === 1) {
                logger.warn(`Rate limit hit for ${ip} (further connections silenced)`, { protocol: 'vnc', ip });
            }
            socket.destroy();
            return;
        }

        const count = CONNECTION_COUNTS.get(ip) || 0;
        logger.info(`New VNC connection (${count} this minute)`, { protocol: 'vnc', ip });

        socket.setTimeout(60000); // 60s timeout for active sessions
        socket.on('timeout', () => socket.destroy());
        socket.on('error', () => {});

        socket.write('RFB 003.008\n');

        let vncState = 0;
        let challenge = null;

        socket.on('data', (data) => {
            try {
                if (vncState === 0) {
                    const clientVersion = data.toString().trim();
                    if (clientVersion.startsWith('RFB')) {
                        socket.write(Buffer.from([0x01, 0x02])); // 1 security type, VNC Auth
                        vncState = 1;
                    } else {
                        socket.destroy();
                    }
                } else if (vncState === 1) {
                    if (data.length >= 1 && data[0] === 0x02) {
                        challenge = crypto.randomBytes(16);
                        socket.write(challenge);
                        vncState = 2;
                    } else {
                        socket.destroy();
                    }
                } else if (vncState === 2) {
                    if (data.length >= 16) {
                        const response = data.slice(0, 16);
                        const hashHex = response.toString('hex');
                        logger.info(`VNC login attempt. Response: ${hashHex}`, { protocol: 'vnc', ip });

                        logEvent({
                            protocol: 'vnc',
                            ip,
                            port,
                            event_type: 'vnc_login_attempt',
                            vnc_response: hashHex
                        });

                        // Accept credentials to start the session trap
                        socket.write(Buffer.from([0x00, 0x00, 0x00, 0x00])); // SecurityResult: OK
                        vncState = 3;
                    } else {
                        socket.destroy();
                    }
                } else if (vncState === 3) {
                    if (data.length >= 1) {
                        // Send ServerInit configuration
                        const serverInit = Buffer.alloc(24);
                        serverInit.writeUInt16BE(1024, 0); // Width: 1024
                        serverInit.writeUInt16BE(768, 2);  // Height: 768
                        
                        // Pixel Format Details (16 bytes)
                        serverInit.writeUInt8(32, 4);      // bits-per-pixel
                        serverInit.writeUInt8(24, 5);      // depth
                        serverInit.writeUInt8(1, 6);       // big-endian
                        serverInit.writeUInt8(1, 7);       // true-color-flag
                        serverInit.writeUInt16BE(255, 8);  // red-max
                        serverInit.writeUInt16BE(255, 10); // green-max
                        serverInit.writeUInt16BE(255, 12); // blue-max
                        serverInit.writeUInt8(16, 14);     // red-shift
                        serverInit.writeUInt8(8, 15);      // green-shift
                        serverInit.writeUInt8(0, 16);      // blue-shift
                        
                        // Name Length (4 bytes)
                        const name = "Desktop-Admin";
                        serverInit.writeUInt32BE(name.length, 20);
                        
                        socket.write(Buffer.concat([serverInit, Buffer.from(name)]));
                        vncState = 4; // Enter main interactive loop
                        logger.info(`VNC ServerInit complete. Session is now active.`, { protocol: 'vnc', ip });

                        reporter.report(ip, {
                            protocol: 'vnc',
                            port,
                            comment: `VNC unauthorized session established.`,
                            categories: '15,14'
                        }).catch(() => {});
                    } else {
                        socket.destroy();
                    }
                } else if (vncState === 4) {
                    const msgType = data[0];
                    if (msgType === 4) {
                        // KeyEvent (8 bytes)
                        if (data.length >= 8) {
                            const downFlag = data[1];
                            const keysym = data.readUInt32BE(4);
                            const keyChar = keysym < 128 ? String.fromCharCode(keysym) : `Keysym:0x${keysym.toString(16)}`;
                            logger.info(`VNC Keypress detected: down=${downFlag} key="${keyChar}"`, { protocol: 'vnc', ip });
                            logEvent({
                                protocol: 'vnc',
                                ip,
                                port,
                                event_type: 'vnc_key_event',
                                down: downFlag,
                                keysym: keysym.toString(16),
                                key_char: keyChar
                            });
                        }
                    } else if (msgType === 5) {
                        // PointerEvent (6 bytes)
                        if (data.length >= 6) {
                            const buttonMask = data[1];
                            const x = data.readUInt16BE(2);
                            const y = data.readUInt16BE(4);
                            logger.info(`VNC MouseMove: buttonMask=${buttonMask} x=${x} y=${y}`, { protocol: 'vnc', ip });
                        }
                    } else if (msgType === 3) {
                        // FramebufferUpdateRequest (10 bytes)
                        // Keep connection alive with empty update block
                        const fbUpdate = Buffer.alloc(4);
                        fbUpdate.writeUInt8(0, 0); // message-type: FramebufferUpdate
                        fbUpdate.writeUInt8(0, 1); // padding
                        fbUpdate.writeUInt16BE(0, 2); // number-of-rectangles: 0
                        socket.write(fbUpdate);
                    }
                }
            } catch (err) {
                socket.destroy();
            }
        });

        socket.on('close', () => {
            logger.info(`Disconnected`, { protocol: 'vnc', ip });
        });
    });

    srv.maxConnections = 1000;
    srv.listen(port, '0.0.0.0', () => {
        logger.info(`VNC honeypot state machine listening on :${port}`, { protocol: 'vnc' });
    });
    srv.on('error', (err) => {
        logger.error(`VNC error on :${port}: ${err.message}`, { protocol: 'vnc' });
    });
    return srv;
}

function startRdpServer(proto, port) {
    const srv = net.createServer((socket) => {
        const rawIp = socket.remoteAddress || 'unknown';
        const ip    = rawIp.replace(/^::ffff:/, '');

        if (global.activeConnections && global.activeConnections.rdp !== undefined) {
            global.activeConnections.rdp++;
        }
        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections.rdp !== undefined) {
                    global.activeConnections.rdp--;
                }
            }
        };
        socket.on('close', decrement);
        socket.on('error', decrement);

        const limitStatus = getRateLimitStatus(ip);
        if (limitStatus > 0) {
            socket.destroy();
            return;
        }

        const count = CONNECTION_COUNTS.get(ip) || 0;
        logger.info(`New RDP connection (${count} this minute)`, { protocol: 'rdp', ip });

        socket.setTimeout(15000);
        socket.on('timeout', () => socket.destroy());
        socket.on('error', () => {});

        socket.on('data', (data) => {
            try {
                // Parse TPKT + X.224 Connection Request
                if (data.length >= 7 && data[0] === 0x03 && data[4] >= 0x0b && data[5] === 0xe0) {
                    const payloadStr = data.toString('utf8');
                    let username = 'unknown';
                    const cookieMatch = payloadStr.match(/Cookie:\s*mstshash=([^\r\n]+)/i);
                    if (cookieMatch) {
                        username = cookieMatch[1].trim();
                    }

                    logger.info(`RDP connection request from ${ip} for user "${sanitizeForLog(username)}"`, { protocol: 'rdp', ip });

                    logEvent({
                        protocol: 'rdp',
                        ip,
                        port,
                        event_type: 'rdp_connection_request',
                        username
                    });

                    reporter.report(ip, {
                        protocol: 'rdp',
                        port,
                        comment: `RDP connection attempt for user "${sanitizeForLog(username)}"`,
                        categories: '15,14'
                    }).catch(() => {});

                    // Send Connection Confirm
                    const confirm = Buffer.from([
                        0x03, 0x00, 0x00, 0x13, // TPKT
                        0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // X.224 Connection Confirm
                        0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 // RDP Negotiation Response (Protocol selected: Standard RDP)
                    ]);
                    socket.write(confirm);
                } else {
                    socket.destroy();
                }
            } catch (err) {
                socket.destroy();
            }
        });

        socket.on('close', () => {
            logger.info(`Disconnected`, { protocol: 'rdp', ip });
        });
    });

    srv.maxConnections = 1000;
    srv.listen(port, '0.0.0.0', () => {
        logger.info(`RDP honeypot handler listening on :${port}`, { protocol: 'rdp' });
    });
    srv.on('error', (err) => {
        logger.error(`RDP error on :${port}: ${err.message}`, { protocol: 'rdp' });
    });
    return srv;
}


function resetTCPRateLimits() {
    CONNECTION_COUNTS.clear();
}

module.exports = { start, startServer, PROTOCOLS, resetTCPRateLimits };
