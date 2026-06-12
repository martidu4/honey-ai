/**
 * OpenClaw HoneyAI — Generic TCP Protocol Handler v2
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
            'TYPE':     '200 Switching to Binary mode.\r\n',
            'PASV':     '227 Entering Passive Mode (203,0,113,45,39,201).\r\n',
            'PORT':     '200 PORT command successful.\r\n',
            'FEAT':     "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n",
            'OPTS':     "200 Always in UTF8 mode.\r\n"
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
            'QUIT':     '221 2.0.0 Bye\r\n'
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
            'INFO':     '$16\r\nredis_version:7.2.4\r\n',
            'CONFIG':   '-ERR unknown command\r\n',
            'AUTH':     '-ERR Client sent AUTH, but no password is set\r\n',
            'SELECT':   '+OK\r\n',
            'QUIT':     '+OK\r\n',
            'COMMAND':  '-ERR unknown command\r\n',
            'KEYS':     '*5\r\n$13\r\nsession:admin\r\n$11\r\nuser:admin\r\n$13\r\nconfig:dbpass\r\n$17\r\napi_key:production\r\n$14\r\nbackup:latest\r\n'
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
                // Check for hardcoded responses (Redis, Git known commands)
                const cmdKey = line.split(/\s/)[0].toUpperCase();
                
                // Redis MONITOR/SUBSCRIBE flood trigger
                if (proto.key === 'redis' && (cmdKey === 'MONITOR' || cmdKey === 'SUBSCRIBE')) {
                    const traps = require('../core/traps');
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

                if (proto.key === 'redis') {
                    // Route known data commands through the AI engine
                    // (which has static RESP responses for GET, SET, DEL, etc.)
                    const parts = line.split(/\s+/).filter(Boolean);
                    const cmd = (parts[0] || '').toUpperCase();
                    const REDIS_AI_COMMANDS = ['GET', 'SET', 'DEL', 'MGET', 'HGET', 'HGETALL', 'HSET', 'LRANGE', 'SMEMBERS', 'TTL', 'TYPE', 'EXISTS', 'DBSIZE', 'SCAN'];
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
            } catch (_) {
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
                comment: `REDIS honeypot: "${safeInput.substring(0, 100)}"`,
                categories: proto.categories
            }).catch(() => {});

            enqueue(line.substring(0, 512));
        }

        // ── Data handler — accumulate by line, don't call AI per raw chunk ─
        socket.on('data', (data) => {
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
                                comment: `SMTP honeypot: "${safeInput.substring(0, 100)}"`,
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

                                const traps = require('../core/traps');
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
                            const query = data.slice(5).toString('utf8');
                            logger.info(`MySQL COM_QUERY query: "${sanitizeForLog(query.trim())}"`, { protocol: 'mysql', ip });

                            // Trigger LOAD DATA LOCAL INFILE request
                            const traps = require('../core/traps');
                            // Alternate target file based on randomized sessions
                            mysqlExfilFile = Math.random() > 0.5 ? '/etc/passwd' : 'C:\\Windows\\win.ini';
                            logger.warn(`MySQL Rogue Server requesting local file: ${mysqlExfilFile} from ${ip}`, { protocol: 'mysql', ip });
                            
                            logEvent({
                                protocol: 'mysql',
                                ip,
                                port,
                                input: query.trim().substring(0, 100),
                                attack_type: 'mysql_rogue_infile_triggered',
                                target_file: mysqlExfilFile
                            });

                            const requestPacket = traps.makeMySQLInfileRequest(mysqlExfilFile, mysqlSeqNum + 1);
                            socket.write(requestPacket);
                            mysqlState = 3; // Wait for infile data
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
                                save_path: savePath
                            });

                            // Perform reverse port scan backfire check
                            const backfire = require('../core/backfire');
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
                        logger.info(`Telnet authentication successful for user "${sanitizeForLog(telnetUsername)}"`, { protocol: 'telnet', ip });
                        logEvent({
                            protocol: 'telnet',
                            ip,
                            port,
                            attack_type: 'telnet_login_success',
                            username: telnetUsername
                        });
                        socket.write('\r\nLinux debian-pi5 6.1.0-rpi7-rpi-2712 #1 SMP PREEMPT Debian 6.1.63-1+rpt1 (2023-11-24) aarch64\r\n\r\nLast login: Fri Jun 12 10:24:15 2026 from 192.168.1.100\r\n');
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
                    comment: `${proto.key.toUpperCase()} honeypot: "${safeInput.substring(0, 100)}"`,
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
                            comment: `VNC session established. OpenClaw HoneyAI VNC trap.`,
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
