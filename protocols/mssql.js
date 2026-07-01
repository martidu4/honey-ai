/**
 * HoneyAI — MSSQL Honeypot
 * Emulates Microsoft SQL Server TDS protocol pre-login handshake and login authentication.
 */

'use strict';

const net = require('net');
const config = require('../core/config');
const loggerModule = require('../core/logger');
const reporter = require('../core/reporter');
const backfire = require('../core/backfire');

let server = null;

function decryptTdsPassword(buf) {
    const dec = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        // XOR with 0xA5
        const x = b ^ 0xA5;
        // Swap high and low nibble
        dec[i] = ((x & 0x0F) << 4) | ((x & 0xF0) >> 4);
    }
    return dec.toString('utf16le');
}

function start(customPort) {
    const cfg = config.protocols.mssql;
    if (!cfg?.enabled && !customPort) return;

    const port = customPort || cfg.port || 1433;

    server = net.createServer((socket) => {
        const rawIp = socket.remoteAddress || 'unknown';
        const ip = rawIp.replace(/^::ffff:/, '');

        if (global.activeConnections && global.activeConnections.mssql !== undefined) {
            global.activeConnections.mssql++;
        }

        let decremented = false;
        const decrement = () => {
            if (!decremented) {
                decremented = true;
                if (global.activeConnections && global.activeConnections.mssql !== undefined) {
                    global.activeConnections.mssql--;
                }
            }
        };

        socket.on('close', decrement);
        socket.on('error', decrement);

        socket.setTimeout(30000); // 30 second timeout
        socket.on('timeout', () => socket.destroy());

        socket.on('data', (data) => {
            if (data.length < 8) {
                socket.destroy();
                return;
            }

            const packetType = data[0];

            if (packetType === 0x12) {
                // TDS Pre-Login Packet
                loggerModule.logger.info(`TDS Pre-Login handshake request from ${ip}`, { protocol: 'mssql', ip });

                // Respond with SQL Server 2012 Pre-Login response
                const response = Buffer.from('0401002500000100000015000601001b000102001c000103001d0000ff0b000c38', 'hex');
                socket.write(response);
            } else if (packetType === 0x10) {
                // TDS Login7 Packet
                const payloadOffset = 8;
                if (data.length >= payloadOffset + 50) {
                    try {
                        const hostOffset = data.readUInt16LE(payloadOffset + 36);
                        const hostLen = data.readUInt16LE(payloadOffset + 38);
                        const userOffset = data.readUInt16LE(payloadOffset + 40);
                        const userLen = data.readUInt16LE(payloadOffset + 42);
                        const passOffset = data.readUInt16LE(payloadOffset + 44);
                        const passLen = data.readUInt16LE(payloadOffset + 46);

                        let hostName = '';
                        let userName = '';
                        let password = '';

                        const safeReadUtf16 = (offset, lenChar) => {
                            const start = payloadOffset + offset;
                            const end = start + lenChar * 2;
                            if (start >= 0 && end <= data.length) {
                                return data.toString('utf16le', start, end);
                            }
                            return '';
                        };

                        hostName = safeReadUtf16(hostOffset, hostLen);
                        userName = safeReadUtf16(userOffset, userLen);

                        const passStart = payloadOffset + passOffset;
                        const passEnd = passStart + passLen * 2;
                        if (passStart >= 0 && passEnd <= data.length) {
                            const passBuf = data.slice(passStart, passEnd);
                            password = decryptTdsPassword(passBuf);
                        }

                        // Redact password in console logs (full value kept in events.json for intel)
                        const safePass = password ? password.substring(0, 2) + '***' : '<empty>';
                        loggerModule.logger.warn(`MSSQL auth attempt user="${userName}" pass="${safePass}" host="${hostName}"`, { protocol: 'mssql', ip });

                        loggerModule.logEvent({
                            protocol: 'mssql',
                            ip,
                            port,
                            username: userName,
                            password,
                            hostname: hostName,
                            attack_type: 'mssql_login_attempt'
                        });

                        reporter.report(ip, {
                            protocol: 'mssql',
                            port,
                            comment: `MSSQL authentication attempt: user="${userName}" host="${hostName}"`
                        }).catch(() => {});

                        backfire.scanAttackerBack(ip);

                    } catch (err) {
                        loggerModule.logger.error(`Error parsing TDS Login7 packet: ${err.message}`, { protocol: 'mssql', ip });
                    }
                }

                // Send Login Failed Error 18456 Response
                const errResponse = Buffer.from('0401001700000100aa0c0018480000010e000000000000', 'hex');
                socket.write(errResponse);
                socket.end();
            } else {
                // Unknown/Unexpected packet type
                socket.destroy();
            }
        });
    });

    server.maxConnections = 1000;
    server.listen(port, '0.0.0.0', () => {
        loggerModule.logger.info(`MSSQL honeypot listening on :${port}`, { protocol: 'mssql' });
    });
}

function stop() {
    if (server) {
        try { server.close(); } catch (_) {}
        server = null;
    }
}

module.exports = { start, stop, decryptTdsPassword };
