/**
 * HoneyAI — SNMP UDP Honeypot
 * Emulates a basic SNMP daemon, parses SNMP requests using a native BER parser, and alerts.
 */

'use strict';

const dgram = require('dgram');
const config = require('../core/config');
const loggerModule = require('../core/logger');
const reporter = require('../core/reporter');
const backfire = require('../core/backfire');

let socket = null;

function readBerLength(buffer, pos) {
    let len = buffer[pos++];
    if (len & 0x80) {
        const bytesCount = len & 0x7F;
        len = 0;
        for (let i = 0; i < bytesCount; i++) {
            if (pos >= buffer.length) break;
            len = (len << 8) | buffer[pos++];
        }
    }
    return { length: len, newPos: pos };
}

function decodeOid(buffer) {
    if (buffer.length === 0) return '';
    const parts = [];
    const first = buffer[0];
    parts.push(Math.floor(first / 40));
    parts.push(first % 40);

    let val = 0;
    for (let i = 1; i < buffer.length; i++) {
        const b = buffer[i];
        val = (val << 7) | (b & 0x7F);
        if (!(b & 0x80)) {
            parts.push(val);
            val = 0;
        }
    }
    return parts.join('.');
}

function encodeBerLength(len) {
    if (len < 128) {
        return Buffer.from([len]);
    }
    const bytes = [];
    let temp = len;
    while (temp > 0) {
        bytes.unshift(temp & 0xFF);
        temp = temp >> 8;
    }
    return Buffer.concat([
        Buffer.from([0x80 | bytes.length]),
        Buffer.from(bytes)
    ]);
}

function buildTlv(tag, valueBuffer) {
    const lenBuf = encodeBerLength(valueBuffer.length);
    return Buffer.concat([Buffer.from([tag]), lenBuf, valueBuffer]);
}

function buildSnmpResponse(parseResult, responseValue = "Debian GNU/Linux 12 (bookworm) Linux 6.1.0-rpi7") {
    const { versionBytes, communityBytes, requestIdBytes, oidBytesList } = parseResult;
    if (!oidBytesList || oidBytesList.length === 0) return null;
    
    const varbinds = [];
    for (const oidBytes of oidBytesList) {
        const valBuf = buildTlv(0x04, Buffer.from(responseValue)); // Value: OCTET STRING
        const varbind = buildTlv(0x30, Buffer.concat([buildTlv(0x06, oidBytes), valBuf]));
        varbinds.push(varbind);
    }
    const varbindList = buildTlv(0x30, Buffer.concat(varbinds));

    const errStatus = buildTlv(0x02, Buffer.from([0]));
    const errIndex = buildTlv(0x02, Buffer.from([0]));
    const reqId = buildTlv(0x02, requestIdBytes);
    
    const pduBody = Buffer.concat([reqId, errStatus, errIndex, varbindList]);
    const pdu = buildTlv(0xa2, pduBody); // 0xa2 is GetResponse PDU

    const versionVal = buildTlv(0x02, versionBytes);
    const communityVal = buildTlv(0x04, communityBytes);
    
    return buildTlv(0x30, Buffer.concat([versionVal, communityVal, pdu]));
}

function parseSnmp(buffer) {
    try {
        let pos = 0;
        
        // 1. Read Outer Sequence
        if (buffer[pos++] !== 0x30) return null;
        let len = readBerLength(buffer, pos);
        pos = len.newPos;

        // 2. Read SNMP Version
        if (buffer[pos++] !== 0x02) return null;
        const verLen = buffer[pos++];
        const versionBytes = buffer.slice(pos, pos + verLen);
        const version = buffer.readUIntBE(pos, verLen);
        pos += verLen;

        // 3. Read Community String
        if (buffer[pos++] !== 0x04) return null;
        const commLen = buffer[pos++];
        if (pos + commLen > buffer.length) return null;
        const communityBytes = buffer.slice(pos, pos + commLen);
        const community = buffer.toString('utf8', pos, pos + commLen);
        pos += commLen;

        // 4. Read PDU
        const pduType = buffer[pos++];
        if ((pduType & 0xE0) !== 0xA0) {
            return null;
        }
        let pduLen = readBerLength(buffer, pos);
        pos = pduLen.newPos;

        // 5. Read Request ID
        if (buffer[pos++] !== 0x02) return null;
        let reqIdLen = buffer[pos++];
        const requestIdBytes = buffer.slice(pos, pos + reqIdLen);
        pos += reqIdLen;

        // 6. Read Error Status
        if (buffer[pos++] !== 0x02) return null;
        pos += buffer[pos++] + 1;

        // 7. Read Error Index
        if (buffer[pos++] !== 0x02) return null;
        pos += buffer[pos++] + 1;

        // 8. Read Varbind List Sequence
        if (buffer[pos++] !== 0x30) return null;
        let varbindListLen = readBerLength(buffer, pos);
        pos = varbindListLen.newPos;

        const requests = [];
        const oidBytesList = [];
        // Loop over varbinds
        while (pos < buffer.length) {
            if (buffer[pos++] !== 0x30) break;
            let varbindLen = readBerLength(buffer, pos);
            let varbindEnd = varbindLen.newPos + varbindLen.length;
            pos = varbindLen.newPos;

            // Read OID
            if (buffer[pos++] !== 0x06) break;
            const oidLen = buffer[pos++];
            if (pos + oidLen > buffer.length) break;
            const oidBytes = buffer.slice(pos, pos + oidLen);
            const oid = decodeOid(oidBytes);
            if (oid) {
                requests.push(oid);
                oidBytesList.push(oidBytes);
            }

            pos = varbindEnd;
        }

        return { community, requests, version, versionBytes, communityBytes, requestIdBytes, oidBytesList };
    } catch (err) {
        return null;
    }
}

function start(customPort) {
    const cfg = config.protocols.snmp;
    if (!cfg?.enabled && !customPort) return;

    const port = customPort || cfg.port || 161;

    socket = dgram.createSocket('udp4');

    socket.on('message', (msg, rinfo) => {
        const ip = rinfo.address.replace(/^::ffff:/, '');
        const parseResult = parseSnmp(msg);

        if (global.activeConnections && global.activeConnections.snmp !== undefined) {
            global.activeConnections.snmp++;
            setTimeout(() => {
                if (global.activeConnections && global.activeConnections.snmp !== undefined) {
                    global.activeConnections.snmp--;
                }
            }, 1000);
        }

        if (parseResult) {
            const { community, requests, version } = parseResult;
            const oidsStr = requests.length ? requests.join(', ') : 'none';
            loggerModule.logger.warn(`SNMP request from ${ip}: community="${community}" version=${version} OIDs=[${oidsStr}]`, { protocol: 'snmp', ip });

            const respBuf = buildSnmpResponse(parseResult);
            if (respBuf && socket) {
                socket.send(respBuf, rinfo.port, rinfo.address, (err) => {
                    if (err) {
                        loggerModule.logger.error(`Failed to send SNMP response to ${ip}: ${err.message}`, { protocol: 'snmp', ip });
                    }
                });
            }

            loggerModule.logEvent({
                protocol: 'snmp',
                ip,
                port,
                community,
                version,
                oids: requests,
                attack_type: 'snmp_request'
            });

            reporter.report(ip, {
                protocol: 'snmp',
                port,
                comment: `SNMP query: community="${community}", version=${version}, OIDs=[${oidsStr}]`
            }).catch(() => {});
        } else {
            loggerModule.logger.warn(`Malformed/raw SNMP request from ${ip}`, { protocol: 'snmp', ip });
            loggerModule.logEvent({
                protocol: 'snmp',
                ip,
                port,
                attack_type: 'snmp_probe'
            });

            reporter.report(ip, {
                protocol: 'snmp',
                port,
                comment: `Raw/malformed SNMP connection or packet`
            }).catch(() => {});
        }

        backfire.scanAttackerBack(ip);
    });

    socket.on('error', (err) => {
        loggerModule.logger.error(`SNMP UDP socket error: ${err.message}`, { protocol: 'snmp' });
    });

    socket.bind(port, '0.0.0.0', () => {
        loggerModule.logger.info(`SNMP UDP honeypot listening on :${port}`, { protocol: 'snmp' });
    });
}

function stop() {
    if (socket) {
        try { socket.close(); } catch (_) {}
        socket = null;
    }
}

module.exports = { start, stop, parseSnmp, decodeOid, buildSnmpResponse, encodeBerLength, buildTlv };
