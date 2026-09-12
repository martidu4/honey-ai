/**
 * HoneyAI — Unified Logger
 * Logs to console (colored) + file (JSON lines for easy parsing)
 */

const winston = require('winston');
const fs      = require('fs');
const path    = require('path');
const config  = require('./config');

const logsDir = path.dirname(config.logging.file);
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const { combine, timestamp, printf, colorize } = winston.format;

const consoleFormat = printf(({ level, message, timestamp, protocol, ip }) => {
    const proto = protocol ? `[${protocol.toUpperCase()}]` : '';
    const src   = ip ? ` ${ip}` : '';
    return `${timestamp} ${level} ${proto}${src} ${message}`;
});

const logger = winston.createLogger({
    level: config.logging.level || 'info',
    transports: [
        // Console — human readable
        new winston.transports.Console({
            format: combine(
                colorize(),
                timestamp({ format: 'HH:mm:ss' }),
                consoleFormat
            )
        }),
        // Main log file — plain text
        new winston.transports.File({
            filename: config.logging.file,
            format: combine(timestamp(), winston.format.json()),
            maxsize: 50 * 1024 * 1024, // 50MB
            maxFiles: 5,
            tailable: true
        })
    ]
});

// Events file — JSONL, one attack event per line (like Galah's event_log.json)
const eventsFile = config.logging.events_file;
const eventsDir  = path.dirname(eventsFile);
if (!fs.existsSync(eventsDir)) fs.mkdirSync(eventsDir, { recursive: true });

// HIGH-03: Async write stream with rotation (prevents DoS via disk fill)
const MAX_EVENTS_SIZE = 100 * 1024 * 1024; // 100MB
// Rotation used to rename and never delete, so logs/ just grew: two 100MB
// leftovers from July and August were still sitting there. Keep a bounded
// number of rotations, like the winston File transport already does.
const MAX_EVENTS_FILES = 3;

function pruneRotatedEvents() {
    try {
        const dir  = path.dirname(eventsFile);
        const base = path.basename(eventsFile) + '.';
        const old  = fs.readdirSync(dir)
            .filter(f => f.startsWith(base) && /\.\d+$/.test(f))
            .sort()          // suffix is Date.now(), so lexical == chronological
            .slice(0, -MAX_EVENTS_FILES);
        for (const f of old) {
            try {
                fs.unlinkSync(path.join(dir, f));
                logger.info(`Pruned old events log ${f}`, { protocol: 'core' });
            } catch (_) {}
        }
    } catch (_) {}
}
let eventsStream = fs.createWriteStream(eventsFile, { flags: 'a' });
let currentEventsSize = fs.existsSync(eventsFile) ? fs.statSync(eventsFile).size : 0;

eventsStream.on('error', (err) => {
    logger.error(`Events stream error: ${err.message}`);
});

function logEvent(event) {
    // MED #10: Validate event keys against allowlist to prevent log injection
    const { sanitizeEventKeys } = require('./utils');
    const clean = sanitizeEventKeys(event);
    const line = JSON.stringify({
        timestamp: new Date().toISOString(),
        ...clean
    }) + '\n';

    currentEventsSize += Buffer.byteLength(line);

    // Rotate when file exceeds 100MB
    if (currentEventsSize > MAX_EVENTS_SIZE) {
        const oldStream = eventsStream;
        try {
            const rotated = eventsFile + '.' + Date.now();
            fs.renameSync(eventsFile, rotated);
        } catch (_) {}
        eventsStream = fs.createWriteStream(eventsFile, { flags: 'a' });
        eventsStream.on('error', (err) => logger.error(`Events stream error: ${err.message}`));
        currentEventsSize = 0;
        oldStream.end();
        pruneRotatedEvents();
    }

    eventsStream.write(line); // Async — does NOT block the event loop
}

function sanitizeForLog(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/[\r\n\t]/g, ' ')                    // CRLF / tab injection
        .replace(/[\x00-\x1f\x7f-\x9f]/g, '?')       // control chars / ANSI escape sequences
        .substring(0, 512);                          // length limit
}

module.exports = { logger, logEvent, sanitizeForLog };
