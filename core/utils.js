/**
 * HoneyAI — Security Utilities
 * Shared helpers for safe regex, IP normalization, and input validation.
 */

'use strict';

const vm = require('vm');

// ─── CRIT #3: Safe Regex Execution with Timeout ──────────────────────────────
// Custom command regexes are admin-defined in config.yaml.
// Even trusted input can contain exponential patterns like (a+)+$.
// vm.runInNewContext with timeout prevents ReDoS from hanging the event loop.

/**
 * Execute a regex test with a timeout to prevent ReDoS.
 * @param {string} pattern - Regex pattern string
 * @param {string} input - String to test against
 * @param {number} timeoutMs - Max execution time (default 100ms)
 * @returns {{ match: boolean, groups: string[]|null }} Result or { match: false } on timeout
 */
function safeRegexMatch(pattern, input, timeoutMs = 100) {
    try {
        if (pattern.length > 200) return { match: false, groups: null };
        const ctx = vm.createContext({ p: pattern, i: input });
        const result = vm.runInNewContext(
            '(function() { const m = i.match(new RegExp(p, "i")); return m ? Array.from(m) : null; })()',
            ctx,
            { timeout: timeoutMs }
        );
        if (result) {
            return { match: true, groups: result };
        }
        return { match: false, groups: null };
    } catch (_) {
        // Timeout or regex error → no match, no crash
        return { match: false, groups: null };
    }
}

// ─── #9: IPv6 /64 Rate Limiting ──────────────────────────────────────────────
// Full IPv6 addresses allow attackers to rotate through /64 prefix (~18 quintillion IPs).
// Rate limiters should key by /64 prefix for IPv6, or full address for IPv4.

/**
 * Normalize an IP address for rate limiting.
 * IPv4: strips ::ffff: mapped prefix, returns full address.
 * IPv6: masks to /64 prefix to prevent rotation attacks.
 * Loopback/link-local: preserved as-is (no masking needed).
 * @param {string} rawIp
 * @returns {string}
 */
function normalizeIP(rawIp) {
    if (!rawIp) return 'unknown';
    let ip = rawIp.replace(/^::ffff:/, '');
    
    // Strip IPv6 zone ID (fe80::1%eth0, fe80::1%25eth0)
    ip = ip.replace(/%.*$/, '');
    
    // IPv4 after stripping mapped prefix
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return ip;
    
    // Special IPv6 addresses — no masking needed
    if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:0' || ip === '0:0:0:0:0:0:0:1') return ip;
    
    // IPv6: fully expand, then take first 4 groups (/64)
    if (ip.includes(':')) {
        // Split on ::
        const halves = ip.split('::');
        let groups;
        if (halves.length === 2) {
            // Expand :: shorthand
            const left = halves[0] ? halves[0].split(':') : [];
            const right = halves[1] ? halves[1].split(':') : [];
            const missing = 8 - left.length - right.length;
            groups = [...left, ...Array(missing).fill('0'), ...right];
        } else {
            groups = ip.split(':');
        }
        // Pad to 8 groups
        while (groups.length < 8) groups.push('0');
        // Take first 4 groups = /64 prefix
        return groups.slice(0, 4).join(':') + '::';
    }
    
    return ip;
}

// ─── #10: Log Event Key Validation ───────────────────────────────────────────
// Allowlist of valid event keys to prevent log structure corruption.

const VALID_EVENT_KEYS = new Set([
    'protocol', 'ip', 'port', 'command', 'method', 'path', 'user_agent',
    'attack_type', 'username', 'password_hash', 'auth_method', 'response_bytes',
    'cache_hit', 'mode', 'input', 'hostname', 'data', 'comment', 'service',
    'oid', 'version', 'community', 'query', 'redirect_url', 'status_code',
    'alert', 'session_id', 'tool_name', 'resource_uri', 'headers'
]);

/**
 * Sanitize event object keys against allowlist.
 * Unknown keys are stripped to prevent log injection via attacker-controlled fields.
 * @param {object} event
 * @returns {object} Sanitized event
 */
function sanitizeEventKeys(event) {
    const clean = {};
    const dropped = [];
    for (const [key, value] of Object.entries(event)) {
        if (VALID_EVENT_KEYS.has(key)) {
            clean[key] = value;
        } else {
            dropped.push(key);
        }
    }
    if (dropped.length > 0) {
        // Lazy-require to avoid circular dependency (logger → utils → logger)
        try {
            const { logger } = require('./logger');
            logger.debug(`Event keys dropped by allowlist: ${dropped.join(', ')}`, { protocol: clean.protocol || 'unknown' });
        } catch (_) {}
    }
    return clean;
}

module.exports = {
    safeRegexMatch,
    normalizeIP,
    sanitizeEventKeys,
    VALID_EVENT_KEYS
};
