/**
 * HoneyAI — Jitter & Latency Injection Utility
 */

'use strict';

/**
 * Returns a promise that resolves after a random delay between min and max milliseconds.
 * @param {number} minMs 
 * @param {number} maxMs 
 * @returns {Promise<void>}
 */
function sleep(minMs, maxMs = minMs) {
    const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Helper to write text to a stream with simulated typing speed (character-by-character).
 * @param {any} stream 
 * @param {string} text 
 * @param {number} minDelayMs 
 * @param {number} maxDelayMs 
 */
async function writeWithJitter(stream, text, minDelayMs = 10, maxDelayMs = 40) {
    if (!text) return;
    for (let i = 0; i < text.length; i++) {
        if (stream.destroyed || stream.writableEnded) break;
        stream.write(text[i]);
        await sleep(minDelayMs, maxDelayMs);
    }
}

module.exports = {
    sleep,
    writeWithJitter
};
