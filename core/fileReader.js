/**
 * OpenClaw HoneyAI — Efficient File Reader
 * Reads last N lines from the end of a file using backward chunk seeking.
 * Prevents memory issues and event loop blocking on huge log files.
 */

'use strict';

const fs = require('fs');

/**
 * Reads the last maxLines lines from the given file path synchronously.
 * @param {string} filePath
 * @param {number} maxLines
 * @returns {string[]} Array of lines (oldest first)
 */
function readLastLinesSync(filePath, maxLines) {
    if (maxLines <= 0) return [];

    const CHUNK_SIZE = 64 * 1024; // 64KB chunks
    let fd;
    try {
        fd = fs.openSync(filePath, 'r');
    } catch (err) {
        return [];
    }

    try {
        const stat = fs.fstatSync(fd);
        let size = stat.size;
        if (size === 0) return [];

        let buffer = Buffer.alloc(CHUNK_SIZE);
        let lines = [];
        let leftOver = '';
        let offset = size;

        while (offset > 0 && lines.length < maxLines) {
            const bytesToRead = Math.min(offset, CHUNK_SIZE);
            offset -= bytesToRead;

            fs.readSync(fd, buffer, 0, bytesToRead, offset);
            const chunkStr = buffer.toString('utf8', 0, bytesToRead) + leftOver;
            const chunkLines = chunkStr.split('\n');
            
            if (offset > 0) {
                // Keep the first line of the chunk as leftOver since it might be incomplete
                leftOver = chunkLines.shift();
            } else {
                leftOver = '';
            }

            // Iterate backwards through the lines of this chunk
            for (let i = chunkLines.length - 1; i >= 0; i--) {
                const line = chunkLines[i].trim();
                if (line) {
                    lines.push(line);
                    if (lines.length >= maxLines) {
                        break;
                    }
                }
            }
        }

        if (leftOver.trim() && lines.length < maxLines) {
            lines.push(leftOver.trim());
        }

        // Reverse to return oldest first
        return lines.reverse();
    } catch (err) {
        return [];
    } finally {
        try {
            fs.closeSync(fd);
        } catch (_) {}
    }
}

module.exports = {
    readLastLinesSync
};
