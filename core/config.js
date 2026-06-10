/**
 * OpenClaw HoneyAI — Core Config Loader
 * Merges config.yaml with env vars. Env vars always win.
 */

const fs   = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const CONFIG_FILE = path.join(__dirname, '..', 'config.yaml');
const EXAMPLE     = path.join(__dirname, '..', 'config.example.yaml');

function load() {
    let raw = {};

    // Load YAML config
    const src = fs.existsSync(CONFIG_FILE) ? CONFIG_FILE : EXAMPLE;
    try {
        raw = yaml.load(fs.readFileSync(src, 'utf8'));
    } catch (e) {
        console.error('[config] Failed to parse config.yaml:', e.message);
        process.exit(1);
    }

    // Env var overrides (set by `pnpm run setup` → .env)
    const r = raw.reporting || {};
    const n = raw.notifications || {};

    const abuseipdbKey = process.env.ABUSEIPDB_KEY || process.env.ABUSEIPDB_API_KEY;
    const otxKey = process.env.OTX_KEY || process.env.OTX_API_KEY;
    const dshieldKey = process.env.DSHIELD_KEY || process.env.DSHIELD_API_KEY;
    const blocklistKey = process.env.BLOCKLIST_KEY || process.env.BLOCKLIST_DE_KEY;
    const blocklistEmail = process.env.BLOCKLIST_DE_EMAIL;
    const vtKey = process.env.VT_KEY || process.env.VIRUSTOTAL_KEY;
    const telegramToken = process.env.TELEGRAM_TOKEN;
    const telegramChat = process.env.TELEGRAM_CHAT || process.env.TELEGRAM_CHAT_ID;
    
    if (abuseipdbKey)  setNested(raw, 'reporting.abuseipdb.api_key', abuseipdbKey);
    if (otxKey)        setNested(raw, 'reporting.otx.api_key', otxKey);
    if (process.env.OTX_SSH_PULSE_ID) setNested(raw, 'reporting.otx.ssh_pulse_id', process.env.OTX_SSH_PULSE_ID);
    if (process.env.OTX_PULSE_ID)     setNested(raw, 'reporting.otx.http_pulse_id', process.env.OTX_PULSE_ID);
    if (dshieldKey)    setNested(raw, 'reporting.dshield.api_key', dshieldKey);
    if (process.env.DSHIELD_USER_ID)  setNested(raw, 'reporting.dshield.user_id', process.env.DSHIELD_USER_ID);
    if (blocklistKey)  setNested(raw, 'reporting.blocklist_de.api_key', blocklistKey);
    if (blocklistEmail) setNested(raw, 'reporting.blocklist_de.email', blocklistEmail);
    if (vtKey)         setNested(raw, 'reporting.virustotal.api_key', vtKey);
    if (telegramToken) setNested(raw, 'notifications.telegram.bot_token', telegramToken);
    if (telegramChat)  setNested(raw, 'notifications.telegram.chat_id', telegramChat);
    if (process.env.OLLAMA_URL)     setNested(raw, 'ai.url', process.env.OLLAMA_URL);
    if (process.env.AI_MODEL)       setNested(raw, 'ai.model', process.env.AI_MODEL);

    // Auto-enable platforms when keys are present
    const rep = raw.reporting;
    if (rep.abuseipdb.api_key)  rep.abuseipdb.enabled  = true;
    if (rep.otx.api_key)        rep.otx.enabled         = true;
    if (rep.dshield.api_key)    rep.dshield.enabled     = true;
    if (rep.blocklist_de.api_key) rep.blocklist_de.enabled = true;
    if (rep.virustotal.api_key) rep.virustotal.enabled  = true;

    return raw;
}

function setNested(obj, path, value) {
    const parts = path.split('.');
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!cur[parts[i]]) cur[parts[i]] = {};
        cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = value;
}

module.exports = load();
