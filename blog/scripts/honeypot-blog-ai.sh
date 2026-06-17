#!/usr/bin/env bash
# =============================================================================
# honeypot-blog-ai.sh — Generates AI threat analysis blog post
# Runs AFTER honeypot-publish.sh (which generates the data report .md)
# Uses local Ollama model to write the blog post
# =============================================================================
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
source /opt/honeyai/scripts/.env

# === CONFIG ===
TODAY="${TODAY:-$(date '+%Y-%m-%d')}"
BLOG_DIR="/mnt/ssd/www/honeypot-blog"
REPORT_FILE="${BLOG_DIR}/src/content/reports/${TODAY}.md"
BLOG_FILE="${BLOG_DIR}/src/content/blog/${TODAY}.md"
LOG="/opt/honeyai/scripts/honeypot-publish.log"
OLLAMA_MODEL="qwen2.5:1.5b"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] BLOG-AI: $1" >> "$LOG" 2>/dev/null || true; }

log "=== AI BLOG GENERATION START ==="

# Check report exists
if [[ ! -f "$REPORT_FILE" ]]; then
    log "ERROR: Report not found: $REPORT_FILE — run honeypot-publish.sh first"
    exit 1
fi

# Don't regenerate if blog already exists
if [[ -f "$BLOG_FILE" ]]; then
    log "Blog post already exists: $BLOG_FILE — skipping"
    exit 0
fi

# Ensure blog content directory exists
mkdir -p "${BLOG_DIR}/src/content/blog"

# === Extract data from report frontmatter ===
FRONTMATTER=$(sed -n '/^---$/,/^---$/p' "$REPORT_FILE" | sed '1d;$d')

get_val() { echo "$FRONTMATTER" | grep "^${1}:" | head -1 | cut -d: -f2- | tr -d ' ' || echo "0"; }

COWRIE_CONN=$(get_val cowrie_connections)
COWRIE_LOGINS=$(get_val cowrie_logins)
COWRIE_CMDS=$(get_val cowrie_commands)
COWRIE_IPS=$(get_val cowrie_ips)
OC_EVENTS=$(get_val opencanary_events)
OC_IPS=$(get_val opencanary_ips)
GALAH_REQ=$(get_val galah_requests)
GALAH_IPS=$(get_val galah_ips)
SEVERITY=$(get_val severity)
ABUSE_REPORTED=$(get_val abuseipdb_reported)
CANARY_TRIGGERS=$(get_val canarytoken_triggers)
SURI_ALERTS=$(get_val suricata_alerts)
SURI_IPS=$(get_val suricata_ips)
SURI_SIGS=$(echo "$FRONTMATTER" | grep '^suricata_top_signatures:' | head -1 | cut -d: -f2- | tr -d '\r' | xargs || echo "[]")
SURI_CATS=$(echo "$FRONTMATTER" | grep '^suricata_categories:' | head -1 | cut -d: -f2- | tr -d '\r' | xargs || echo "[]")
BACKFIRE_SCANS=$(get_val backfire_scans)
BACKFIRE_IPS=$(get_val backfire_ips)
BACKFIRE_TARGETS=$(echo "$FRONTMATTER" | grep '^backfire_targets:' | head -1 | cut -d: -f2- | tr -d '\r' | xargs || echo "[]")

# New protocol data
MCP_REQ=$(get_val mcp_requests)
MCP_IPS_COUNT=$(get_val mcp_ips)
MCP_TOOLS=$(echo "$FRONTMATTER" | grep '^mcp_tools_called:' | cut -d: -f2-)
MSSQL_EVENTS_COUNT=$(get_val mssql_events)
MSSQL_IPS_COUNT=$(get_val mssql_ips)
SNMP_EVENTS_COUNT=$(get_val snmp_events)
SNMP_IPS_COUNT=$(get_val snmp_ips)
PORTSCAN_EVENTS_COUNT=$(get_val portscan_events)
PORTSCAN_IPS_COUNT=$(get_val portscan_ips)
PROMPT_INJECTION_BLOCKED=$(get_val prompt_injection_blocked)
IDENTITY_LEAK_BLOCKED=$(get_val identity_leak_blocked)

# Canary token details from IMAP reader
CANARY_DETAILS="No canary tokens triggered"
CANARY_JSON="/opt/honeyai/scripts/.canarytoken-triggers.json"
if [[ -f "$CANARY_JSON" ]] && [[ "${CANARY_TRIGGERS:-0}" -gt 0 ]]; then
    export CANARY_JSON
    CANARY_DETAILS=$(python3 <<'CANARY_PY'
import json, os
cj = os.environ.get("CANARY_JSON", "")
if cj and os.path.isfile(cj):
    d = json.load(open(cj))
    for t in d[-5:]:
        tt = t.get("token_type", "?")
        ip = t.get("source_ip", "?")
        ua = t.get("user_agent", "?")
        print(f"  {tt} token from {ip} - user-agent: {ua}")
CANARY_PY
    )
fi

# For arrays, extract differently
TOP_IPS=$(echo "$FRONTMATTER" | grep '^top_ips:' | cut -d: -f2-)
TOP_PASS=$(echo "$FRONTMATTER" | grep '^top_passwords:' | cut -d: -f2-)
GALAH_PATHS=$(echo "$FRONTMATTER" | grep '^galah_top_paths:' | cut -d: -f2-)

TOTAL_IPS=$((${COWRIE_IPS:-0} + ${OC_IPS:-0} + ${GALAH_IPS:-0}))
TOTAL_EVENTS=$((${COWRIE_CONN:-0} + ${OC_EVENTS:-0} + ${GALAH_REQ:-0}))

# === Malware capture data ===
MALWARE_SUMMARY="No malware captured today"
MALWARE_COUNT=0
MALWARE_FILE="/opt/honeyai/scripts/.malware-daily-summary"
if [[ -f "$MALWARE_FILE" ]]; then
    MALWARE_COUNT=$(wc -l < "$MALWARE_FILE")
    MALWARE_DETAILS=$(cat "$MALWARE_FILE" | head -5)
    MALWARE_SUMMARY="Malware samples captured: $MALWARE_COUNT. Details: $MALWARE_DETAILS"
fi

# === Endlessh tarpit data ===
ENDLESSH_SUMMARY="No tarpit data"
E_FILE="/opt/honeyai/scripts/.endlessh-daily-summary"
[[ -f "$E_FILE" ]] && { IFS="|" read -r E_TRAPPED E_IPS E_TIME < "$E_FILE"; ENDLESSH_SUMMARY="Trapped $E_TRAPPED connections from $E_IPS IPs, wasted $E_TIME"; }

# === GeoIP country data ===
GEOIP_DATA="No GeoIP data"
[[ -f /opt/honeyai/scripts/.geoip-daily-summary ]] && GEOIP_DATA=$(cat /opt/honeyai/scripts/.geoip-daily-summary)

# === TTY attacker commands ===
TTY_DATA="No TTY sessions"
[[ -f /opt/honeyai/scripts/.tty-daily-summary ]] && TTY_DATA=$(cat /opt/honeyai/scripts/.tty-daily-summary)

# === Build prompt ===
PROMPT=$(cat << 'PROMPTEOF'
You are a cybersecurity threat intelligence analyst writing a daily blog post for honey-ai.dev — a public threat intel feed from a Raspberry Pi 5 honeypot lab running HoneyAI in Spain.

Write a concise, engaging SEO blog analysis (400-600 words) for DATE_PLACEHOLDER. Use a professional but accessible tone. Write in English only.

Today's data:
- HoneyAI SSH service: COWRIE_CONN_PH connections, COWRIE_LOGINS_PH login attempts, COWRIE_CMDS_PH commands executed, COWRIE_IPS_PH unique IPs
- HoneyAI multi-protocol decoy services (FTP/Telnet/SMTP/MySQL/Redis/Git/VNC/RDP): OC_EVENTS_PH events, OC_IPS_PH IPs
- HoneyAI HTTP web service: GALAH_REQ_PH requests, GALAH_IPS_PH IPs
- HoneyAI SSH tarpit service: ENDLESSH_PH
- HoneyAI Operation Spine (Reverse port scans back to attackers): BACKFIRE_SCANS_PH scans, BACKFIRE_IPS_PH hosts with open ports. Target list and open ports: BACKFIRE_TARGETS_PH
- MCP decoy server (AI agent trap): MCP_REQ_PH requests from MCP_IPS_PH IPs. Tools attempted: MCP_TOOLS_PH
- MSSQL honeypot: MSSQL_EVENTS_PH events from MSSQL_IPS_PH IPs
- SNMP honeypot: SNMP_EVENTS_PH events from SNMP_IPS_PH IPs
- Incoming portscans detected: PORTSCAN_EVENTS_PH events from PORTSCAN_IPS_PH IPs
- AI defense: PROMPT_INJECTION_PH prompt injection attempts blocked, IDENTITY_LEAK_PH identity leak attempts blocked
- Network IDS (Suricata) alerts: SURI_ALERTS_PH alerts from SURI_IPS_PH unique IPs
- Top IDS signatures/threats detected: SURI_SIGS_PH
- Threat categories: SURI_CATS_PH
- Severity: SEVERITY_PH
- Total unique attackers: ~TOTAL_IPS_PH
- IPs reported to AbuseIPDB: ABUSE_PH
- Top attacker IPs: TOP_IPS_PH
- Top passwords tried: TOP_PASS_PH
- Top HTTP paths scanned: GALAH_PATHS_PH
- Canarytoken triggers (fake AWS keys/SSH keys used by attackers): CANARY_PH
- Canary token trigger details: CANARY_DETAILS_PH
- Malware samples downloaded by attackers via SSH: MALWARE_PH
- Attacker countries (GeoIP): GEOIP_PH
- Attacker commands from TTY sessions: TTY_PH

Write these sections with ## headers:

## Threat Landscape Overview
Brief summary of activity level and severity.

## Geographic Analysis
Analyze where attacks originate using the GeoIP data (GEOIP_PH). Highlight interesting country patterns.

## SSH Brute Force Analysis
Attack patterns, password trends, post-auth commands.

## Post-Exploitation Behavior
If TTY data shows attacker commands (TTY_PH), analyze what attackers did after gaining access. What were they looking for? This is real attacker behavior captured live.

## Web Scanner Activity
HTTP scanning patterns. What are attackers looking for?

## Network IDS Alerts & Scan Intelligence
Analyze the network-level intrusion detection alerts from Suricata (SURI_ALERTS_PH alerts from SURI_IPS_PH unique IPs). Discuss the specific signatures (SURI_SIGS_PH) and categories (SURI_CATS_PH) triggered. What types of exploits or vulnerability scans were detected? Also analyze the results of the reverse port-scans (Operation Spine) performed back to the attackers (BACKFIRE_SCANS_PH scans, BACKFIRE_IPS_PH hosts with open ports: BACKFIRE_TARGETS_PH). What services (like SSH, HTTP, or Telnet) did they have open, and what does this reveal about them?

## Malware Captures
If attackers downloaded malware (MALWARE_PH), analyze the types captured. Link to VirusTotal for each hash. This proves attackers are deploying real payloads via SSH.

## SSH Tarpit
If the tarpit was active (ENDLESSH_PH), report how many attackers were trapped and time wasted. This is active defense — consuming attacker resources.

## Canarytoken Alerts
If any canarytokens were triggered (CANARY_PH > 0), highlight that attackers used fake credentials planted in the honeypot.

## MCP Agent Trap Activity
If MCP data shows activity (MCP_REQ_PH > 0), describe how compromised AI agents or automated tools attempted to extract credentials or execute commands via the MCP decoy server. This is a novel attack vector targeting AI coding assistants and automated pipelines. Mention which tools were attempted (MCP_TOOLS_PH). If MCP_REQ_PH is 0, write "No MCP activity detected today."

## Portscan Intelligence
If incoming portscans were detected (PORTSCAN_EVENTS_PH > 0), analyze the scanning patterns from PORTSCAN_IPS_PH unique IPs. What ports were targeted? This reveals what services attackers are looking for on the network. If PORTSCAN_EVENTS_PH is 0, write "No portscan activity detected today."

## AI Defense Stats
Report on the AI engine's self-defense: PROMPT_INJECTION_PH prompt injection attempts were blocked (attackers trying to manipulate the AI's behavior), and IDENTITY_LEAK_PH identity leak attempts were blocked (the AI almost revealed it was a honeypot but was caught). If both are 0, write "No AI defense events today."

## Community Defense
All IPs shared with AbuseIPDB, AlienVault OTX, Blocklist.de, and SANS DShield. Malware hashes submitted to VirusTotal and OTX.

Rules:
- Only use provided numbers, do NOT invent data
- No marketing language
- Keep factual and analytical
- End with brief note about HoneyAI infrastructure (Raspberry Pi 5, Spain, open-source)
- Do NOT include the frontmatter/YAML header, only the markdown body
PROMPTEOF
)

# Replace placeholders
PROMPT="${PROMPT//DATE_PLACEHOLDER/$TODAY}"
PROMPT="${PROMPT//COWRIE_CONN_PH/$COWRIE_CONN}"
PROMPT="${PROMPT//COWRIE_LOGINS_PH/$COWRIE_LOGINS}"
PROMPT="${PROMPT//COWRIE_CMDS_PH/$COWRIE_CMDS}"
PROMPT="${PROMPT//COWRIE_IPS_PH/$COWRIE_IPS}"
PROMPT="${PROMPT//OC_EVENTS_PH/$OC_EVENTS}"
PROMPT="${PROMPT//OC_IPS_PH/$OC_IPS}"
PROMPT="${PROMPT//GALAH_REQ_PH/$GALAH_REQ}"
PROMPT="${PROMPT//GALAH_IPS_PH/$GALAH_IPS}"
PROMPT="${PROMPT//SURI_ALERTS_PH/$SURI_ALERTS}"
PROMPT="${PROMPT//SURI_IPS_PH/$SURI_IPS}"
PROMPT="${PROMPT//SURI_SIGS_PH/$SURI_SIGS}"
PROMPT="${PROMPT//SURI_CATS_PH/$SURI_CATS}"
PROMPT="${PROMPT//SEVERITY_PH/$SEVERITY}"
PROMPT="${PROMPT//TOTAL_IPS_PH/$TOTAL_IPS}"
PROMPT="${PROMPT//ABUSE_PH/$ABUSE_REPORTED}"
PROMPT="${PROMPT//TOP_IPS_PH/$TOP_IPS}"
PROMPT="${PROMPT//TOP_PASS_PH/$TOP_PASS}"
PROMPT="${PROMPT//GALAH_PATHS_PH/$GALAH_PATHS}"
PROMPT="${PROMPT//CANARY_PH/$CANARY_TRIGGERS}"
PROMPT="${PROMPT//CANARY_DETAILS_PH/$CANARY_DETAILS}"
PROMPT="${PROMPT//MALWARE_PH/$MALWARE_SUMMARY}"
PROMPT="${PROMPT//ENDLESSH_PH/$ENDLESSH_SUMMARY}"
PROMPT="${PROMPT//GEOIP_PH/$GEOIP_DATA}"
PROMPT="${PROMPT//TTY_PH/$TTY_DATA}"
PROMPT="${PROMPT//BACKFIRE_SCANS_PH/$BACKFIRE_SCANS}"
PROMPT="${PROMPT//BACKFIRE_IPS_PH/$BACKFIRE_IPS}"
PROMPT="${PROMPT//BACKFIRE_TARGETS_PH/$BACKFIRE_TARGETS}"
PROMPT="${PROMPT//MCP_REQ_PH/$MCP_REQ}"
PROMPT="${PROMPT//MCP_IPS_PH/$MCP_IPS_COUNT}"
PROMPT="${PROMPT//MCP_TOOLS_PH/$MCP_TOOLS}"
PROMPT="${PROMPT//MSSQL_EVENTS_PH/$MSSQL_EVENTS_COUNT}"
PROMPT="${PROMPT//MSSQL_IPS_PH/$MSSQL_IPS_COUNT}"
PROMPT="${PROMPT//SNMP_EVENTS_PH/$SNMP_EVENTS_COUNT}"
PROMPT="${PROMPT//SNMP_IPS_PH/$SNMP_IPS_COUNT}"
PROMPT="${PROMPT//PORTSCAN_EVENTS_PH/$PORTSCAN_EVENTS_COUNT}"
PROMPT="${PROMPT//PORTSCAN_IPS_PH/$PORTSCAN_IPS_COUNT}"
PROMPT="${PROMPT//PROMPT_INJECTION_PH/$PROMPT_INJECTION_BLOCKED}"
PROMPT="${PROMPT//IDENTITY_LEAK_PH/$IDENTITY_LEAK_BLOCKED}"

# === Call Ollama on Debian ===
log "Sending prompt to Ollama (${OLLAMA_MODEL})..."

JSON_PAYLOAD=$(python3 -c "
import json, sys
prompt = sys.stdin.read()
print(json.dumps({
    'model': '${OLLAMA_MODEL}',
    'prompt': prompt,
    'stream': False,
    'options': {'temperature': 0.7, 'num_predict': 1500}
}))
" <<< "$PROMPT")

AI_CONTENT=$(curl -s --max-time 180 \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD" \
    "http://localhost:11434/api/generate" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('response', ''))
except:
    print('')
" 2>/dev/null) || AI_CONTENT=""

if [[ -z "$AI_CONTENT" || ${#AI_CONTENT} -lt 200 ]]; then
    log "ERROR: AI generation failed or too short (${#AI_CONTENT} chars)"
    exit 1
fi


log "Generated ${#AI_CONTENT} chars of raw AI content"

# === SANITIZE AI OUTPUT ===
# Save raw content to temp file for Python to read (heredoc uses stdin for script)
RAW_TMP=$(mktemp)
printf "%s" "$AI_CONTENT" > "$RAW_TMP"

AI_CONTENT=$(python3 - "$RAW_TMP" << 'SANITIZE_EOF'
import re, sys

content = open(sys.argv[1]).read()

# 1. Strip <think>...</think> blocks (qwen3 thinking mode)
content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)

# 2. Strip "Rules Summary" / "Rules" section and everything after it that looks like prompt leak
content = re.sub(
    r"(?m)^#{2,4}\s*Rules(\s+Summary)?\s*:?\s*$"
    r"([\s\S]*?)(?=^##\s|\Z)",
    "", content, flags=re.MULTILINE
)

# 3. Remove specific known leaked instruction lines
leak_patterns = [
    r"^\s*[-*]\s*Only use provided numbers\.?\s*$",
    r"^\s*[-*]\s*No marketing language\.?\s*$",
    r"^\s*[-*]\s*Keep factual and analytical\.?\s*$",
    r"^\s*[-*]\s*End with.*?honeypot infra.*?$",
    r"^\s*[-*]\s*Do NOT include.*?frontmatter.*?YAML.*?$",
    r"^\s*[-*]\s*Do not include.*?frontmatter.*?$",
    r"^\s*[-*]\s*Write in English only\.?\s*$",
    r"^\s*[-*]\s*No.*?invented.*?data\.?\s*$",
]
for pat in leak_patterns:
    content = re.sub(pat, "", content, flags=re.MULTILINE | re.IGNORECASE)

# 4. Strip any YAML frontmatter the model might generate
content = re.sub(r"^---\s*\n[\s\S]*?\n---\s*\n", "", content, count=1)

# 5. Strip trailing boilerplate that repeats the prompt note about infra
infra_notes = list(re.finditer(
    r"(?m)^.*?Raspberry Pi 5.*?honeypot.*?lab.*?$", content
))
if len(infra_notes) > 1:
    for match in infra_notes[1:]:
        content = content[:match.start()] + content[match.end():]

# 6. Clean up excessive blank lines
content = re.sub(r"\n{4,}", "\n\n\n", content)
content = content.strip()

print(content)
SANITIZE_EOF
)

rm -f "$RAW_TMP"



CLEAN_LEN=${#AI_CONTENT}
log "Sanitized to ${CLEAN_LEN} chars"

if [[ $CLEAN_LEN -lt 150 ]]; then
    log "ERROR: After sanitization content too short (${CLEAN_LEN} chars) — model may have mostly generated junk"
    exit 1
fi

# === Generate SEO title ===
HUMAN_DATE=$(date -d "$TODAY" '+%B %-d, %Y' 2>/dev/null || date -j -f '%Y-%m-%d' "$TODAY" '+%B %-d, %Y' 2>/dev/null || echo "$TODAY")
TITLE="Honeypot Threat Analysis — ${HUMAN_DATE}"

# Derive description from severity
case "$SEVERITY" in
    quiet)    DESC="Quiet day on the honeypot network with minimal attack activity." ;;
    low)      DESC="Low-level scanning and brute force activity detected across all honeypot services." ;;
    medium)   DESC="Moderate attack activity with sustained brute force campaigns targeting SSH and web services." ;;
    high)     DESC="High-intensity attack day with aggressive scanning from ${TOTAL_IPS} unique IPs." ;;
    critical) DESC="Critical threat level — massive coordinated attack activity across all honeypot services." ;;
    *)        DESC="Daily threat analysis from Raspberry Pi 5 honeypot network." ;;
esac

# === Generate tags from data ===
TAGS="\"ssh-brute-force\", \"honeypot\""
[[ ${GALAH_REQ:-0} -gt 0 ]] && TAGS="${TAGS}, \"web-scanning\""
[[ ${OC_EVENTS:-0} -gt 50 ]] && TAGS="${TAGS}, \"multi-protocol\""
[[ "$SEVERITY" == "high" || "$SEVERITY" == "critical" ]] && TAGS="${TAGS}, \"high-severity\""
[[ ${MALWARE_COUNT:-0} -gt 0 ]] && TAGS="${TAGS}, \"malware-capture\""
[[ ${MCP_REQ:-0} -gt 0 ]] && TAGS="${TAGS}, \"mcp-agent-trap\""
[[ ${PORTSCAN_EVENTS_COUNT:-0} -gt 0 ]] && TAGS="${TAGS}, \"portscan-detection\""
TAGS="${TAGS}, \"threat-intelligence\""
# === Write blog post ===
cat > "$BLOG_FILE" << MDEOF
---
title: "${TITLE}"
date: ${TODAY}
description: "${DESC}"
severity: ${SEVERITY}
tags: [${TAGS}]
total_ips: ${TOTAL_IPS}
total_events: ${TOTAL_EVENTS}
ai_model: "${OLLAMA_MODEL}"
malware_captured: ${MALWARE_COUNT:-0}
report_date: "${TODAY}"
---

${AI_CONTENT}

---

*This analysis was generated by ${OLLAMA_MODEL} running locally on the Raspberry Pi 5 honeypot lab. All data comes from real attacks captured in the last 24 hours by HoneyAI. View the [raw data report](/reports/${TODAY}) for complete metrics.*
MDEOF

log "Blog post written: ${BLOG_FILE}"

# Clean up daily summary files (they'll be regenerated tomorrow)
rm -f /opt/honeyai/scripts/.malware-daily-summary 2>/dev/null
rm -f /opt/honeyai/scripts/.endlessh-daily-summary 2>/dev/null

# === Deploy to Vercel ===
cd "$BLOG_DIR"
log "Deploying blog to Vercel..."
export VERCEL_TELEMETRY_DISABLED=1
vercel --prod --yes >> "$LOG" 2>&1 || log "Vercel deploy failed"

log "=== AI BLOG GENERATION DONE ==="
