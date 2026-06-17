#!/usr/bin/env bash
# =============================================================================
# HONEYPOT PUBLISH — Genera post diario en Astro + deploy a Vercel
# Cron: 30 22 * * *   (30 min después del reporte Telegram)
# Pi 5: /opt/honeyai/scripts/honeypot-publish.sh
# =============================================================================
set -Eeuo pipefail
trap 'echo "[ERR] Failed at line $LINENO: $BASH_COMMAND" | tee -a /opt/honeyai/honeypot-publish.log' ERR

source /opt/honeyai/scripts/.env

BLOG_DIR="/mnt/ssd/www/honeypot-blog"
CONTENT_DIR="${BLOG_DIR}/src/content/reports"
TODAY=${TODAY:-$(date '+%Y-%m-%d')}
POST_FILE="${CONTENT_DIR}/${TODAY}.md"
LOG="/opt/honeyai/honeypot-publish.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Evitar doble ejecución
if [[ -f "$POST_FILE" ]]; then
    log "Post del día ya existe: $POST_FILE — saltando."
    exit 0
fi

log "=== HONEYPOT PUBLISH ${TODAY} ==="

# ============================================================
# 1. HONEYAI DATA
# ============================================================
HONEYAI_JSON_FILE="/opt/honeyai/logs/events.json"
HONEYAI_STATS_SCRIPT="/opt/honeyai/honeyai-stats.py"

if [[ -f "$HONEYAI_JSON_FILE" && -f "$HONEYAI_STATS_SCRIPT" ]]; then
    log "Parsing HoneyAI events..."
    HONEYAI_JSON=$(python3 "$HONEYAI_STATS_SCRIPT" "$HONEYAI_JSON_FILE" "$TODAY" 2>/dev/null || echo "{}")
    
    get_val() {
        echo "$HONEYAI_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('$1', $2))" 2>/dev/null || echo "$2"
    }
    
    get_arr() {
        echo "$HONEYAI_JSON" | python3 -c "import sys, json; print('\n'.join(json.load(sys.stdin).get('$1', [])))" 2>/dev/null || echo ""
    }

    get_json_val() {
        echo "$HONEYAI_JSON" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin).get('$1', $2)))" 2>/dev/null || echo "$2"
    }
    
    COWRIE_CONNECTIONS=$(get_val "ssh_connections" 0)
    COWRIE_LOGINS=$(get_val "ssh_logins" 0)
    COWRIE_COMMANDS=$(get_val "ssh_commands" 0)
    COWRIE_IPS=$(get_val "ssh_ips" 0)
    
    OC_EVENTS=$(get_val "opencanary_events" 0)
    OC_IPS=$(get_val "opencanary_ips" 0)
    
    GALAH_REQUESTS=$(get_val "galah_requests" 0)
    GALAH_IPS=$(get_val "galah_ips" 0)
    
    TOP_IPS_RAW=$(get_arr "top_ips")
    TOP_PASS_RAW=$(get_arr "top_passwords")
    TOP_CMDS_RAW=$(get_arr "top_commands")
    FUNNY_PASS_RAW=$(get_arr "funny_passwords")
    FUNNY_CMDS_RAW=$(get_arr "funny_commands")
    HONEYPOT_FILES_RAW=$(get_arr "honeypot_files_accessed")
    GALAH_PATHS_RAW=$(get_arr "galah_top_paths")
    GALAH_AGENTS_RAW=$(get_arr "galah_top_agents")

    BACKFIRE_SCANS=$(get_val "backfire_scans" 0)
    BACKFIRE_IPS=$(get_val "backfire_ips" 0)
    BACKFIRE_PORTS_TALLY_JSON=$(get_json_val "backfire_ports_tally" "[]")
    BACKFIRE_TARGETS_JSON=$(get_json_val "backfire_targets" "[]")

    # New protocol-specific data
    MCP_REQUESTS=$(get_val "mcp_requests" 0)
    MCP_IPS=$(get_val "mcp_ips" 0)
    MCP_TOOLS_RAW=$(get_arr "mcp_tools_called")
    MSSQL_EVENTS=$(get_val "mssql_events" 0)
    MSSQL_IPS=$(get_val "mssql_ips" 0)
    MSSQL_CREDS_RAW=$(get_arr "mssql_top_credentials")
    SNMP_EVENTS=$(get_val "snmp_events" 0)
    SNMP_IPS=$(get_val "snmp_ips" 0)
    SNMP_COMMUNITIES_RAW=$(get_arr "snmp_top_communities")
    PORTSCAN_EVENTS=$(get_val "portscan_events" 0)
    PORTSCAN_IPS=$(get_val "portscan_ips" 0)
    PORTSCAN_TOP_PORTS_JSON=$(get_json_val "portscan_top_ports" "[]")
    PROTOCOL_BREAKDOWN_JSON=$(get_json_val "protocol_breakdown" "[]")
    PROMPT_INJECTION_BLOCKED=$(get_val "prompt_injection_blocked" 0)
    IDENTITY_LEAK_BLOCKED=$(get_val "identity_leak_blocked" 0)
else
    log "WARNING: HoneyAI files not found. Setting metrics to 0."
    COWRIE_CONNECTIONS=0; COWRIE_LOGINS=0; COWRIE_COMMANDS=0; COWRIE_IPS=0
    OC_EVENTS=0; OC_IPS=0
    GALAH_REQUESTS=0; GALAH_IPS=0
    TOP_IPS_RAW=""; TOP_PASS_RAW=""; TOP_CMDS_RAW=""
    FUNNY_PASS_RAW=""; FUNNY_CMDS_RAW=""; HONEYPOT_FILES_RAW=""
    GALAH_PATHS_RAW=""; GALAH_AGENTS_RAW=""
    BACKFIRE_SCANS=0; BACKFIRE_IPS=0
    BACKFIRE_PORTS_TALLY_JSON="[]"
    BACKFIRE_TARGETS_JSON="[]"
    MCP_REQUESTS=0; MCP_IPS=0; MCP_TOOLS_RAW=""
    MSSQL_EVENTS=0; MSSQL_IPS=0; MSSQL_CREDS_RAW=""
    SNMP_EVENTS=0; SNMP_IPS=0; SNMP_COMMUNITIES_RAW=""
    PORTSCAN_EVENTS=0; PORTSCAN_IPS=0
    PORTSCAN_TOP_PORTS_JSON="[]"; PROTOCOL_BREAKDOWN_JSON="[]"
    PROMPT_INJECTION_BLOCKED=0; IDENTITY_LEAK_BLOCKED=0
fi

# 1.5 CANARYTOKEN DATA
CANARY_JSON="/opt/honeyai/scripts/.canarytoken-triggers.json"
CANARY_TRIGGERS=0
CANARY_DETAILS="No canary tokens triggered"
if [[ -f "$CANARY_JSON" ]]; then
    CANARY_TRIGGERS=$(python3 - "$CANARY_JSON" "$TODAY" << 'CANARYEOF'
import json, sys, re
from datetime import datetime
count = 0
try:
    target = sys.argv[2]
    d = json.load(open(sys.argv[1]))
    for t in d:
        ts = t.get('timestamp', '')
        m = re.search(r'\d{1,2}\s+[A-Za-z]+\s+\d{4}', ts)
        if m:
            dt = datetime.strptime(m.group(0), "%d %b %Y")
            if dt.strftime("%Y-%m-%d") == target:
                count += 1
except:
    pass
print(count)
CANARYEOF
    ) 2>/dev/null || echo 0
    CANARY_DETAILS=$(python3 - "$CANARY_JSON" "$TODAY" << 'CANARYEOF2'
import json, sys, re
from datetime import datetime
try:
    target = sys.argv[2]
    d = json.load(open(sys.argv[1]))
    for t in d:
        ts = t.get('timestamp', '')
        m = re.search(r'\d{1,2}\s+[A-Za-z]+\s+\d{4}', ts)
        if m:
            dt = datetime.strptime(m.group(0), "%d %b %Y")
            if dt.strftime("%Y-%m-%d") == target:
                print(f"  {t.get('token_type', '?')}: {t.get('source_ip', '?')}")
except:
    pass
CANARYEOF2
    ) 2>/dev/null || true
fi

# ============================================================
# 3. ABUSEIPDB COUNT (Grepping from HoneyAI log)
# ============================================================
ABUSE_REPORTED=0
HONEYAI_LOG_FILE="/opt/honeyai/logs/honeyai.log"
if [[ -f "$HONEYAI_LOG_FILE" ]]; then
    set +o pipefail
    ABUSE_REPORTED=$(grep -a "${TODAY}" "$HONEYAI_LOG_FILE" 2>/dev/null | grep -a -c "AbuseIPDB: reported" || true)
    set -o pipefail
    [[ "$ABUSE_REPORTED" =~ ^[0-9]+$ ]] || ABUSE_REPORTED=0
fi

# ============================================================
# 3c. SURICATA IDS DATA
# ============================================================
SURICATA_LOG="/var/log/suricata/eve.json"
SURICATA_ALERTS=0
SURICATA_IPS=0
SURICATA_TOP_SIGS_RAW=""
SURICATA_CATEGORIES_RAW=""

if [[ -f "$SURICATA_LOG" ]]; then
    SURI_RAW=$(python3 /opt/honeyai/scripts/suricata-stats.py "$TODAY" 2>/dev/null || echo "0|0||")
    SURICATA_ALERTS=$(echo "$SURI_RAW" | cut -d'|' -f1)
    SURICATA_IPS=$(echo "$SURI_RAW" | cut -d'|' -f2)
    SURICATA_TOP_SIGS_RAW=$(echo "$SURI_RAW" | cut -d'|' -f3 | tr ';;' '\n')
    SURICATA_CATEGORIES_RAW=$(echo "$SURI_RAW" | cut -d'|' -f4 | tr ';;' '\n')
fi

# ============================================================
# 4. DETERMINAR SEVERIDAD
# ============================================================
TOTAL_EVENTS=$((COWRIE_CONNECTIONS + OC_EVENTS + SURICATA_ALERTS + MCP_REQUESTS + PORTSCAN_EVENTS))

if   [[ $TOTAL_EVENTS -eq 0 ]];      then SEVERITY="quiet"
elif [[ $TOTAL_EVENTS -lt 200 ]];    then SEVERITY="low"
elif [[ $TOTAL_EVENTS -lt 800 ]];    then SEVERITY="medium"
elif [[ $TOTAL_EVENTS -lt 2000 ]];   then SEVERITY="high"
else                                       SEVERITY="critical"
fi

# ============================================================
# 5. BUILD YAML ARRAYS
# ============================================================
build_yaml_array() {
    local items="$1"
    if [[ -z "$items" ]]; then echo "[]"; return; fi
    local result="["
    local first=true
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        # Escape backslash and double-quote for YAML string safety
        item="${item//\\/\\\\}"
        local _dq='"'
        item="${item//$_dq/\$_dq}"
        $first || result+=", "
        result+="\"${item}\""
        first=false
    done <<< "$items"
    result+="]"
    echo "$result"
}

TOP_IPS_YAML=$(build_yaml_array "$TOP_IPS_RAW")
TOP_PASS_YAML=$(build_yaml_array "$TOP_PASS_RAW")
TOP_CMDS_YAML=$(build_yaml_array "$TOP_CMDS_RAW")
FUNNY_PASS_YAML=$(build_yaml_array "$FUNNY_PASS_RAW")
FUNNY_CMDS_YAML=$(build_yaml_array "$FUNNY_CMDS_RAW")
GALAH_PATHS_YAML=$(build_yaml_array "$GALAH_PATHS_RAW")
GALAH_AGENTS_YAML=$(build_yaml_array "$GALAH_AGENTS_RAW")
HONEYPOT_FILES_YAML=$(build_yaml_array "$HONEYPOT_FILES_RAW")
SURICATA_SIGS_YAML=$(build_yaml_array "$SURICATA_TOP_SIGS_RAW")
SURICATA_CATS_YAML=$(build_yaml_array "$SURICATA_CATEGORIES_RAW")
MCP_TOOLS_YAML=$(build_yaml_array "$MCP_TOOLS_RAW")
MSSQL_CREDS_YAML=$(build_yaml_array "$MSSQL_CREDS_RAW")
SNMP_COMMUNITIES_YAML=$(build_yaml_array "$SNMP_COMMUNITIES_RAW")

# ============================================================
# 6. GENERAR MARKDOWN
# ============================================================
log "Generando ${POST_FILE}..."

HUMAN_DATE=$(python3 -c "import datetime; d = datetime.datetime.strptime('$TODAY', '%Y-%m-%d'); months = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre']; print(f'{d.day} de {months[d.month-1]} de {d.year}')" 2>/dev/null || date -d "$TODAY" '+%-d de %B de %Y' 2>/dev/null || echo "$TODAY")

cat > "$POST_FILE" << MDEOF
---
date: ${TODAY}
cowrie_connections: ${COWRIE_CONNECTIONS}
cowrie_logins: ${COWRIE_LOGINS}
cowrie_commands: ${COWRIE_COMMANDS}
cowrie_ips: ${COWRIE_IPS}
opencanary_events: ${OC_EVENTS}
opencanary_ips: ${OC_IPS}
canarytoken_triggers: ${CANARY_TRIGGERS}
top_ips: ${TOP_IPS_YAML}
top_commands: ${TOP_CMDS_YAML}
top_passwords: ${TOP_PASS_YAML}
abuseipdb_reported: ${ABUSE_REPORTED}
galah_requests: ${GALAH_REQUESTS}
galah_ips: ${GALAH_IPS}
galah_top_paths: ${GALAH_PATHS_YAML}
galah_top_agents: ${GALAH_AGENTS_YAML}
severity: ${SEVERITY}
funny_passwords: ${FUNNY_PASS_YAML}
funny_commands: ${FUNNY_CMDS_YAML}
honeypot_files_accessed: ${HONEYPOT_FILES_YAML}
suricata_alerts: ${SURICATA_ALERTS}
suricata_ips: ${SURICATA_IPS}
suricata_top_signatures: ${SURICATA_SIGS_YAML}
suricata_categories: ${SURICATA_CATS_YAML}
backfire_scans: ${BACKFIRE_SCANS}
backfire_ips: ${BACKFIRE_IPS}
backfire_ports_tally: ${BACKFIRE_PORTS_TALLY_JSON}
backfire_targets: ${BACKFIRE_TARGETS_JSON}
mcp_requests: ${MCP_REQUESTS}
mcp_ips: ${MCP_IPS}
mcp_tools_called: ${MCP_TOOLS_YAML}
mssql_events: ${MSSQL_EVENTS}
mssql_ips: ${MSSQL_IPS}
mssql_top_credentials: ${MSSQL_CREDS_YAML}
snmp_events: ${SNMP_EVENTS}
snmp_ips: ${SNMP_IPS}
snmp_top_communities: ${SNMP_COMMUNITIES_YAML}
portscan_events: ${PORTSCAN_EVENTS}
portscan_ips: ${PORTSCAN_IPS}
portscan_top_ports: ${PORTSCAN_TOP_PORTS_JSON}
protocol_breakdown: ${PROTOCOL_BREAKDOWN_JSON}
prompt_injection_blocked: ${PROMPT_INJECTION_BLOCKED}
identity_leak_blocked: ${IDENTITY_LEAK_BLOCKED}
---

Automated report for ${HUMAN_DATE}. Recorded **${COWRIE_CONNECTIONS}** SSH connections and **${OC_EVENTS}** multi-protocol decoy events on HoneyAI, from **$((COWRIE_IPS + OC_IPS))** unique IPs.
${ABUSE_REPORTED} IPs were automatically reported to the AbuseIPDB community database.

## SSH Activity (HoneyAI)

The SSH service received **${COWRIE_LOGINS}** login attempts from **${COWRIE_IPS}** unique IPs.
Attackers executed **${COWRIE_COMMANDS}** commands after gaining simulated system access.

## Multi-Protocol Decoys (HoneyAI)

Detected **${OC_EVENTS}** events across services including FTP, Telnet, SMTP, MySQL, Redis, Git, VNC, and RDP
from **${OC_IPS}** distinct IPs. All events are access attempts against simulated production services.

## HTTP Web Service (HoneyAI)

The web service received **${GALAH_REQUESTS}** HTTP requests from real scanners across **${GALAH_IPS}** unique IPs.
Each attacker received a fake response generated in real time by the local AI engine (Ollama, no internet connection required).

## MCP Agent Trap

The MCP decoy server received **${MCP_REQUESTS}** requests from **${MCP_IPS}** unique IPs.
Attackers attempted to call internal tools including credential extraction and system command execution.

## MSSQL / SNMP Honeypots

The MSSQL decoy received **${MSSQL_EVENTS}** authentication events from **${MSSQL_IPS}** IPs.
The SNMP trap received **${SNMP_EVENTS}** queries from **${SNMP_IPS}** IPs probing community strings and OIDs.

## Portscan Detection

Detected **${PORTSCAN_EVENTS}** incoming port scan events from **${PORTSCAN_IPS}** unique IPs.

## AI Defense Stats

Blocked **${PROMPT_INJECTION_BLOCKED}** prompt injection attempts and **${IDENTITY_LEAK_BLOCKED}** identity leak attempts.

## Active Defense (Operation Spine)

HoneyAI performed **${BACKFIRE_SCANS}** reverse port scans back to active attacker IPs. Out of these, **${BACKFIRE_IPS}** hosts were found running open public services, allowing backfire profiling.

## Network IDS (Suricata)

The network intrusion detection system generated **${SURICATA_ALERTS}** alerts from **${SURICATA_IPS}** unique source IPs.
Suricata monitors all traffic on the primary network interface using Emerging Threats + AlienVault OTX rulesets.
MDEOF

log "Post generado OK: ${POST_FILE}"

# ============================================================
# 7. DEPLOY A VERCEL (build en cloud)
# ============================================================
cd "$BLOG_DIR"

log "Deploying a Vercel..."
export VERCEL_TELEMETRY_DISABLED=1
vercel --prod --yes \
    >> "$LOG" 2>&1

log "Deploy completado."

# ============================================================
# 8. NOTIFICAR TELEGRAM
# ============================================================
MSG=$(printf '🌐 <b>Honeypot Blog actualizado</b>\n📅 %s — Severidad: %s\n🔗 <a href="https://honey-ai.dev/reports/%s">Ver reporte →</a>' "$TODAY" "$SEVERITY" "$TODAY")

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="$MSG" \
    -d parse_mode="HTML" > /dev/null 2>&1

# ============================================================
# 9. AUTO-POST MASTODON — disabled, set MASTODON_TOKEN to enable
# ============================================================
log "Mastodon: MASTODON_TOKEN not set, skipping."


log "=== DONE ==="
