#!/usr/bin/env bash
# 🍯 Honeypot Daily Report — HoneyAI Edition
set -Eeo pipefail
source /opt/honeyai/scripts/.env

STATS=$(python3 << "PYEOF"
import json
from datetime import datetime, timedelta, timezone
from collections import Counter

cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
protocols, ips, passwords, paths, attack_types = Counter(), Counter(), Counter(), Counter(), Counter()
commands_list = []
total = 0

with open("/opt/honeyai/logs/events.json", "r") as f:
    for line in f:
        try:
            e = json.loads(line.strip())
            ts = e.get("timestamp","")[:19]
            t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            if t < cutoff: continue
            ip = e.get("ip","")
            if ip.startswith("192.168.") or ip.startswith("127."): continue
            total += 1
            protocols[e.get("protocol","?")] += 1
            ips[ip] += 1
            if e.get("password"): passwords[e["password"]] += 1
            if e.get("command"): commands_list.append(e["command"])
            if e.get("path"): paths[e["path"]] += 1
            if e.get("attack_type"): attack_types[e["attack_type"]] += 1
        except: continue

s = "; "
print("TOTAL=" + str(total))
print("UNIQUE_IPS=" + str(len(ips)))
print("PROTOCOLS=" + s.join(p+":"+str(c) for p,c in protocols.most_common(8)))
print("TOP_IPS=" + s.join(ip+" ("+str(c)+")" for ip,c in ips.most_common(5)))
print("TOP_PASS=" + s.join(p+" ("+str(c)+")" for p,c in passwords.most_common(5)))
print("TOP_CMDS=" + s.join(commands_list[:5]))
print("TOP_PATHS=" + s.join(p+" ("+str(c)+")" for p,c in paths.most_common(5)))
print("ATTACK_TYPES=" + s.join(a+":"+str(c) for a,c in attack_types.most_common()))
PYEOF
)

eval "$STATS"

CANARY_SECTION=""
CANARY_LOG="/opt/honeyai/scripts/canarytoken-triggers.log"
if [[ -f "$CANARY_LOG" ]]; then
    TODAY_CANARY=$(grep "$(date "+%Y-%m-%d")" "$CANARY_LOG" 2>/dev/null | wc -l || echo 0)
    [[ $TODAY_CANARY -gt 0 ]] && CANARY_SECTION="🪤 Canarytokens: $TODAY_CANARY"
fi

if [[ ${TOTAL:-0} -gt 0 ]]; then
    MSG="🍯 <b>HONEYAI — Reporte Diario</b>
━━━━━━━━━━━━━━━━━━
📊 Total: ${TOTAL} | IPs: ${UNIQUE_IPS}
📡 ${PROTOCOLS}
💀 ${ATTACK_TYPES}

🌍 <b>Top IPs:</b> ${TOP_IPS}
🔗 <b>Top paths:</b> ${TOP_PATHS}"
    [[ -n "$TOP_PASS" ]] && MSG+=$n"🔑 <b>Passwords:</b> ${TOP_PASS}"
    [[ -n "$TOP_CMDS" ]] && MSG+=$n"💻 <b>Cmds:</b> ${TOP_CMDS}"
    [[ -n "$CANARY_SECTION" ]] && MSG+=$n"$CANARY_SECTION"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" -d text="$MSG" -d parse_mode="HTML" >/dev/null 2>&1
else
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" -d text="🍯 HoneyAI: 0 ataques externos en 24h." -d parse_mode="HTML" >/dev/null 2>&1
fi

if [[ -n "${CROWDSEC_CTI_KEY:-}" && ${TOTAL:-0} -gt 0 ]]; then
    TOP3=$(python3 -c "
import json
from datetime import datetime, timedelta, timezone
from collections import Counter
cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
ips = Counter()
with open(\"/opt/honeyai/logs/events.json\") as f:
    for line in f:
        try:
            e = json.loads(line.strip())
            ts = datetime.strptime(e.get(\"timestamp\",\"\")[:19], \"%Y-%m-%dT%H:%M:%S\").replace(tzinfo=timezone.utc)
            if ts < cutoff: continue
            ip = e.get(\"ip\",\"\")
            if not ip.startswith(\"192.168.\") and not ip.startswith(\"127.\"): ips[ip] += 1
        except: continue
for ip, _ in ips.most_common(3): print(ip)
" 2>/dev/null)
    if [[ -n "$TOP3" ]]; then
        CTI=$(python3 /opt/honeyai/scripts/parse-cti.py "$TOP3" 2>/dev/null || true)
        [[ -n "$CTI" ]] && curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" -d text="🧠 <b>CTI Top atacantes</b>
$CTI" -d parse_mode="HTML" >/dev/null 2>&1
    fi
fi
