#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# 🎓 Honeypot Auto-Graduate — "Juega, aprende, y a la calle"
# ═══════════════════════════════════════════════════════════════
# Cuando una IP supera el umbral de eventos en los honeypots,
# se "gradúa": ban total en CrowdSec + bloqueo en iptables
# ANTES del bypass de honeypots. Ya no vuelve a entrar.
#
# Cron: 0 * * * * /opt/honeyai/scripts/honeypot-graduate.sh
# ═══════════════════════════════════════════════════════════════
set -Eeo pipefail

source /opt/honeyai/scripts/.env

# === CONFIGURACIÓN ===
THRESHOLD=200                    # Eventos para "graduar" una IP
BAN_DURATION="2160h"             # 90 días de ban (3 meses)

# IPs que NUNCA se deben banear (DNS, CDN, infra conocida)
WHITELIST="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220"
GRADUATED_FILE="/opt/honeyai/scripts/honeypot-graduated.txt"
IPTABLES_CHAIN="HONEYPOT_GRADUATED"
OPENCANARY_LOG="/var/lib/docker/volumes/opencanary_opencanary-logs/_data/opencanary.log"
LOG_FILE="/opt/honeyai/honeypot-graduate.log"
TMP_COUNTS="/tmp/.honeypot-grad-counts"

touch "$GRADUATED_FILE"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" | tee -a "$LOG_FILE"
}

send_telegram() {
  local msg="$1"
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" -d text="$msg" -d parse_mode="HTML" >/dev/null 2>&1 || true
}

# === 1. Crear chain iptables si no existe ===
if ! sudo iptables -L "$IPTABLES_CHAIN" -n >/dev/null 2>&1; then
  sudo iptables -N "$IPTABLES_CHAIN"
  log "Created iptables chain $IPTABLES_CHAIN"
fi

# Insertar chain ANTES del bypass de honeypots (posición 1)
if ! sudo iptables -C INPUT -j "$IPTABLES_CHAIN" 2>/dev/null; then
  sudo iptables -I INPUT 1 -j "$IPTABLES_CHAIN"
  log "Inserted $IPTABLES_CHAIN as INPUT rule #1 (before honeypot bypass)"
fi

# === 2. Recoger IPs con conteo de eventos (últimas 24h) ===
# Usar fichero temporal para evitar problemas con subshells
: > "$TMP_COUNTS"

# HoneyAI events
HONEYAI_EVENTS_FILE="/opt/honeyai/logs/events.json"
if [ -f "$HONEYAI_EVENTS_FILE" ]; then
  python3 -c "
import json
from datetime import datetime, timedelta
from collections import Counter
cutoff = datetime.now() - timedelta(hours=24)
ips = Counter()
try:
    with open('$HONEYAI_EVENTS_FILE', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                ts_str = e.get('timestamp','')
                if not ts_str: continue
                # Parse ISO timestamp securely
                ts_str_clean = ts_str.rstrip('Z').split('.')[0]
                ts = datetime.strptime(ts_str_clean, '%Y-%m-%dT%H:%M:%S')
                if ts < cutoff: continue
                ip = e.get('ip','')
                if ip and not ip.startswith('192.168.') and not ip.startswith('10.') and ip != '127.0.0.1':
                    ips[ip] += 1
            except: pass
except: pass
for ip, c in ips.items():
    print(f'{ip} {c}')
" 2>/dev/null >> "$TMP_COUNTS" || true
fi

# Consolidar: sumar conteos por IP
CONSOLIDATED="/tmp/.honeypot-grad-consolidated"
awk '{ip[$1]+=$2} END {for(i in ip) print i, ip[i]}' "$TMP_COUNTS" | sort -k2 -rn > "$CONSOLIDATED"

# === 3. Graduar IPs que superan el umbral ===
NEW_GRADS=0
GRAD_MSG=""
TOTAL_ACTIVE=0

while read -r ip count; do
  [ -z "$ip" ] && continue
  TOTAL_ACTIVE=$((TOTAL_ACTIVE + 1))

  # ¿Ya graduada?
  grep -q "^${ip}$" "$GRADUATED_FILE" 2>/dev/null && continue

  # ¿Whitelist?
  echo "$WHITELIST" | grep -qw "$ip" && continue

  if [ "$count" -ge "$THRESHOLD" ] 2>/dev/null; then
    log "🎓 GRADUATING $ip — $count events in 24h (threshold: $THRESHOLD)"

    # Ban en CrowdSec (90 días)
    sudo cscli decisions add -i "$ip" -d "$BAN_DURATION" \
      -R "honeypot:auto-graduated ($count events)" -t ban 2>/dev/null || true

    # Bloquear ANTES del bypass de honeypots
    if ! sudo iptables -C "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null; then
      sudo iptables -A "$IPTABLES_CHAIN" -s "$ip" -j DROP
    fi

    # Registrar como graduada
    printf '%s\n' "$ip" >> "$GRADUATED_FILE"
    NEW_GRADS=$((NEW_GRADS + 1))
    GRAD_MSG="${GRAD_MSG}  🎓 <code>${ip}</code> — ${count} eventos
"

    log "  ✅ Banned in CrowdSec ($BAN_DURATION) + blocked in iptables"
  fi
done < "$CONSOLIDATED"

# === 4. Restaurar graduados previos en iptables (por si reboot) ===
while IFS= read -r ip; do
  [ -z "$ip" ] && continue
  [[ "$ip" == \#* ]] && continue
  if ! sudo iptables -C "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null; then
    sudo iptables -A "$IPTABLES_CHAIN" -s "$ip" -j DROP
    log "  ♻️ Restored iptables block for graduated IP: $ip"
  fi
done < "$GRADUATED_FILE"

# === 5. Stats y notificación ===
TOTAL_GRADUATED=$(wc -l < "$GRADUATED_FILE" | tr -d ' ')

if [ "$NEW_GRADS" -gt 0 ]; then
  send_telegram "🎓 <b>HONEYPOT AUTO-GRADUATE</b>

${NEW_GRADS} IP(s) graduadas (umbral: ${THRESHOLD} eventos/24h):
${GRAD_MSG}
📊 Total graduadas: ${TOTAL_GRADUATED}
🍯 IPs activas en honeypots: $((TOTAL_ACTIVE - NEW_GRADS))

Ban: ${BAN_DURATION} | Bloqueadas a nivel iptables"
fi

log "Run complete: $NEW_GRADS new graduates, $TOTAL_GRADUATED total, $TOTAL_ACTIVE active IPs"

# Cleanup
rm -f "$TMP_COUNTS" "$CONSOLIDATED"
