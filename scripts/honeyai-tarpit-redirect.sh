#!/usr/bin/env bash
# honeyai-tarpit-redirect.sh
# Host-level active defense script for OpenClaw HoneyAI.
# Redirects offending IPs logged in events.json to a local Endlessh tarpit.
# Run on the host (e.g. via crontab as root) to dynamically block attackers.

set -euo pipefail

# Configuration (can be overridden by environment variables)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVENTS_FILE="${HONEYAI_EVENTS_FILE:-$SCRIPT_DIR/../logs/events.json}"
TARPIT_PORT="${HONEYAI_TARPIT_PORT:-2224}"
STATE_FILE="${HONEYAI_STATE_FILE:-/tmp/honeyai-tarpited-ips.txt}"

# Ensure state file exists
touch "$STATE_FILE"

if [ ! -f "$EVENTS_FILE" ]; then
    echo "Info: HoneyAI events file not found at $EVENTS_FILE"
    exit 0
fi

# Extract unique IPs with action: "tarpit" or severity: "critical"
if command -v jq >/dev/null 2>&1; then
    ips=$(jq -r 'select(.action == "tarpit" or .severity == "critical") | .ip' "$EVENTS_FILE" | grep -v 'null' | sort -u)
else
    ips=$(grep -E '"action"\s*:\s*"tarpit"|"severity"\s*:\s*"critical"' "$EVENTS_FILE" | grep -oE '"ip"\s*:\s*"[0-9.]+"' | sed -E 's/.*"([0-9.]+)".*/\1/' | sort -u)
fi

for ip in $ips; do
    # Validate IP format
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        continue
    fi

    # Check if already processed to save execution time
    if grep -qFx "$ip" "$STATE_FILE"; then
        continue
    fi

    echo "[Tarpit Redirect] Offending IP detected: $ip"

    # Check if the iptables rule already exists
    if sudo iptables -t nat -C PREROUTING -s "$ip" -p tcp -j REDIRECT --to-ports "$TARPIT_PORT" >/dev/null 2>&1; then
        echo "iptables rule already exists for $ip"
    else
        echo "Adding iptables REDIRECT rule for $ip to port $TARPIT_PORT"
        sudo iptables -t nat -A PREROUTING -s "$ip" -p tcp -j REDIRECT --to-ports "$TARPIT_PORT"
    fi

    # Append to state file
    echo "$ip" >> "$STATE_FILE"
done
