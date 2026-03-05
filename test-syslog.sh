#!/usr/bin/env bash
# =============================================================================
# Test Script — Send sample Sangfor NGAF fwlog entries to the collector
# Run this from any machine that can reach the collector VM on UDP 514
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_IP="${1:-127.0.0.1}"
TARGET_PORT="${2:-514}"

log() { echo -e "${GREEN}[SEND]${NC} $1"; }
warn() { echo -e "${YELLOW}[INFO]${NC} $1"; }

warn "Sending test fwlog messages to $TARGET_IP:$TARGET_PORT"
warn "Watch the collector with: tail -f /var/log/scalyr-agent-2/sangfor-ngaf.log"
echo ""

# Sample Sangfor NGAF fwlog messages
MESSAGES=(
  "<134>$(date '+%b %d %H:%M:%S') localhost fwlog: Log type: APT detection, policy name:fwlogin, rule ID:0, src IP: 10.8.2.201, src port:50815, dst IP: 8.8.8.8, dst port: 53, attack type: Botnet, threat level:Information, action:Denied, URL:pool.hashvault.pro"
  "<134>$(date '+%b %d %H:%M:%S') localhost fwlog: Log Type: traffic audit, App Category:Gmail[Browse], Username/Host:10.63.44.25, Outbound(B):18376, Inbound(B):10572, Bidirectional(B):28948"
  "<134>$(date '+%b %d %H:%M:%S') localhost fwlog: Log type: IPS, policy name:default, src IP: 192.168.1.10, src port:4444, dst IP: 10.0.0.1, dst port: 80, attack type: SQL Injection, threat level:High, action:Denied"
  "<134>$(date '+%b %d %H:%M:%S') localhost fwlog: Log type: URL filter, src IP: 10.1.1.50, dst IP: 93.184.216.34, action:Denied, URL:malware-site.com, threat level:Critical"
  "<134>$(date '+%b %d %H:%M:%S') localhost fwlog: Log type: user auth, Username/Host:john.doe, src IP: 10.5.5.20, action:Allowed"
)

# Use /dev/udp if available (bash built-in), otherwise fall back to nc
send_syslog() {
  local msg="$1"
  if command -v nc &>/dev/null; then
    echo "$msg" | nc -u -w1 "$TARGET_IP" "$TARGET_PORT"
  elif [[ -w /dev/udp ]]; then
    echo "$msg" > /dev/udp/"$TARGET_IP"/"$TARGET_PORT"
  else
    warn "Neither 'nc' nor /dev/udp available. Install netcat: apt install netcat-openbsd"
    exit 1
  fi
}

for i in "${!MESSAGES[@]}"; do
  MSG="${MESSAGES[$i]}"
  send_syslog "$MSG"
  log "Sent message $((i+1))/$(( ${#MESSAGES[@]} )): ${MSG:50:60}..."
  sleep 0.5
done

echo ""
warn "Done. Verify on collector:"
warn "  tail -f /var/log/scalyr-agent-2/sangfor-ngaf.log"
warn "  tail -f /var/log/scalyr-agent-2/sangfor-ngaf-parsed.log"
