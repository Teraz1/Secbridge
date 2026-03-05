#!/usr/bin/env bash
# =============================================================================
# SecBridge — Source Management Script
# Manages multiple syslog sources, firewall rules, and agent config
#
# Usage:
#   sudo bash manage-sources.sh list            — show all configured sources
#   sudo bash manage-sources.sh add             — interactive: add a new source
#   sudo bash manage-sources.sh apply           — apply sources.json → firewall + agent.json
#   sudo bash manage-sources.sh status          — show port listeners and service status
#   sudo bash manage-sources.sh remove <id>     — disable a source by ID
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()   { echo -e "${GREEN}[OK]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERR]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
title() { echo -e "\n${CYAN}── $1 ──${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/../config/sources.json"
AGENT_CONF="/etc/scalyr-agent-2/agent.json"
LOG_DIR="/var/log/scalyr-agent-2"
MANAGE_LOG="/var/log/secbridge-manage.log"

# FIX: init log file before any tee -a — prevents silent exit under set -e
mkdir -p "$(dirname "$MANAGE_LOG")" 2>/dev/null || true
touch "$MANAGE_LOG" 2>/dev/null || MANAGE_LOG="/dev/null"

[[ ! -f "$CONFIG_FILE" ]] && error "sources.json not found at $CONFIG_FILE"

PYTHON_BIN=$(command -v python3 || error "python3 not found")

# ── Helper: read sources.json via Python ──────────────────────────────────
read_sources() {
  $PYTHON_BIN - "$CONFIG_FILE" << 'PYEOF'
import json, sys

# Strip JS-style // comments before parsing
def strip_comments(text):
    import re
    return re.sub(r'//.*', '', text)

with open(sys.argv[1]) as f:
    data = json.loads(strip_comments(f.read()))

sources = data['secbridge']['sources']
for s in sources:
    enabled = "true" if s.get('enabled', True) else "false"
    ips = ','.join(s.get('allowed_ips', [])) or 'any'
    print(f"{s['id']}|{enabled}|{s['name']}|{s['product']}|{s['syslog_port']}|{s['protocol']}|{ips}|{s['log_file']}|{s['parser_name']}")
PYEOF
}

# ── COMMAND: list ─────────────────────────────────────────────────────────
cmd_list() {
  title "Configured Sources"
  printf "\n  %-4s %-8s %-25s %-20s %-6s %-6s %-15s\n" "ID" "STATUS" "NAME" "PRODUCT" "PORT" "PROTO" "ALLOWED IPS"
  printf "  %-4s %-8s %-25s %-20s %-6s %-6s %-15s\n" "---" "-------" "------------------------" "-------------------" "-----" "-----" "--------------"

  while IFS='|' read -r id enabled name product port proto ips logfile parser; do
    status_color="$GREEN"; status_label="enabled"
    [[ "$enabled" == "false" ]] && status_color="$RED" && status_label="disabled"
    printf "  %-4s ${status_color}%-8s${NC} %-25s %-20s %-6s %-6s %-15s\n" \
      "$id" "$status_label" "$name" "$product" "$port" "$proto" "$ips"
  done < <(read_sources)
  echo ""
}

# ── COMMAND: add ──────────────────────────────────────────────────────────
cmd_add() {
  title "Add New Syslog Source"
  echo ""

  # Get next ID
  LAST_ID=$(read_sources | awk -F'|' '{print $1}' | sort -n | tail -1)
  NEXT_ID=$(printf "%03d" $(( 10#$LAST_ID + 1 )))

  # Get used ports
  USED_PORTS=$(read_sources | awk -F'|' '{print $5}' | tr '\n' ' ')
  echo "  Currently used ports: $USED_PORTS"
  echo "  NOTE: each source needs a unique port on this collector VM."
  echo ""

  read -rp "  Product name (e.g. fortinet-fortigate): " NEW_PRODUCT
  [[ -z "$NEW_PRODUCT" ]] && error "Product name required."

  read -rp "  Display name (e.g. Fortinet FortiGate): " NEW_NAME
  [[ -z "$NEW_NAME" ]] && error "Display name required."

  read -rp "  Syslog port [e.g. 5140]: " NEW_PORT
  [[ -z "$NEW_PORT" ]] && error "Port required."

  # Check port not already used
  if echo "$USED_PORTS" | grep -qw "$NEW_PORT"; then
    error "Port $NEW_PORT already in use. Choose a different port."
  fi

  read -rp "  Protocol [udp/tcp/both, default: udp]: " NEW_PROTO
  NEW_PROTO="${NEW_PROTO:-udp}"

  read -rp "  Allowed IPs from this device (e.g. 192.168.1.1 — leave blank to allow any): " NEW_IPS

  read -rp "  Parser script path (leave blank if not yet built): " NEW_PARSER_SCRIPT
  NEW_PARSER_SCRIPT="${NEW_PARSER_SCRIPT:-/opt/secbridge/parser/${NEW_PRODUCT}_parser.py}"

  read -rp "  Description: " NEW_DESC

  # Build allowed_ips JSON array
  if [[ -z "$NEW_IPS" ]]; then
    IPS_JSON="[]"
  else
    IPS_JSON="[\"$(echo $NEW_IPS | sed 's/ /", "/g')\"]"
  fi

  NEW_LOG_FILE="${NEW_PRODUCT}.log"
  NEW_PARSED_LOG="${NEW_PRODUCT}-parsed.log"
  NEW_PARSER_NAME="${NEW_PRODUCT}"

  # Append new source to sources.json using Python
  $PYTHON_BIN - "$CONFIG_FILE" "$NEXT_ID" "$NEW_PRODUCT" "$NEW_NAME" \
    "$NEW_PORT" "$NEW_PROTO" "$IPS_JSON" "$NEW_LOG_FILE" \
    "$NEW_PARSED_LOG" "$NEW_PARSER_SCRIPT" "$NEW_PARSER_NAME" "$NEW_DESC" << 'PYEOF'
import json, sys, re

def strip_comments(text):
    return re.sub(r'//.*', '', text)

config_path = sys.argv[1]
with open(config_path) as f:
    data = json.loads(strip_comments(f.read()))

ips_raw = sys.argv[6]
try:
    allowed_ips = json.loads(ips_raw)
except:
    allowed_ips = []

new_source = {
    "id":                sys.argv[2],
    "enabled":           True,
    "name":              sys.argv[3],
    "product":           sys.argv[4],
    "description":       sys.argv[12],
    "allowed_ips":       allowed_ips,
    "syslog_port":       int(sys.argv[5]),
    "protocol":          sys.argv[6] if sys.argv[6] in ['udp','tcp','both'] else 'udp',
    "log_file":          sys.argv[7],
    "parsed_log_file":   sys.argv[8],
    "parser_script":     sys.argv[9],
    "parser_name":       sys.argv[10],
    "log_type":          "firewall"
}

# Fix protocol from positional args
new_source["protocol"] = sys.argv[6] if sys.argv[6] in ['udp','tcp','both'] else 'udp'

data['secbridge']['sources'].append(new_source)

with open(config_path, 'w') as f:
    json.dump(data, f, indent=2)

print(f"Source {new_source['id']} ({new_source['name']}) added to sources.json")
PYEOF

  echo ""
  log "Source $NEXT_ID ($NEW_NAME) added to sources.json"
  warn "Run 'sudo bash manage-sources.sh apply' to activate it."
  echo ""
}

# ── COMMAND: apply ────────────────────────────────────────────────────────
cmd_apply() {
  [[ "$EUID" -ne 0 ]] && error "Apply requires root: sudo bash manage-sources.sh apply"

  title "Applying sources.json → Firewall + Agent Config"

  # Read API key and URL from existing agent.json
  API_KEY=""
  SCALYR_SERVER=""
  if [[ -f "$AGENT_CONF" ]]; then
    API_KEY=$($PYTHON_BIN -c "
import re
with open('$AGENT_CONF') as f: t = re.sub(r'//.*','',f.read())
import json; d=json.loads(t)
print(d.get('api_key',''))
" 2>/dev/null || true)
    SCALYR_SERVER=$($PYTHON_BIN -c "
import re
with open('$AGENT_CONF') as f: t = re.sub(r'//.*','',f.read())
import json; d=json.loads(t)
print(d.get('scalyr_server',''))
" 2>/dev/null || true)
  fi

  if [[ -z "$API_KEY" || -z "$SCALYR_SERVER" ]]; then
    warn "Could not read API key/URL from existing agent.json."
    read -rp "  Enter S1 API Key: " API_KEY
    read -rp "  Enter S1 Ingest URL: " SCALYR_SERVER
  else
    info "Using existing credentials from agent.json."
  fi

  # Detect OS for firewall management
  OS="unknown"
  [[ -f /etc/os-release ]] && . /etc/os-release && OS=$ID

  info "Building agent.json monitors and logs from sources.json..."

  # Generate agent.json via Python
  $PYTHON_BIN - "$CONFIG_FILE" "$AGENT_CONF" "$API_KEY" "$SCALYR_SERVER" "$LOG_DIR" << 'PYEOF'
import json, sys, re, os

def strip_comments(text):
    return re.sub(r'//.*', '', text)

config_path   = sys.argv[1]
agent_path    = sys.argv[2]
api_key       = sys.argv[3]
scalyr_server = sys.argv[4]
log_dir       = sys.argv[5]

with open(config_path) as f:
    data = json.loads(strip_comments(f.read()))

sources = [s for s in data['secbridge']['sources'] if s.get('enabled', True)]

logs_block    = []
monitors_block = []

for s in sources:
    proto = s['protocol']
    port  = s['syslog_port']

    # Build protocols string
    if proto == 'both':
        protocols_str = f"udp:{port}, tcp:{port}"
    else:
        protocols_str = f"{proto}:{port}"

    # Ensure log dir exists
    os.makedirs(log_dir, exist_ok=True)

    # Log entry for raw syslog
    logs_block.append({
        "path": f"{log_dir}/{s['log_file']}",
        "attributes": {
            "parser":     s['parser_name'],
            "source":     s['product'],
            "source_id":  s['id'],
            "log_format": "raw_syslog"
        }
    })

    # Log entry for parsed JSON
    logs_block.append({
        "path": f"{log_dir}/{s['parsed_log_file']}",
        "attributes": {
            "parser":     f"{s['parser_name']}-parsed",
            "source":     s['product'],
            "source_id":  s['id'],
            "log_format": "json"
        }
    })

    # Monitor entry
    monitor = {
        "module":                    "scalyr_agent.builtin_monitors.syslog_monitor",
        "protocols":                 protocols_str,
        "accept_remote_connections": True,
        "message_log":               s['log_file'],
        "parser":                    s['parser_name'],
        "log_rotation_max_bytes":    20971520,
        "log_rotation_backup_count": 5
    }
    monitors_block.append(monitor)

agent_config = {
    "api_key":      api_key,
    "scalyr_server": scalyr_server,
    "server_attributes": {
        "serverHost": "secbridge-collector",
        "role":       "multi-source-collector"
    },
    "logs":     logs_block,
    "monitors": monitors_block
}

# Backup existing
if os.path.exists(agent_path):
    import shutil, time
    shutil.copy(agent_path, f"{agent_path}.bak.{int(time.time())}")

with open(agent_path, 'w') as f:
    json.dump(agent_config, f, indent=2)

print(f"agent.json written with {len(sources)} source(s), {len(monitors_block)} monitor(s)")
PYEOF

  log "agent.json regenerated."

  # Open firewall ports for all enabled sources
  title "Opening Firewall Ports"
  while IFS='|' read -r id enabled name product port proto ips logfile parser; do
    [[ "$enabled" == "false" ]] && continue

    info "Source $id ($name) — port $port/$proto"

    case "$OS" in
      ubuntu)
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
          if [[ "$proto" == "both" ]]; then
            ufw allow "$port"/udp > /dev/null 2>&1 && ufw allow "$port"/tcp > /dev/null 2>&1
          else
            ufw allow "$port"/"$proto" > /dev/null 2>&1
          fi
          log "  UFW: port $port opened for $name"
        else
          warn "  UFW not active — open port $port manually"
        fi
        ;;
      rocky|rhel|centos|almalinux)
        if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
          if [[ "$proto" == "both" ]]; then
            firewall-cmd --permanent --add-port="$port"/udp > /dev/null 2>&1
            firewall-cmd --permanent --add-port="$port"/tcp > /dev/null 2>&1
          else
            firewall-cmd --permanent --add-port="$port"/"$proto" > /dev/null 2>&1
          fi
          log "  firewalld: port $port opened for $name"
        else
          warn "  firewalld not active — open port $port manually"
        fi
        ;;
      *)
        warn "  Unknown OS — open port $port/$proto manually for $name"
        ;;
    esac

    # Add IP-based restrict rule if allowed_ips defined
    if [[ "$ips" != "any" && -n "$ips" ]]; then
      IFS=',' read -ra IP_LIST <<< "$ips"
      for ip in "${IP_LIST[@]}"; do
        info "  Allowing syslog specifically from $ip"
        # Add iptables rule to only accept syslog from allowed IPs
        iptables -I INPUT -p udp --dport "$port" -s "$ip" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport "$port" -s "$ip" -j ACCEPT 2>/dev/null || true
        iptables -A INPUT -p udp --dport "$port" ! -s "$ip" -j DROP 2>/dev/null || true
      done
      log "  IP restriction applied for $name: allowed=$ips"
    fi

  done < <(read_sources)

  # Reload firewall
  case "$OS" in
    rocky|rhel|centos|almalinux)
      firewall-cmd --reload > /dev/null 2>&1 || true ;;
  esac

  # Restart Scalyr Agent
  title "Restarting Scalyr Agent"
  systemctl restart scalyr-agent-2 && sleep 3
  if systemctl is-active --quiet scalyr-agent-2; then
    log "Scalyr Agent restarted with new config."
  else
    error "Agent failed to restart — run: journalctl -u scalyr-agent-2 -n 50"
  fi

  echo ""
  log "All sources applied. Run 'manage-sources.sh status' to verify."
  echo ""
}

# ── COMMAND: status ───────────────────────────────────────────────────────
cmd_status() {
  title "SecBridge Collector Status"

  echo ""
  info "Scalyr Agent:"
  systemctl is-active scalyr-agent-2 &>/dev/null \
    && echo -e "  ${GREEN}● running${NC}" \
    || echo -e "  ${RED}● stopped${NC}"

  echo ""
  info "Listening ports:"
  ss -ulnp 2>/dev/null | grep -E ":[0-9]+" | grep -v "127.0.0.1" | \
    awk '{print "  UDP " $4}' | head -20 || true
  ss -tlnp 2>/dev/null | grep -E ":[0-9]+" | grep -v "127.0.0.1" | \
    awk '{print "  TCP " $4}' | head -20 || true

  echo ""
  info "Per-source log activity (last 3 lines each):"
  while IFS='|' read -r id enabled name product port proto ips logfile parser; do
    [[ "$enabled" == "false" ]] && continue
    LOG_PATH="/var/log/scalyr-agent-2/$logfile"
    echo -e "\n  ${CYAN}[$id] $name${NC} → $LOG_PATH"
    if [[ -f "$LOG_PATH" ]]; then
      tail -3 "$LOG_PATH" | sed 's/^/    /' || echo "    (empty)"
    else
      echo "    (log file not yet created — waiting for first event)"
    fi
  done < <(read_sources)
  echo ""
}

# ── COMMAND: remove ───────────────────────────────────────────────────────
cmd_remove() {
  [[ -z "${1:-}" ]] && error "Usage: manage-sources.sh remove <id>"
  TARGET_ID="$1"

  $PYTHON_BIN - "$CONFIG_FILE" "$TARGET_ID" << 'PYEOF'
import json, sys, re

def strip_comments(text):
    return re.sub(r'//.*', '', text)

config_path = sys.argv[1]
target_id   = sys.argv[2]

with open(config_path) as f:
    data = json.loads(strip_comments(f.read()))

sources = data['secbridge']['sources']
found = False
for s in sources:
    if s['id'] == target_id:
        s['enabled'] = False
        found = True
        print(f"Source {target_id} ({s['name']}) disabled.")

if not found:
    print(f"ERROR: Source ID {target_id} not found.", file=sys.stderr)
    sys.exit(1)

with open(config_path, 'w') as f:
    json.dump(data, f, indent=2)
PYEOF

  warn "Source $TARGET_ID disabled. Run 'sudo bash manage-sources.sh apply' to close its firewall port."
}

# ── COMMAND: help ─────────────────────────────────────────────────────────
cmd_help() {
  echo ""
  echo "  SecBridge — manage-sources.sh"
  echo ""
  echo "  Commands:"
  echo "    list              Show all configured sources"
  echo "    add               Interactively add a new syslog source"
  echo "    apply             Apply sources.json → opens ports + regenerates agent.json"
  echo "    status            Show live port listeners and recent log activity"
  echo "    remove <id>       Disable a source by its ID"
  echo ""
  echo "  Examples:"
  echo "    bash manage-sources.sh list"
  echo "    bash manage-sources.sh add"
  echo "    sudo bash manage-sources.sh apply"
  echo "    sudo bash manage-sources.sh remove 002"
  echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────
CMD="${1:-help}"
case "$CMD" in
  list)           cmd_list ;;
  add)            cmd_add ;;
  apply)          cmd_apply ;;
  status)         cmd_status ;;
  remove)         cmd_remove "${2:-}" ;;
  help|--help|-h) cmd_help ;;
  *)              error "Unknown command: $CMD. Run: manage-sources.sh help" ;;
esac
