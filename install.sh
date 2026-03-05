#!/usr/bin/env bash
# =============================================================================
# Sangfor NGAF → SentinelOne SDL — Collector Setup
# Version: 3.0
# Supports: Ubuntu 22.04, Ubuntu 24.04, Rocky Linux 9 / AlmaLinux 9
#
# Fixes in v3:
#   BUG1 — deploy_parser_config() no longer looks for external file;
#           creates /opt/config/sangfor-ngaf-parser.json inline
#   BUG2 — Unsupported installer flags removed; agent.json written ourselves
#   BUG3 — configs.d dir created with mkdir -p before any copy attempt
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

AGENT_CONF="/etc/scalyr-agent-2/agent.json"
PARSER_DIR="/etc/scalyr-agent-2/configs.d"
OPT_CONFIG_DIR="/opt/config"
PARSER_CONFIG_FILE="$OPT_CONFIG_DIR/sangfor-ngaf-parser.json"
LOG_FILE="/var/log/sangfor-s1-install.log"

# FIX: init log file before any tee -a call.
# Without this, tee -a fails if /var/log isn't writable (e.g. non-root run
# before check_root fires), and set -e silently kills the script.
init_logfile() {
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
}

log()   { echo -e "${GREEN}[OK]${NC}  $1" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }

# ── Banner ────────────────────────────────────────────────────────────────
banner() {
  echo ""
  echo "============================================================"
  echo "  Sangfor NGAF → SentinelOne SDL  |  Setup Kit  v3.0"
  echo "============================================================"
  echo ""
}

# ── Checks ────────────────────────────────────────────────────────────────
check_root() {
  [[ "$EUID" -ne 0 ]] && error "Run as root: sudo bash install.sh"
}

detect_os() {
  [[ -f /etc/os-release ]] && . /etc/os-release || error "Cannot detect OS."
  OS=$ID; VER=$VERSION_ID
  info "Detected OS: $OS $VER"
}

# Portable IP — works on Ubuntu and Rocky (hostname -I is not portable)
get_local_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' \
    || ip addr show | awk '/inet / && !/127.0.0.1/{print $2}' | cut -d/ -f1 | head -1 \
    || echo "<YOUR_VM_IP>"
}

# ── Credentials prompt ────────────────────────────────────────────────────
prompt_credentials() {
  echo ""
  echo "  ── SentinelOne Credentials ──────────────────────────────"
  echo "  Get your Write API Key:"
  echo "    S1 Console → Settings → API Keys → Log Access Keys → Add"
  echo ""
  read -rp "  S1 Write API Key: " S1_API_KEY
  [[ -z "$S1_API_KEY" ]] && error "API key cannot be empty."

  echo ""
  echo "  Ingest URL (your region):"
  echo "    https://xdr.us1.sentinelone.net"
  echo "    https://xdr.eu1.sentinelone.net"
  echo ""
  read -rp "  S1 Ingest URL (include https://): " S1_URL
  [[ -z "$S1_URL" ]] && error "Ingest URL cannot be empty."
  S1_URL="${S1_URL%/}"  # strip trailing slash

  read -rp "  Syslog listen port [default: 514]: " SYSLOG_PORT
  SYSLOG_PORT="${SYSLOG_PORT:-514}"

  read -rp "  Collector hostname label [default: sangfor-collector]: " SERVER_HOST
  SERVER_HOST="${SERVER_HOST:-sangfor-collector}"

  echo ""
  info "API Key : ${S1_API_KEY:0:8}... (truncated)"
  info "URL     : $S1_URL"
  info "Port    : $SYSLOG_PORT"
  info "Host    : $SERVER_HOST"
}

# ── Dependencies ──────────────────────────────────────────────────────────
install_deps_ubuntu() {
  info "Installing dependencies (Ubuntu)..."
  apt-get update -qq
  apt-get install -y -qq curl wget python3 python3-pip \
    iproute2 netcat-openbsd >> "$LOG_FILE" 2>&1
  log "Dependencies ready."
}

install_deps_rocky() {
  info "Installing dependencies (Rocky/RHEL)..."
  dnf install -y -q curl wget python3 python3-pip \
    iproute nmap-ncat >> "$LOG_FILE" 2>&1
  log "Dependencies ready."
}

# ── Scalyr Agent ──────────────────────────────────────────────────────────
install_scalyr_agent() {
  info "Installing Scalyr Agent 2 (SentinelOne Collector)..."

  if command -v scalyr-agent-2 &>/dev/null; then
    warn "Scalyr Agent already installed — skipping install, updating config only."
    return
  fi

  curl -fsSL \
    https://www.scalyr.com/scalyr-repo/stable/latest/install-scalyr-agent-2.sh \
    -o /tmp/install-scalyr.sh >> "$LOG_FILE" 2>&1 \
    || error "Download failed. Check internet connectivity."

  # BUG2 FIX: run plain — no --set-scalyr-server / --set-api-key flags
  # (those flags are not supported). We write our own agent.json after install.
  bash /tmp/install-scalyr.sh >> "$LOG_FILE" 2>&1 \
    || error "Scalyr Agent install failed. See: $LOG_FILE"

  rm -f /tmp/install-scalyr.sh
  log "Scalyr Agent 2 installed."
}

# ── agent.json ────────────────────────────────────────────────────────────
configure_agent() {
  info "Writing /etc/scalyr-agent-2/agent.json ..."

  # Backup existing config
  [[ -f "$AGENT_CONF" ]] && \
    cp "$AGENT_CONF" "${AGENT_CONF}.bak.$(date +%s)" && \
    info "Backed up existing agent.json"

  # BUG3 FIX: mkdir -p ensures configs.d exists before anything tries to use it
  mkdir -p "$PARSER_DIR"

  cat > "$AGENT_CONF" <<EOF
{
  // Sangfor NGAF → SentinelOne SDL Collector
  // Generated by sangfor-s1-kit install.sh v3.0

  api_key: "$S1_API_KEY",
  scalyr_server: "$S1_URL",

  server_attributes: {
    serverHost: "$SERVER_HOST",
    role: "sangfor-ngaf-collector",
    version: "3.0"
  },

  logs: [
    {
      path: "/var/log/scalyr-agent-2/sangfor-ngaf.log",
      attributes: {
        parser: "sangfor-ngaf",
        source: "sangfor_firewall",
        log_format: "raw_fwlog"
      }
    },
    {
      path: "/var/log/scalyr-agent-2/sangfor-ngaf-parsed.log",
      attributes: {
        parser: "sangfor-ngaf-parsed",
        source: "sangfor_firewall",
        log_format: "json"
      }
    }
  ],

  monitors: [
    {
      module: "scalyr_agent.builtin_monitors.syslog_monitor",
      protocols: "udp:$SYSLOG_PORT, tcp:$SYSLOG_PORT",
      accept_remote_connections: true,
      message_log: "sangfor-ngaf.log",
      parser: "sangfor-ngaf",
      log_rotation_max_bytes: 20971520,
      log_rotation_backup_count: 5
    }
  ]
}
EOF
  log "agent.json written to $AGENT_CONF"
}

# ── Parser config — BUG1 FIX ──────────────────────────────────────────────
# Creates the CEF field mapping config inline — no longer looks for
# an external file that may not exist on a fresh system.
create_parser_config() {
  info "Creating parser config at $PARSER_CONFIG_FILE ..."

  # BUG1 FIX: create /opt/config/ and write the file here — self-contained
  mkdir -p "$OPT_CONFIG_DIR"

  cat > "$PARSER_CONFIG_FILE" <<'EOF'
{
  "formats": [
    { "id": "sangfor-src",   "format": "src=$src$ "   },
    { "id": "sangfor-dst",   "format": "dst=$dst$ "   },
    { "id": "sangfor-act",   "format": "act=$act$ "   },
    { "id": "sangfor-app",   "format": "app=$app$ "   },
    { "id": "sangfor-proto", "format": "proto=$proto$ " },
    { "id": "sangfor-suser", "format": "suser=$suser$ " },
    { "id": "sangfor-spt",   "format": "spt=$spt$ "   },
    { "id": "sangfor-dpt",   "format": "dpt=$dpt$ "   },
    { "id": "sangfor-out",   "format": "out=$out$ "   },
    { "id": "sangfor-in",    "format": "in=$in$ "     }
  ]
}
EOF

  log "Parser config created: $PARSER_CONFIG_FILE"

  # Also copy into Scalyr configs.d so agent picks it up
  cp "$PARSER_CONFIG_FILE" "$PARSER_DIR/sangfor-ngaf-parser.json"
  log "Parser config deployed to $PARSER_DIR"
}

# ── Firewall ──────────────────────────────────────────────────────────────
open_firewall_port() {
  info "Opening firewall port $SYSLOG_PORT (UDP + TCP)..."

  case "$OS" in
    ubuntu)
      if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$SYSLOG_PORT"/udp >> "$LOG_FILE" 2>&1
        ufw allow "$SYSLOG_PORT"/tcp >> "$LOG_FILE" 2>&1
        log "UFW: port $SYSLOG_PORT opened."
      else
        warn "UFW not active — open port $SYSLOG_PORT manually if needed."
      fi
      ;;
    rocky|rhel|centos|almalinux)
      if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="$SYSLOG_PORT"/udp >> "$LOG_FILE" 2>&1
        firewall-cmd --permanent --add-port="$SYSLOG_PORT"/tcp >> "$LOG_FILE" 2>&1
        firewall-cmd --reload >> "$LOG_FILE" 2>&1
        log "firewalld: port $SYSLOG_PORT opened."
      else
        warn "firewalld not active — open port $SYSLOG_PORT manually if needed."
      fi
      ;;
  esac
}

# ── Agent start ───────────────────────────────────────────────────────────
start_agent() {
  info "Enabling and starting Scalyr Agent..."
  systemctl enable scalyr-agent-2 >> "$LOG_FILE" 2>&1
  systemctl restart scalyr-agent-2 >> "$LOG_FILE" 2>&1
  sleep 3

  if systemctl is-active --quiet scalyr-agent-2; then
    log "Scalyr Agent is running."
  else
    error "Agent failed to start. Run: journalctl -u scalyr-agent-2 -n 50"
  fi
}

verify_port_listening() {
  info "Verifying listener on port $SYSLOG_PORT..."
  sleep 2
  if ss -ulnp 2>/dev/null | grep -q ":${SYSLOG_PORT}[[:space:]]" || \
     ss -tlnp 2>/dev/null | grep -q ":${SYSLOG_PORT}[[:space:]]"; then
    log "Confirmed: listening on port $SYSLOG_PORT"
  else
    warn "Port not yet visible in ss — may take a few seconds to bind."
  fi
}

# ── Summary ───────────────────────────────────────────────────────────────
print_next_steps() {
  local MY_IP; MY_IP=$(get_local_ip)

  echo ""
  echo "============================================================"
  echo -e "${GREEN}  INSTALL COMPLETE — v3.0${NC}"
  echo "============================================================"
  echo ""
  echo "  Files created:"
  echo "    $PARSER_CONFIG_FILE"
  echo "    $PARSER_DIR/sangfor-ngaf-parser.json"
  echo "    $AGENT_CONF"
  echo ""
  echo "  STEP 1 — Deploy parser service:"
  echo "    sudo bash $(cd "$(dirname "$0")" && pwd)/deploy-parser.sh"
  echo ""
  echo "  STEP 2 — Configure Sangfor NGAF syslog:"
  echo "    NGAF v6.5+: System → Logging Options → Syslog Server tab"
  echo "    NGAF v6.4-: System → Logging Options → Syslog → Enable"
  echo ""
  echo "    Destination IP : $MY_IP"
  echo "    Port           : $SYSLOG_PORT"
  echo ""
  echo "  STEP 3 — Create 'sangfor-ngaf' parser in SentinelOne SDL console"
  echo "           (rules documented in docs/README.md)"
  echo ""
  echo "  Verify:"
  echo "    sudo scalyr-agent-2 status"
  echo "    sudo tail -f /var/log/scalyr-agent-2/sangfor-ngaf.log"
  echo "    sudo bash $(cd "$(dirname "$0")" && pwd)/test-syslog.sh $MY_IP $SYSLOG_PORT"
  echo ""
  echo "  Install log: $LOG_FILE"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
init_logfile   # must be first — ensures tee -a never fails under set -e
banner
check_root
detect_os
prompt_credentials

case "$OS" in
  ubuntu)
    install_deps_ubuntu ;;
  rocky|rhel|centos|almalinux)
    install_deps_rocky ;;
  *)
    error "Unsupported OS: $OS. Use Ubuntu 22.04/24.04 or Rocky Linux 9." ;;
esac

install_scalyr_agent
configure_agent
create_parser_config   # BUG1 FIX: replaces old deploy_parser_config()
open_firewall_port
start_agent
verify_port_listening
print_next_steps
