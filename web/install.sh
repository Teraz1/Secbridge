#!/usr/bin/env bash
# =============================================================================
# SecBridge Web UI — Installer
# Installs FastAPI backend + React frontend as systemd services
#
# Usage: sudo bash install.sh
# Access: http://YOUR_IP:3000
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

INSTALL_DIR="/opt/secbridge/web"
API_PORT=8000
UI_PORT=3000
LOG_FILE="/var/log/secbridge-web-install.log"

init_log() {
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
}

log()   { echo -e "${GREEN}[OK]${NC}  $1" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERR]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
title() { echo -e "\n${CYAN}── $1 ──${NC}"; }

get_local_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' \
    || ip addr show | awk '/inet / && !/127.0.0.1/{print $2}' | cut -d/ -f1 | head -1 \
    || echo "YOUR_VM_IP"
}

banner() {
  echo ""
  echo "============================================================"
  echo "  SecBridge Web UI  |  Backend + Frontend Installer"
  echo "============================================================"
  echo ""
}

check_root() {
  [[ "$EUID" -ne 0 ]] && error "Run as root: sudo bash install.sh"
}

detect_os() {
  [[ -f /etc/os-release ]] && . /etc/os-release || error "Cannot detect OS"
  OS=$ID; VER=$VERSION_ID
  info "OS: $OS $VER"
}

# ── Install system deps ───────────────────────────────────────────────────
install_deps() {
  title "Installing Dependencies"
  case "$OS" in
    ubuntu)
      apt-get update -qq
      apt-get install -y -qq python3 python3-pip curl nodejs npm >> "$LOG_FILE" 2>&1
      ;;
    rocky|rhel|centos|almalinux)
      dnf install -y -q python3 python3-pip curl nodejs npm >> "$LOG_FILE" 2>&1
      ;;
    *)
      error "Unsupported OS: $OS"
      ;;
  esac
  log "System dependencies installed."
}

# ── Install Python backend deps ───────────────────────────────────────────
install_python_deps() {
  title "Installing Python Dependencies"
  pip install fastapi uvicorn python-multipart --break-system-packages \
    >> "$LOG_FILE" 2>&1
  log "FastAPI + Uvicorn installed."
}

# ── Install Node deps and build React ─────────────────────────────────────
build_frontend() {
  title "Building React Frontend"

  # Install frontend deps and build production bundle
  # FastAPI serves the dist/ directly — no separate 'serve' process needed
  cd "$INSTALL_DIR/frontend"
  npm install >> "$LOG_FILE" 2>&1
  npm run build >> "$LOG_FILE" 2>&1

  log "React frontend built at $INSTALL_DIR/frontend/dist"
}

# ── Copy files to install dir ─────────────────────────────────────────────
install_files() {
  title "Installing Files"

  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

  # Install web/ contents to /opt/secbridge/web/
  mkdir -p "$INSTALL_DIR"
  cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
  chmod +x "$INSTALL_DIR/install.sh"

  # Install repo root folders that backend.py depends on:
  #   config/sources.json   → BASE_DIR/config/
  #   scripts/              → BASE_DIR/scripts/
  #   integrations/         → BASE_DIR/integrations/
  BASE_INSTALL="$(dirname "$INSTALL_DIR")"   # /opt/secbridge

  if [[ -d "$REPO_ROOT/config" ]]; then
    mkdir -p "$BASE_INSTALL/config"
    cp -rn "$REPO_ROOT/config/." "$BASE_INSTALL/config/" 2>/dev/null || true
    log "config/ installed to $BASE_INSTALL/config/"
  else
    warn "config/ not found in repo root — create $BASE_INSTALL/config/sources.json manually"
    mkdir -p "$BASE_INSTALL/config"
    cat > "$BASE_INSTALL/config/sources.json" <<'SRCEOF'
{
  "secbridge": {
    "version": "1.0",
    "destination": {"type": "sentinelone_sdl", "ingest_url": "", "api_key": ""},
    "sources": []
  }
}
SRCEOF
    log "Empty sources.json created at $BASE_INSTALL/config/sources.json"
  fi

  if [[ -d "$REPO_ROOT/scripts" ]]; then
    mkdir -p "$BASE_INSTALL/scripts"
    cp -r "$REPO_ROOT/scripts/." "$BASE_INSTALL/scripts/"
    chmod +x "$BASE_INSTALL/scripts/"*.sh 2>/dev/null || true
    log "scripts/ installed to $BASE_INSTALL/scripts/"
  else
    warn "scripts/ not found — manage-sources.sh will not be available"
  fi

  if [[ -d "$REPO_ROOT/integrations" ]]; then
    mkdir -p "$BASE_INSTALL/integrations"
    cp -r "$REPO_ROOT/integrations/." "$BASE_INSTALL/integrations/"
    log "integrations/ installed to $BASE_INSTALL/integrations/"
  else
    warn "integrations/ not found — parser files will not be available"
  fi

  # Add sudoers entries so backend can run manage-sources.sh and restart agent
  SUDOERS_FILE="/etc/sudoers.d/secbridge"
  if [[ ! -f "$SUDOERS_FILE" ]]; then
    cat > "$SUDOERS_FILE" <<EOF
# SecBridge Web UI — allow backend to manage sources and restart agent
root ALL=(ALL) NOPASSWD: /bin/bash $BASE_INSTALL/scripts/manage-sources.sh
www-data ALL=(ALL) NOPASSWD: /bin/bash $BASE_INSTALL/scripts/manage-sources.sh
root ALL=(ALL) NOPASSWD: /bin/systemctl restart scalyr-agent-2
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart scalyr-agent-2
EOF
    chmod 440 "$SUDOERS_FILE"
    log "sudoers entry created: $SUDOERS_FILE"
  fi

  log "Files installed to $INSTALL_DIR"
}

# ── Create systemd service — Backend ─────────────────────────────────────
install_backend_service() {
  title "Creating SecBridge Service"

  UVICORN_BIN=$(command -v uvicorn || echo "uvicorn")

  cat > /etc/systemd/system/secbridge.service <<EOF
[Unit]
Description=SecBridge Web UI + API
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$UVICORN_BIN backend:app --host 0.0.0.0 --port $UI_PORT
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secbridge

[Install]
WantedBy=multi-user.target
EOF

  log "secbridge.service created (port $UI_PORT — serves UI + API together)."
}

# (Frontend is served by FastAPI — no separate UI service needed)

# ── Open firewall ports ───────────────────────────────────────────────────
open_ports() {
  title "Opening Firewall Ports"

  case "$OS" in
    ubuntu)
      if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow $UI_PORT/tcp >> "$LOG_FILE" 2>&1
        log "UFW: port $UI_PORT opened."
      else
        warn "UFW not active — open port $UI_PORT manually if needed."
      fi
      ;;
    rocky|rhel|centos|almalinux)
      if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=$UI_PORT/tcp >> "$LOG_FILE" 2>&1
        firewall-cmd --reload >> "$LOG_FILE" 2>&1
        log "firewalld: port $UI_PORT opened."
      else
        warn "firewalld not active — open port manually if needed."
      fi
      ;;
  esac
}

# ── Start services ────────────────────────────────────────────────────────
start_services() {
  title "Starting Services"

  systemctl daemon-reload

  systemctl enable secbridge >> "$LOG_FILE" 2>&1
  systemctl restart secbridge
  sleep 3

  if systemctl is-active --quiet secbridge; then
    log "secbridge running on port $UI_PORT (UI + API combined)"
  else
    error "secbridge failed to start. Check: journalctl -u secbridge -n 30"
  fi
}

# ── Done ──────────────────────────────────────────────────────────────────
print_done() {
  local MY_IP; MY_IP=$(get_local_ip)
  echo ""
  echo "============================================================"
  echo -e "${GREEN}  WEB UI INSTALL COMPLETE${NC}"
  echo "============================================================"
  echo ""
  echo "  Open in browser:"
  echo -e "  ${CYAN}http://$MY_IP:$UI_PORT${NC}"
  echo ""
  echo "  Default login:  admin / admin"
  echo ""
  echo "  Service (UI + API combined):"
  echo "    systemctl status secbridge"
  echo "    journalctl -u secbridge -f"
  echo ""
  echo "  Install log: $LOG_FILE"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
init_log
banner
check_root
detect_os
install_deps
install_python_deps
install_files
build_frontend
install_backend_service
open_ports
start_services
print_done
