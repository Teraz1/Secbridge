#!/usr/bin/env bash
# =============================================================================
# Deploy Sangfor Parser as Systemd Service
# Run this after install.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

DEPLOY_LOG="/var/log/sangfor-s1-deploy.log"

# FIX: init log before any tee -a — prevents silent exit under set -e
init_logfile() {
  mkdir -p "$(dirname "$DEPLOY_LOG")" 2>/dev/null || true
  touch "$DEPLOY_LOG" 2>/dev/null || DEPLOY_LOG="/dev/null"
}

log()   { echo -e "${GREEN}[OK]${NC}  $1" | tee -a "$DEPLOY_LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$DEPLOY_LOG"; }
error() { echo -e "${RED}[ERR]${NC} $1" | tee -a "$DEPLOY_LOG"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$DEPLOY_LOG"; }

init_logfile

[[ "$EUID" -ne 0 ]] && error "Run as root: sudo bash deploy-parser.sh"

INSTALL_DIR="/opt/sangfor-s1-kit"
SERVICE_FILE="/etc/systemd/system/sangfor-parser.service"

# FIX: detect python3 path reliably (handles python3.X on Rocky)
PYTHON_BIN=$(command -v python3 || command -v python3.11 || command -v python3.9 || echo "")
[[ -z "$PYTHON_BIN" ]] && error "python3 not found. Install it first: dnf install python3 / apt install python3"
info "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# Copy kit to /opt
info "Installing kit to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r "$(cd "$(dirname "$0")/.." && pwd)/." "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/scripts/"*.sh
chmod +x "$INSTALL_DIR/parser/sangfor_parser.py"
log "Kit installed to $INSTALL_DIR"

# Ensure output log dir exists
mkdir -p /var/log/scalyr-agent-2
touch /var/log/scalyr-agent-2/sangfor-ngaf.log
touch /var/log/scalyr-agent-2/sangfor-ngaf-parsed.log

# FIX: Write the service file dynamically with the correct python3 path
# instead of relying on a hardcoded /usr/bin/python3 that may not exist
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sangfor NGAF fwlog Parser for SentinelOne SDL
After=network.target scalyr-agent-2.service
Wants=scalyr-agent-2.service

[Service]
Type=simple
User=root
ExecStart=$PYTHON_BIN $INSTALL_DIR/parser/sangfor_parser.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sangfor-parser
MemoryMax=128M
CPUQuota=10%

[Install]
WantedBy=multi-user.target
EOF

log "Systemd service written: $SERVICE_FILE"

# Enable and start
systemctl daemon-reload
systemctl enable sangfor-parser >> /dev/null 2>&1
systemctl restart sangfor-parser
sleep 3

if systemctl is-active --quiet sangfor-parser; then
  log "sangfor-parser service is running."
else
  echo ""; error "Parser failed to start. Check: journalctl -u sangfor-parser -n 30"
fi

# Verify parser is actually processing
info "Running parser self-test..."
if $PYTHON_BIN "$INSTALL_DIR/parser/sangfor_parser.py" --test > /dev/null 2>&1; then
  log "Parser self-test passed."
else
  error "Parser self-test failed. Check: $PYTHON_BIN $INSTALL_DIR/parser/sangfor_parser.py --test"
fi

echo ""
echo "============================================================"
echo -e "${GREEN}  PARSER DEPLOYED SUCCESSFULLY${NC}"
echo "============================================================"
echo ""
echo "  Self-test:     $PYTHON_BIN $INSTALL_DIR/parser/sangfor_parser.py --test"
echo "  Live raw:      tail -f /var/log/scalyr-agent-2/sangfor-ngaf.log"
echo "  Live parsed:   tail -f /var/log/scalyr-agent-2/sangfor-ngaf-parsed.log"
echo "  Service logs:  journalctl -u sangfor-parser -f"
echo ""
