#!/usr/bin/env bash
# =============================================================================
# SecBridge — Cisco XDR Shipper Deploy Script
# =============================================================================
# Usage: sudo bash deploy-cisco-xdr.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()   { echo -e "${GREEN}[OK]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

[[ "$EUID" -ne 0 ]] && error "Run as root: sudo bash deploy-cisco-xdr.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/secbridge"

echo ""
echo "============================================================"
echo "  SecBridge — Cisco XDR Shipper Installer"
echo "============================================================"
echo ""

# ── Install Python requests if missing ───────────────────────────────────
if ! python3 -c "import requests" 2>/dev/null; then
    echo "Installing python3-requests..."
    pip install requests --break-system-packages
    log "requests installed"
else
    log "python3 requests already available"
fi

# ── Copy shipper script ───────────────────────────────────────────────────
cp "$SCRIPT_DIR/cisco_xdr_shipper.py" "$INSTALL_DIR/cisco_xdr_shipper.py"
chmod +x "$INSTALL_DIR/cisco_xdr_shipper.py"
log "cisco_xdr_shipper.py installed to $INSTALL_DIR/"

# ── Copy config template (don't overwrite if exists) ─────────────────────
CONFIG_FILE="$INSTALL_DIR/config/cisco_xdr.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cp "$SCRIPT_DIR/cisco_xdr.json" "$CONFIG_FILE"
    log "Config template created: $CONFIG_FILE"
    warn "Edit $CONFIG_FILE with your Cisco XDR client_id and client_secret"
else
    log "Config already exists — not overwriting: $CONFIG_FILE"
fi

# ── Install systemd service ───────────────────────────────────────────────
cp "$SCRIPT_DIR/secbridge-cisco-xdr.service" /etc/systemd/system/secbridge-cisco-xdr.service
systemctl daemon-reload
systemctl enable secbridge-cisco-xdr
log "systemd service installed and enabled"

# ── Check if config is filled in ─────────────────────────────────────────
if grep -q "YOUR_CLIENT_ID" "$CONFIG_FILE"; then
    echo ""
    echo "============================================================"
    echo -e "${YELLOW}  ACTION REQUIRED${NC}"
    echo "============================================================"
    echo ""
    echo "  Edit your Cisco XDR credentials:"
    echo -e "  ${CYAN}nano $CONFIG_FILE${NC}"
    echo ""
    echo "  Get credentials from:"
    echo "  XDR Console → Administration → API Clients → Add API Client"
    echo "  Scope needed: private-intel:sighting:write"
    echo ""
    echo "  Then start the service:"
    echo -e "  ${CYAN}sudo systemctl start secbridge-cisco-xdr${NC}"
    echo ""
else
    # Config is filled in — start service
    systemctl start secbridge-cisco-xdr
    sleep 2
    if systemctl is-active --quiet secbridge-cisco-xdr; then
        log "secbridge-cisco-xdr service started"
    else
        error "Service failed to start. Check: journalctl -u secbridge-cisco-xdr -n 30"
    fi
fi

echo ""
echo "  Useful commands:"
echo "    systemctl status secbridge-cisco-xdr"
echo "    journalctl -u secbridge-cisco-xdr -f"
echo "    python3 $INSTALL_DIR/cisco_xdr_shipper.py --test"
echo "    python3 $INSTALL_DIR/cisco_xdr_shipper.py --test-auth"
echo ""
