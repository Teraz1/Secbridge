#!/usr/bin/env python3
"""
=============================================================================
Sangfor NGAF fwlog Parser
=============================================================================
Parses Sangfor NGAF raw syslog (fwlog) lines into structured JSON.
Reads from: /var/log/scalyr-agent-2/sangfor-ngaf.log  (live tail)
Writes to:  /var/log/scalyr-agent-2/sangfor-ngaf-parsed.log

The Scalyr Agent then ships the PARSED log to SentinelOne SDL.

Run as a service: see systemd unit in docs/sangfor-parser.service
=============================================================================
"""

import re
import json
import time
import sys
import os
import logging
from datetime import datetime, timezone

# ── Logging setup ──────────────────────────────────────────────────────────
LOG_DIR = "/var/log/scalyr-agent-2"
handlers = [logging.StreamHandler(sys.stdout)]
if os.path.isdir(LOG_DIR):
    handlers.append(logging.FileHandler(f"{LOG_DIR}/sangfor-parser-service.log"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=handlers,
)
logger = logging.getLogger("sangfor-parser")

# ── File paths ─────────────────────────────────────────────────────────────
INPUT_LOG  = "/var/log/scalyr-agent-2/sangfor-ngaf.log"
OUTPUT_LOG = "/var/log/scalyr-agent-2/sangfor-ngaf-parsed.log"
STATE_FILE = "/var/log/scalyr-agent-2/sangfor-parser.state"

# ── Field extraction patterns ──────────────────────────────────────────────
# These patterns match Sangfor NGAF fwlog key-value pairs
PATTERNS = {
    "log_type":     re.compile(r"Log [Tt]ype[:\s]+([^,\n]+?)(?:,|$)"),
    "policy_name":  re.compile(r"policy name[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "rule_id":      re.compile(r"rule ID[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "src_ip":       re.compile(r"src IP[:\s]+(\d{1,3}(?:\.\d{1,3}){3})"),
    "src_port":     re.compile(r"src port[:\s]+(\d+)"),
    "dst_ip":       re.compile(r"dst IP[:\s]+(\d{1,3}(?:\.\d{1,3}){3})"),
    "dst_port":     re.compile(r"dst port[:\s]+(\d+)"),
    "attack_type":  re.compile(r"attack type[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "threat_level": re.compile(r"threat level[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "action":       re.compile(r"action[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "url":          re.compile(r"\bURL:([^\s,\n]+)"),        # FIX: avoids matching "URL filter" log type
    "username":     re.compile(r"[Uu]sername(?:/[Hh]ost)?[:\s]+([^,\n]+?)(?:,|$)"),
    "app_category": re.compile(r"App [Cc]ategory[:\s]+([^,\n]+?)(?:,|$)"),
    "outbound":     re.compile(r"[Oo]utbound\(B\)[:\s]+(\d+)"),
    "inbound":      re.compile(r"[Ii]nbound\(B\)[:\s]+(\d+)"),
    "protocol":     re.compile(r"proto(?:col)?[:\s]+([^,\n]+?)(?:,|$)", re.I),
    "nat_src_ip":   re.compile(r"NAT src IP[:\s]+(\d{1,3}(?:\.\d{1,3}){3})", re.I),
    "nat_dst_ip":   re.compile(r"NAT dst IP[:\s]+(\d{1,3}(?:\.\d{1,3}){3})", re.I),
    "vpn_user":     re.compile(r"VPN [Uu]ser[:\s]+([^,\n]+?)(?:,|$)"),
    "ips_rule":     re.compile(r"IPS rule[:\s]+([^,\n]+?)(?:,|$)", re.I),
}

# ── Severity mapping ───────────────────────────────────────────────────────
SEVERITY_MAP = {
    "critical":     "CRITICAL",
    "high":         "HIGH",
    "medium":       "MEDIUM",
    "low":          "LOW",
    "information":  "INFO",
    "informational":"INFO",
    "info":         "INFO",
    "warning":      "WARNING",
}

# ── Log type → event category ──────────────────────────────────────────────
CATEGORY_MAP = {
    "apt detection":      "threat",
    "ips":                "intrusion",
    "traffic audit":      "traffic",
    "application control":"app_control",
    "url filter":         "web_filter",
    "user auth":          "authentication",
    "vpn":                "vpn",
    "nat":                "nat",
    "system":             "system",
    "anti-virus":         "malware",
    "antivirus":          "malware",
    "dos":                "dos_attack",
}

def parse_fwlog_line(raw_line: str) -> dict | None:
    """
    Parse a single Sangfor NGAF fwlog line into a structured dict.
    Returns None if the line is not a recognisable fwlog entry.
    """
    raw_line = raw_line.strip()
    if not raw_line or "fwlog" not in raw_line.lower():
        return None

    event = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "raw":          raw_line,
        "source":       "sangfor_ngaf",
        "parser":       "sangfor-ngaf",
    }

    # Extract all known fields
    for field, pattern in PATTERNS.items():
        m = pattern.search(raw_line)
        if m:
            event[field] = m.group(1).strip()

    # Enrich: severity normalisation
    if "threat_level" in event:
        event["severity"] = SEVERITY_MAP.get(
            event["threat_level"].lower(), event["threat_level"].upper()
        )

    # Enrich: category from log_type
    if "log_type" in event:
        lt = event["log_type"].lower().strip()
        event["event_category"] = CATEGORY_MAP.get(lt, "firewall")

    # Enrich: action normalisation (Denied → BLOCK, Allowed → ALLOW)
    if "action" in event:
        a = event["action"].lower()
        event["action_normalised"] = "BLOCK" if "den" in a else "ALLOW" if "allow" in a else event["action"].upper()

    # Skip lines that yielded nothing useful
    if len(event) <= 4:
        return None

    return event


def get_file_position() -> int:
    """Read last known byte offset from state file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return int(f.read().strip())
        except Exception:
            pass
    return 0


def save_file_position(pos: int):
    """Persist current byte offset."""
    with open(STATE_FILE, "w") as f:
        f.write(str(pos))


def tail_and_parse():
    """
    Continuously tail INPUT_LOG, parse each line, write JSON to OUTPUT_LOG.
    Survives log rotation by detecting file shrinkage.
    """
    logger.info(f"Sangfor NGAF parser started.")
    logger.info(f"  Input:  {INPUT_LOG}")
    logger.info(f"  Output: {OUTPUT_LOG}")

    last_pos   = get_file_position()
    last_inode = None
    parsed     = 0
    skipped    = 0

    while True:
        try:
            if not os.path.exists(INPUT_LOG):
                time.sleep(5)
                continue

            current_inode = os.stat(INPUT_LOG).st_ino
            if last_inode is not None and current_inode != last_inode:
                logger.info("Log rotation detected. Resetting offset.")
                last_pos = 0

            last_inode = current_inode

            with open(INPUT_LOG, "r", errors="replace") as f:
                # If file shrank (rotation), restart from 0
                f.seek(0, 2)
                size = f.tell()
                if last_pos > size:
                    last_pos = 0

                f.seek(last_pos)

                with open(OUTPUT_LOG, "a") as out:
                    for line in f:
                        result = parse_fwlog_line(line)
                        if result:
                            out.write(json.dumps(result) + "\n")
                            out.flush()
                            parsed += 1
                        else:
                            skipped += 1

                last_pos = f.tell()
                save_file_position(last_pos)

        except Exception as e:
            logger.error(f"Parser error: {e}")

        time.sleep(2)


# ── CLI test mode ──────────────────────────────────────────────────────────
def test_mode():
    """Parse sample lines and print results — for testing without a live feed."""
    samples = [
        "<134>Jan 30 11:38:49 localhost fwlog: Log type: APT detection, policy name:fwlogin, rule ID:0, src IP: 10.8.2.201, src port:50815, dst IP: 0.0.0.0, dst port: 53, attack type: Botnet, threat level:Information, action:Denied, URL:pool.hashvault.pro",
        "<134>Jan 30 11:38:50 localhost fwlog: Log Type: traffic audit, App Category:Gmail[Browse], Username/Host:10.63.44.25, Outbound(B):18376, Inbound(B):10572, Bidirectional(B):28948",
        "<134>Jan 30 11:39:01 localhost fwlog: Log type: IPS, policy name:default, src IP: 192.168.1.10, src port:4444, dst IP: 10.0.0.1, dst port: 80, attack type: SQL Injection, threat level:High, action:Denied",
        "<134>Jan 30 11:40:00 localhost fwlog: Log type: URL filter, src IP: 10.1.1.50, dst IP: 93.184.216.34, action:Denied, URL:malware-site.com, threat level:Critical",
    ]

    print("\n=== Sangfor NGAF Parser - Test Mode ===\n")
    for i, line in enumerate(samples, 1):
        result = parse_fwlog_line(line)
        if result:
            raw = result.pop("raw")   # don't print raw in test
            print(f"Sample {i}:")
            print(json.dumps(result, indent=2))
            print()
        else:
            print(f"Sample {i}: NOT MATCHED\n  {line}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_mode()
    else:
        tail_and_parse()
