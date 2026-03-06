"""
=============================================================================
SecBridge — FastAPI Backend  v3.1
Wraps sources.json and manage-sources.sh as a REST API
=============================================================================
"""

import json
import re
import os
import subprocess
import hashlib
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="SecBridge API", version="3.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Paths ─────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SOURCES_JSON  = os.path.join(BASE_DIR, "config", "sources.json")
MANAGE_SCRIPT = os.path.join(BASE_DIR, "scripts", "manage-sources.sh")
AGENT_CONF    = "/etc/scalyr-agent-2/agent.json"
LOG_DIR       = "/var/log/scalyr-agent-2"
PARSER_DIR    = os.path.join(BASE_DIR, "integrations",
                             "sangfor-ngaf-to-sentinelone", "parser")

# ── Simple Auth ───────────────────────────────────────────────────────────
# In production replace with proper JWT. For now: hardcoded token per user.
USERS = {
    "admin": "admin"   # username: password  — change this!
}

# Simple session tokens stored in memory
SESSIONS: dict = {}

security = HTTPBearer(auto_error=False)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Not authenticated")
    token = creds.credentials
    user  = SESSIONS.get(token)
    if not user:
        raise HTTPException(401, "Invalid or expired token")
    return user


# ── Models ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class NewSource(BaseModel):
    name: str
    product: Optional[str] = ""
    syslog_port: int
    protocol: str = "udp"
    allowed_ips: Optional[List[str]] = []
    description: Optional[str] = ""

class Credentials(BaseModel):
    api_key: str
    ingest_url: str


# ── Helpers ───────────────────────────────────────────────────────────────
def read_sources():
    with open(SOURCES_JSON) as f:
        raw = re.sub(r"//.*", "", f.read())
    return json.loads(raw)

def write_sources(data):
    with open(SOURCES_JSON, "w") as f:
        json.dump(data, f, indent=2)

def read_agent():
    if not os.path.exists(AGENT_CONF):
        return {}
    with open(AGENT_CONF) as f:
        raw = re.sub(r"//.*", "", f.read())
    return json.loads(raw)

def run(cmd: list):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def log_file_stats(product: str) -> dict:
    path = os.path.join(LOG_DIR, f"{product}.log")
    if not os.path.exists(path):
        return {"exists": False, "size": 0, "modified": None}
    stat = os.stat(path)
    return {
        "exists":   True,
        "size":     stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
    }


# ── Auth ──────────────────────────────────────────────────────────────────
@app.post("/api/login")
def login(req: LoginRequest):
    pw = USERS.get(req.username)
    if not pw or pw != req.password:
        raise HTTPException(401, "Invalid credentials")
    # Generate simple token
    token = hashlib.sha256(
        f"{req.username}{datetime.now().isoformat()}".encode()
    ).hexdigest()[:32]
    SESSIONS[token] = req.username
    return {"token": token, "username": req.username}

@app.post("/api/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds:
        SESSIONS.pop(creds.credentials, None)
    return {"ok": True}


# ── Sources ───────────────────────────────────────────────────────────────
@app.get("/api/sources")
def get_sources(user=Depends(get_current_user)):
    data = read_sources()
    sources = data["secbridge"]["sources"]
    # Enrich with live log file stats
    for s in sources:
        s["log_stats"] = log_file_stats(s["product"])
    return sources

@app.post("/api/sources")
def add_source(source: NewSource, user=Depends(get_current_user)):
    data = read_sources()
    sources = data["secbridge"]["sources"]

    used_ports = [s["syslog_port"] for s in sources]
    if source.syslog_port in used_ports:
        raise HTTPException(400, f"Port {source.syslog_port} already in use")

    product = source.product or source.name.lower().replace(" ", "-")
    last_id = max([int(s["id"]) for s in sources], default=0)
    new_id  = str(last_id + 1).zfill(3)

    new_source = {
        "id":              new_id,
        "enabled":         True,
        "name":            source.name,
        "product":         product,
        "description":     source.description,
        "allowed_ips":     source.allowed_ips or [],
        "syslog_port":     source.syslog_port,
        "protocol":        source.protocol,
        "log_file":        f"{product}.log",
        "parsed_log_file": f"{product}-parsed.log",
        "parser_script":   f"/opt/secbridge/parser/{product}_parser.py",
        "parser_name":     product,
        "log_type":        "firewall"
    }

    sources.append(new_source)
    write_sources(data)
    return {"ok": True, "source": new_source}

@app.delete("/api/sources/{source_id}")
def remove_source(source_id: str, user=Depends(get_current_user)):
    data = read_sources()
    before = len(data["secbridge"]["sources"])
    data["secbridge"]["sources"] = [
        s for s in data["secbridge"]["sources"] if s["id"] != source_id
    ]
    if len(data["secbridge"]["sources"]) == before:
        raise HTTPException(404, f"Source {source_id} not found")
    write_sources(data)
    return {"ok": True}

@app.patch("/api/sources/{source_id}/toggle")
def toggle_source(source_id: str, user=Depends(get_current_user)):
    data = read_sources()
    for s in data["secbridge"]["sources"]:
        if s["id"] == source_id:
            s["enabled"] = not s.get("enabled", True)
            write_sources(data)
            return {"ok": True, "enabled": s["enabled"]}
    raise HTTPException(404, f"Source {source_id} not found")


# ── Apply / Status ────────────────────────────────────────────────────────
@app.post("/api/apply")
def apply_sources(user=Depends(get_current_user)):
    code, out, err = run(["sudo", "bash", MANAGE_SCRIPT, "apply"])
    if code != 0:
        raise HTTPException(500, f"Apply failed:\n{err}")
    return {"ok": True, "output": out}

@app.get("/api/status")
def get_status(user=Depends(get_current_user)):
    # Agent running?
    r = subprocess.run(
        ["systemctl", "is-active", "scalyr-agent-2"],
        capture_output=True, text=True
    )
    agent_running = r.stdout.strip() == "active"

    # Port listeners
    r2 = subprocess.run(
        ["ss", "-ulnp"],
        capture_output=True, text=True
    )
    listening_ports = []
    for line in r2.stdout.splitlines():
        if "scalyr" in line or "514" in line or "5140" in line:
            listening_ports.append(line.strip())

    # Log file sizes
    log_files = {}
    if os.path.isdir(LOG_DIR):
        for f in sorted(os.listdir(LOG_DIR)):
            if f.endswith(".log"):
                path = os.path.join(LOG_DIR, f)
                log_files[f] = {
                    "size":     os.path.getsize(path),
                    "modified": datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).isoformat()
                }

    return {
        "agent_running":   agent_running,
        "log_files":       log_files,
        "listening_ports": listening_ports
    }


# ── Logs ──────────────────────────────────────────────────────────────────
@app.get("/api/logs/{product}")
def get_log_tail(product: str, lines: int = 50, user=Depends(get_current_user)):
    # Sanitize product name
    product = re.sub(r"[^a-z0-9\-]", "", product)
    log_path = os.path.join(LOG_DIR, f"{product}.log")
    if not os.path.exists(log_path):
        raise HTTPException(404, f"Log not found: {log_path}")
    r = subprocess.run(["tail", f"-{lines}", log_path], capture_output=True, text=True)
    return {"product": product, "lines": r.stdout.splitlines()}


# ── Destination ───────────────────────────────────────────────────────────
@app.get("/api/destination")
def get_destination(user=Depends(get_current_user)):
    cfg = read_agent()
    api_key = cfg.get("api_key", "")
    return {
        "ingest_url": cfg.get("scalyr_server", ""),
        "api_key":    api_key[:8] + "••••••••" if api_key else ""
    }

@app.post("/api/destination")
def save_destination(creds: Credentials, user=Depends(get_current_user)):
    if not os.path.exists(AGENT_CONF):
        raise HTTPException(404, "agent.json not found")
    cfg = read_agent()
    cfg["api_key"]       = creds.api_key
    cfg["scalyr_server"] = creds.ingest_url
    with open(AGENT_CONF, "w") as f:
        json.dump(cfg, f, indent=2)
    return {"ok": True}


# ── Agent control ─────────────────────────────────────────────────────────
@app.post("/api/restart")
def restart_agent(user=Depends(get_current_user)):
    code, out, err = run(["sudo", "systemctl", "restart", "scalyr-agent-2"])
    return {"ok": code == 0, "output": out or err}


# ── Parsers ───────────────────────────────────────────────────────────────
@app.get("/api/parsers")
def get_parsers(user=Depends(get_current_user)):
    parsers = []
    if os.path.isdir(PARSER_DIR):
        for f in sorted(os.listdir(PARSER_DIR)):
            if f.endswith("_parser.py"):
                path = os.path.join(PARSER_DIR, f)
                name = f.replace("_parser.py", "").replace("_", "-")
                parsers.append({
                    "id":     name,
                    "name":   name,
                    "file":   f,
                    "size":   os.path.getsize(path),
                    "status": "active"
                })
    return parsers
