"""
=============================================================================
SecBridge — FastAPI Backend  v3.2
All endpoints for Web UI v3.2
=============================================================================
Run: uvicorn backend:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import re
import os
import subprocess
import hashlib
import zipfile
import tempfile
import time
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="SecBridge API", version="3.2")

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
# Root parser dir — used for uploaded parsers
PARSER_DIR    = os.path.join(BASE_DIR, "integrations",
                             "sangfor-ngaf-to-sentinelone", "parser")
# Collect parser scripts from ALL integration folders
def get_all_parser_scripts() -> list:
    """Scan every integrations/*/parser/*.py and return list of {name, path, product}."""
    scripts = []
    integrations_dir = os.path.join(BASE_DIR, "integrations")
    if not os.path.isdir(integrations_dir):
        return scripts
    for integration in sorted(os.listdir(integrations_dir)):
        parser_dir = os.path.join(integrations_dir, integration, "parser")
        if not os.path.isdir(parser_dir):
            continue
        for f in sorted(os.listdir(parser_dir)):
            if not f.endswith(".py"):
                continue
            path    = os.path.join(parser_dir, f)
            name    = f.replace("_parser.py", "").replace("_", "-")
            name    = os.path.splitext(name)[0]
            product = integration.replace("-to-sentinelone", "").replace("-to-s1", "")
            scripts.append({
                "name":        name,
                "file":        f,
                "path":        path,
                "integration": integration,
                "product":     product,
            })
    return scripts
USERS_FILE    = os.path.join(os.path.dirname(__file__), "users.json")
BACKUP_DIR    = os.path.join(os.path.dirname(__file__), "backups")

os.makedirs(BACKUP_DIR, exist_ok=True)

# ── Auth ──────────────────────────────────────────────────────────────────
security  = HTTPBearer(auto_error=False)
SESSIONS: dict = {}

def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    default = {"admin": {"password": "admin", "role": "admin", "created": datetime.now().isoformat()}}
    save_users(default)
    return default

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Not authenticated")
    session = SESSIONS.get(creds.credentials)
    if not session:
        raise HTTPException(401, "Invalid or expired token")
    return session

def require_admin(session=Depends(get_current_user)):
    if session["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return session

# ── Helpers ───────────────────────────────────────────────────────────────
def read_sources():
    if not os.path.exists(SOURCES_JSON):
        return {"secbridge": {"sources": []}}
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

def run_cmd(cmd: list):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr

def log_file_info(product: str) -> dict:
    path = os.path.join(LOG_DIR, f"{product}.log")
    if not os.path.exists(path):
        return {"exists": False, "size_kb": 0, "modified": None, "lines": 0}
    stat = os.stat(path)
    try:
        r     = subprocess.run(["wc", "-l", path], capture_output=True, text=True)
        lines = int(r.stdout.strip().split()[0])
    except Exception:
        lines = 0
    return {
        "exists":   True,
        "size_kb":  round(stat.st_size / 1024, 1),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "lines":    lines
    }

def port_is_listening(port: int) -> bool:
    r = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True)
    t = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
    combined = r.stdout + t.stdout
    return f":{port} " in combined or f":{port}\n" in combined


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
    parser_name: Optional[str] = "none"

class Credentials(BaseModel):
    api_key: str
    ingest_url: str

class NewUser(BaseModel):
    username: str
    password: str
    role: str

class ChangePassword(BaseModel):
    username: str
    new_password: str

class WizardSetup(BaseModel):
    api_key: str
    ingest_url: str
    source_name: str
    syslog_port: int
    protocol: str = "udp"


# ═══════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/login")
def login(req: LoginRequest):
    users = load_users()
    user  = users.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(401, "Invalid credentials")
    token = hashlib.sha256(
        f"{req.username}{datetime.now().isoformat()}sbsecret".encode()
    ).hexdigest()[:32]
    SESSIONS[token] = {"username": req.username, "role": user["role"], "token": token}
    # Record last login time
    users = load_users()
    if req.username in users:
        users[req.username]["lastLogin"] = datetime.now().isoformat()
        save_users(users)
    return {"token": token, "username": req.username, "role": user["role"]}

@app.post("/api/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds:
        SESSIONS.pop(creds.credentials, None)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
# SOURCES
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/sources")
def get_sources(session=Depends(get_current_user)):
    data    = read_sources()
    sources = data["secbridge"]["sources"]
    for s in sources:
        port         = s.get("syslog_port", s.get("port", 0))
        s["log_info"]       = log_file_info(s["product"])
        s["port_listening"] = port_is_listening(port)
    return sources

@app.post("/api/sources")
def add_source(source: NewSource, session=Depends(require_admin)):
    data    = read_sources()
    sources = data["secbridge"]["sources"]
    used    = [s.get("syslog_port", s.get("port", 0)) for s in sources]
    if source.syslog_port in used:
        raise HTTPException(400, f"Port {source.syslog_port} already in use")
    product = source.product or source.name.lower().replace(" ", "-")
    last_id = max([int(s["id"]) for s in sources], default=0)
    # Resolve parser_script path — looks up real path from integrations/ folders and uploaded dir
    # parser_name is what scalyr-agent uses as the "parser" attribute (matches SDL parser name)
    # parser_script is the local Python service path (only relevant if using a local .py parser)
    chosen = source.parser_name or "none"
    resolved_script = ""
    resolved_name   = chosen

    if chosen not in ("none", "sdl-handles-parsing", ""):
        # Look in all integrations/*/parser/ dirs first
        for script in get_all_parser_scripts():
            if script["name"] == chosen:
                resolved_script = script["path"]
                break
        # Then check uploaded parsers dir
        if not resolved_script and os.path.isdir(PARSER_DIR):
            for f in sorted(os.listdir(PARSER_DIR)):
                if f.endswith(".py"):
                    n = os.path.splitext(f.replace("_parser","").replace("_","-"))[0]
                    if n == chosen:
                        resolved_script = os.path.join(PARSER_DIR, f)
                        break
        # No match found — leave script blank and warn in description
        if not resolved_script:
            resolved_script = ""

    # parsed_log_file only makes sense when a local parser is used
    use_local_parser = resolved_script != ""
    parsed_log = (product + "-parsed.log") if use_local_parser else ""

    new_src = {
        "id":              str(last_id + 1).zfill(3),
        "enabled":         True,
        "name":            source.name,
        "product":         product,
        "description":     source.description or "",
        "allowed_ips":     source.allowed_ips or [],
        "syslog_port":     source.syslog_port,
        "protocol":        source.protocol.upper(),
        "log_file":        product + ".log",
        "parsed_log_file": parsed_log,
        "parser_script":   resolved_script,
        "parser_name":     resolved_name,
        "log_type":        "firewall"
    }
    sources.append(new_src)
    write_sources(data)
    # Note: agent.json is managed by manage-sources.sh apply — run Apply after adding sources
    return {"ok": True, "source": new_src}

@app.delete("/api/sources/{source_id}")
def remove_source(source_id: str, session=Depends(require_admin)):
    data    = read_sources()
    sources = data["secbridge"]["sources"]
    # Find product BEFORE deleting so we can clean agent.json
    target  = next((s for s in sources if s["id"] == source_id), None)
    if not target:
        raise HTTPException(404, f"Source {source_id} not found")
    data["secbridge"]["sources"] = [s for s in sources if s["id"] != source_id]
    write_sources(data)
    return {"ok": True}



@app.patch("/api/sources/{source_id}/toggle")
def toggle_source(source_id: str, session=Depends(require_admin)):
    data = read_sources()
    for s in data["secbridge"]["sources"]:
        if s["id"] == source_id:
            s["enabled"] = not s.get("enabled", True)
            write_sources(data)
            return {"ok": True, "enabled": s["enabled"]}
    raise HTTPException(404, f"Source {source_id} not found")

@app.post("/api/sources/{source_id}/test")
def test_source(source_id: str, session=Depends(get_current_user)):
    data    = read_sources()
    sources = data["secbridge"]["sources"]
    src     = next((s for s in sources if s["id"] == source_id), None)
    if not src:
        raise HTTPException(404, f"Source {source_id} not found")
    port     = src.get("syslog_port", src.get("port", 514))
    proto    = src.get("protocol", "UDP").lower()
    test_msg = f"<14>SecBridge test — source:{src['product']} ts:{datetime.now().isoformat()}"
    if proto == "tcp":
        subprocess.run(["bash", "-c", f"echo '{test_msg}' | nc -w 2 127.0.0.1 {port}"], capture_output=True)
    else:
        subprocess.run(["bash", "-c", f"echo '{test_msg}' | nc -u -w 2 127.0.0.1 {port}"], capture_output=True)
    time.sleep(1)
    return {"ok": True, "message": test_msg, "port": port, "proto": proto, "log_info": log_file_info(src["product"])}


# ═══════════════════════════════════════════════════════════════════════════
# APPLY / STATUS
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/apply")
def apply_sources(session=Depends(require_admin)):
    code, out, err = run_cmd(["sudo", "bash", MANAGE_SCRIPT, "apply"])
    if code != 0:
        raise HTTPException(500, f"Apply failed:\n{err}")
    return {"ok": True, "output": out}

@app.get("/api/status")
def get_status(session=Depends(get_current_user)):
    def svc_active(name):
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
        return r.stdout.strip() == "active"

    sdl_ok = False
    try:
        cfg = read_agent()
        url = cfg.get("scalyr_server", "")
        if url:
            r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url], capture_output=True, text=True)
            sdl_ok = r.stdout.strip() in ["200", "301", "302", "403"]
    except Exception:
        pass

    log_files = {}
    if os.path.isdir(LOG_DIR):
        for f in sorted(os.listdir(LOG_DIR)):
            if f.endswith(".log"):
                path = os.path.join(LOG_DIR, f)
                stat = os.stat(path)
                log_files[f] = {"size_kb": round(stat.st_size / 1024, 1), "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()}

    sources    = read_sources()["secbridge"]["sources"]
    port_check = {}
    for s in sources:
        port = s.get("syslog_port", s.get("port", 0))
        port_check[s["product"]] = port_is_listening(port)

    return {
        "agent_running":  svc_active("scalyr-agent-2"),
        "api_running":    svc_active("secbridge-api"),
        "ui_running":     svc_active("secbridge-ui"),
        "sdl_reachable":  sdl_ok,
        "log_files":      log_files,
        "port_status":    port_check,
        "checked_at":     datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════════
# LOGS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/logs/{product}")
def get_log_tail(product: str, lines: int = 100, session=Depends(get_current_user)):
    product  = re.sub(r"[^a-z0-9\-]", "", product)
    log_path = os.path.join(LOG_DIR, f"{product}.log")
    if not os.path.exists(log_path):
        raise HTTPException(404, f"Log not found: {log_path}")
    r = subprocess.run(["tail", f"-{lines}", log_path], capture_output=True, text=True)
    return {"product": product, "lines": r.stdout.splitlines(), "log_path": log_path, "info": log_file_info(product)}

@app.get("/api/logs/{product}/stats")
def get_log_stats(product: str, session=Depends(get_current_user)):
    product  = re.sub(r"[^a-z0-9\-]", "", product)
    log_path = os.path.join(LOG_DIR, f"{product}.log")
    hourly   = [0] * 24
    if not os.path.exists(log_path):
        return {"product": product, "hourly": hourly, "total": 0}
    try:
        r = subprocess.run(["grep", "-oP", r"(?<=\s)\d{2}(?=:\d{2}:\d{2})", log_path], capture_output=True, text=True)
        for h in r.stdout.splitlines():
            try:
                hourly[int(h)] += 1
            except Exception:
                pass
    except Exception:
        pass
    return {"product": product, "hourly": hourly, "total": sum(hourly)}


# ═══════════════════════════════════════════════════════════════════════════
# DESTINATION
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/destination")
def get_destination(session=Depends(get_current_user)):
    cfg     = read_agent()
    api_key = cfg.get("api_key", "")
    return {"ingest_url": cfg.get("scalyr_server", ""), "api_key": api_key[:8] + "••••••••" if api_key else ""}

@app.post("/api/destination")
def save_destination(creds: Credentials, session=Depends(require_admin)):
    if not os.path.exists(AGENT_CONF):
        raise HTTPException(404, "agent.json not found")
    cfg = read_agent()
    cfg["api_key"]       = creds.api_key
    cfg["scalyr_server"] = creds.ingest_url
    with open(AGENT_CONF, "w") as f:
        json.dump(cfg, f, indent=2)
    return {"ok": True}

@app.post("/api/destination/test")
def test_destination(session=Depends(get_current_user)):
    cfg  = read_agent()
    url  = cfg.get("scalyr_server", "")
    if not url:
        raise HTTPException(400, "No ingest URL configured")
    r    = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", url], capture_output=True, text=True)
    code = r.stdout.strip()
    return {"ok": code in ["200", "301", "302", "403"], "http_code": code, "url": url}

@app.post("/api/restart")
def restart_agent(session=Depends(require_admin)):
    code, out, err = run_cmd(["sudo", "systemctl", "restart", "scalyr-agent-2"])
    return {"ok": code == 0, "output": out or err}


# ═══════════════════════════════════════════════════════════════════════════
# PARSERS
# ═══════════════════════════════════════════════════════════════════════════

ALLOWED_PARSER_EXTS = {".py", ".json", ".conf", ".yaml", ".yml", ".txt", ".cfg"}

def extract_parser_fields(path: str) -> list:
    """Try to extract field names from a parser file."""
    fields = []
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
        # Python parser: look for field = ..., "field": ..., or parsed["field"]
        if path.endswith(".py"):
            import re as _re
            # Match patterns like: parsed["src_ip"] = ..., or "src_ip": value
            hits = _re.findall(r'parsed\[["\'](\w+)["\']\]', content)
            hits += _re.findall(r'"(\w{3,30})":\s*\w', content)
            hits += _re.findall(r"'(\w{3,30})':\s*\w", content)
            # Deduplicate, filter noise
            seen = set()
            for h in hits:
                if h not in seen and not h.startswith("__") and len(h) > 2:
                    seen.add(h)
                    fields.append(h)
            fields = fields[:20]
        elif path.endswith(".json"):
            import json as _json
            data = _json.loads(content)
            if isinstance(data, dict):
                fields = list(data.keys())[:20]
    except Exception:
        pass
    return fields

@app.get("/api/parsers")
def get_parsers(session=Depends(get_current_user)):
    parsers = []
    seen    = set()
    # 1. Scan all integration parser directories
    for script in get_all_parser_scripts():
        if script["file"] in seen:
            continue
        seen.add(script["file"])
        path   = script["path"]
        stat   = os.stat(path)
        fields = extract_parser_fields(path)
        parsers.append({
            "id":          script["name"],
            "name":        script["name"],
            "file":        script["file"],
            "path":        path,
            "integration": script["integration"],
            "ext":         ".py",
            "size_kb":     round(stat.st_size / 1024, 1),
            "modified":    datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "status":      "active",
            "fields":      fields,
            "field_count": len(fields),
            "source":      "integration"
        })
    # 2. Also scan PARSER_DIR for any manually uploaded parsers
    if os.path.isdir(PARSER_DIR):
        for f in sorted(os.listdir(PARSER_DIR)):
            if f in seen:
                continue
            ext = os.path.splitext(f)[1].lower()
            if ext not in ALLOWED_PARSER_EXTS:
                continue
            seen.add(f)
            path   = os.path.join(PARSER_DIR, f)
            stat   = os.stat(path)
            fields = extract_parser_fields(path)
            name   = f.replace("_parser.py","").replace("_parser.json","").replace("_","-")
            name   = os.path.splitext(name)[0] if not name else name
            parsers.append({
                "id":          name,
                "name":        name,
                "file":        f,
                "path":        path,
                "integration": "uploaded",
                "ext":         ext,
                "size_kb":     round(stat.st_size / 1024, 1),
                "modified":    datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "status":      "active",
                "fields":      fields,
                "field_count": len(fields),
                "source":      "uploaded"
            })
    return parsers

@app.post("/api/parsers/upload")
async def upload_parser(file: UploadFile = File(...), session=Depends(require_admin)):
    """Upload a parser file (.py, .json, .conf, .yaml, etc.) to PARSER_DIR."""
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_PARSER_EXTS:
        raise HTTPException(400, f"File type {ext} not allowed. Allowed: {', '.join(ALLOWED_PARSER_EXTS)}")
    # Sanitize filename
    safe_name = re.sub(r"[^a-zA-Z0-9._\-]", "_", file.filename)
    if not safe_name:
        raise HTTPException(400, "Invalid filename")
    os.makedirs(PARSER_DIR, exist_ok=True)
    dest = os.path.join(PARSER_DIR, safe_name)
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)
    # Extract fields immediately
    fields = extract_parser_fields(dest)
    stat   = os.stat(dest)
    return {
        "ok":       True,
        "file":     safe_name,
        "size_kb":  round(stat.st_size / 1024, 1),
        "fields":   fields,
        "field_count": len(fields),
        "message":  f"Uploaded {safe_name} ({len(fields)} fields detected)"
    }

@app.delete("/api/parsers/{filename}")
def delete_parser(filename: str, session=Depends(require_admin)):
    safe_name = os.path.basename(filename)
    path      = os.path.join(PARSER_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(404, f"Parser file not found: {safe_name}")
    os.remove(path)
    return {"ok": True, "deleted": safe_name}

@app.get("/api/parsers/names")
def get_parser_names(session=Depends(get_current_user)):
    """Return [{name, path}] list for Add Source dropdown."""
    options = [
        {"name": "none",                "label": "None — raw syslog only",                       "path": ""},
        {"name": "sdl-handles-parsing", "label": "SDL handles parsing (recommended — no local parser needed)", "path": ""},
    ]
    for script in get_all_parser_scripts():
        options.append({
            "name":  script["name"],
            "label": script["name"] + " (" + script["integration"] + ")",
            "path":  script["path"],
        })
    # Uploaded parsers
    if os.path.isdir(PARSER_DIR):
        for f in sorted(os.listdir(PARSER_DIR)):
            if f.endswith(".py"):
                n = f.replace("_parser.py","").replace("_","-")
                n = os.path.splitext(n)[0]
                already = any(o["name"] == n for o in options)
                if not already:
                    options.append({
                        "name":  n,
                        "label": n + " (uploaded)",
                        "path":  os.path.join(PARSER_DIR, f),
                    })
    return options


# ═══════════════════════════════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def get_users(session=Depends(require_admin)):
    users = load_users()
    return [{"username": u, "role": d["role"], "created": d.get("created", ""),
             "lastLogin": d.get("lastLogin", d.get("created", "never"))} for u, d in users.items()]

@app.post("/api/users")
def add_user(user: NewUser, session=Depends(require_admin)):
    if user.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(400, "Role must be admin, analyst or viewer")
    users = load_users()
    if user.username in users:
        raise HTTPException(400, f"User {user.username} already exists")
    users[user.username] = {"password": user.password, "role": user.role, "created": datetime.now().isoformat()}
    save_users(users)
    return {"ok": True}

@app.delete("/api/users/{username}")
def remove_user(username: str, session=Depends(require_admin)):
    if username == "admin":
        raise HTTPException(400, "Cannot remove admin user")
    users = load_users()
    if username not in users:
        raise HTTPException(404, f"User {username} not found")
    del users[username]
    save_users(users)
    for token, s in list(SESSIONS.items()):
        if s["username"] == username:
            del SESSIONS[token]
    return {"ok": True}

@app.patch("/api/users/password")
def change_password(req: ChangePassword, session=Depends(require_admin)):
    users = load_users()
    if req.username not in users:
        raise HTTPException(404, f"User {req.username} not found")
    users[req.username]["password"] = req.new_password
    save_users(users)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP & RESTORE
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/backup")
def create_backup(session=Depends(require_admin)):
    ts          = datetime.now().strftime("%Y-%m-%d-%H%M")
    backup_name = f"secbridge-backup-{ts}.zip"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(SOURCES_JSON):
            zf.write(SOURCES_JSON, "sources.json")
        if os.path.exists(AGENT_CONF):
            cfg = read_agent()
            if "api_key" in cfg:
                cfg["api_key"] = cfg["api_key"][:8] + "••••••••"
            zf.writestr("agent.json", json.dumps(cfg, indent=2))
        if os.path.isdir(PARSER_DIR):
            for f in os.listdir(PARSER_DIR):
                zf.write(os.path.join(PARSER_DIR, f), f"parsers/{f}")
        users = load_users()
        safe  = {u: {"role": d["role"], "created": d.get("created","")} for u, d in users.items()}
        zf.writestr("users.json", json.dumps(safe, indent=2))
    size = os.path.getsize(backup_path)
    return {"ok": True, "file": backup_name, "size_kb": round(size/1024,1), "created": datetime.now().isoformat()}

@app.get("/api/backup/list")
def list_backups(session=Depends(require_admin)):
    backups = []
    if os.path.isdir(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith(".zip"):
                path = os.path.join(BACKUP_DIR, f)
                stat = os.stat(path)
                backups.append({"name": f, "size_kb": round(stat.st_size/1024,1), "created": datetime.fromtimestamp(stat.st_ctime).isoformat()})
    return backups

@app.get("/api/backup/download/{filename}")
def download_backup(filename: str, token: str = None,
                    creds: HTTPAuthorizationCredentials = Depends(security)):
    """Support both Bearer header auth and ?token= query param (for window.open downloads)."""
    # Resolve token from either source
    tok = None
    if creds:
        tok = creds.credentials
    elif token:
        tok = token
    if not tok or tok not in SESSIONS:
        raise HTTPException(401, "Not authenticated")
    session = SESSIONS[tok]
    if session["role"] != "admin":
        raise HTTPException(403, "Admin required")
    filename = os.path.basename(filename)
    path     = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Backup not found")
    return FileResponse(path, filename=filename, media_type="application/zip")

@app.delete("/api/backup/{filename}")
def delete_backup(filename: str, session=Depends(require_admin)):
    filename = os.path.basename(filename)
    path     = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Backup not found")
    os.remove(path)
    return {"ok": True}

@app.post("/api/restore")
async def restore_backup(file: UploadFile = File(...), session=Depends(require_admin)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, "Must be a .zip file")
    tmp = tempfile.mktemp(suffix=".zip")
    try:
        content = await file.read()
        with open(tmp, "wb") as f:
            f.write(content)
        with zipfile.ZipFile(tmp, "r") as zf:
            names = zf.namelist()
            if "sources.json" in names:
                with zf.open("sources.json") as src:
                    with open(SOURCES_JSON, "wb") as dst:
                        dst.write(src.read())
            for name in names:
                if name.startswith("parsers/") and os.path.isdir(PARSER_DIR):
                    fname = os.path.basename(name)
                    if fname:
                        with zf.open(name) as src, open(os.path.join(PARSER_DIR, fname), "wb") as dst:
                            dst.write(src.read())
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    subprocess.run(["sudo", "systemctl", "restart", "scalyr-agent-2"])
    return {"ok": True, "message": "Restore complete. Agent restarted."}


# ═══════════════════════════════════════════════════════════════════════════
# WIZARD
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/wizard/setup")
def wizard_setup(setup: WizardSetup, session=Depends(require_admin)):
    errors = []
    if os.path.exists(AGENT_CONF):
        try:
            cfg = read_agent()
            cfg["api_key"]       = setup.api_key
            cfg["scalyr_server"] = setup.ingest_url
            with open(AGENT_CONF, "w") as f:
                json.dump(cfg, f, indent=2)
        except Exception as e:
            errors.append(f"agent.json: {e}")
    data    = read_sources()
    sources = data["secbridge"]["sources"]
    used    = [s.get("syslog_port", s.get("port", 0)) for s in sources]
    if setup.syslog_port not in used:
        product = setup.source_name.lower().replace(" ", "-")
        last_id = max([int(s["id"]) for s in sources], default=0)
        sources.append({
            "id":              str(last_id+1).zfill(3),
            "enabled":         True,
            "name":            setup.source_name,
            "product":         product,
            "description":     "Added via Setup Wizard",
            "allowed_ips":     [],
            "syslog_port":     setup.syslog_port,
            "protocol":        setup.protocol.upper(),
            "log_file":        product + ".log",
            "parsed_log_file": "",
            "parser_script":   "",
            "parser_name":     "sdl-handles-parsing",
            "log_type":        "firewall"
        })
        write_sources(data)
    code, out, err = run_cmd(["sudo", "bash", MANAGE_SCRIPT, "apply"])
    if code != 0:
        errors.append(f"apply: {err[:200]}")
    return {"ok": len(errors)==0, "errors": errors, "message": "Setup complete." if not errors else "Done with warnings."}
