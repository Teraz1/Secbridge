# SecBridge Web UI

Dashboard for managing SecBridge sources, viewing pipeline status, and configuring destinations.

> **Requires:** SecBridge v3.1 core already installed on the same VM (`main` branch)

---

## Install (one command)

```bash
cd secbridge/web
sudo bash install.sh
```

That's it. Opens at `http://YOUR_VM_IP:3000`

Default login: **admin / admin**

---

## What gets installed

| Component | Details |
|-----------|---------|
| FastAPI backend | Runs on port 8000, wraps `sources.json` and `manage-sources.sh` |
| React frontend | Runs on port 3000, served as static files |
| `secbridge-api` service | Systemd — auto-starts on boot |
| `secbridge-ui` service | Systemd — auto-starts on boot |

---

## File Structure

```
web/
├── install.sh          ← run this
├── backend.py          ← FastAPI REST API
├── requirements.txt    ← Python deps
├── frontend/
│   ├── src/
│   │   ├── main.jsx    ← React entry point
│   │   └── App.jsx     ← full UI — all pages
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## API Endpoints

| Method | Endpoint | What it does |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate, get token |
| POST | `/api/logout` | Invalidate token |
| GET | `/api/sources` | List all sources |
| POST | `/api/sources` | Add new source |
| DELETE | `/api/sources/{id}` | Remove source |
| PATCH | `/api/sources/{id}/toggle` | Enable / disable |
| POST | `/api/apply` | Apply config → firewall + agent |
| GET | `/api/status` | Agent status + log sizes |
| GET | `/api/logs/{product}` | Tail a log file |
| GET | `/api/destination` | Read SDL credentials |
| POST | `/api/destination` | Save SDL credentials |
| POST | `/api/restart` | Restart Scalyr Agent |
| GET | `/api/parsers` | List parser files |

---

## Manage Services

```bash
# Status
systemctl status secbridge-api
systemctl status secbridge-ui

# Restart
systemctl restart secbridge-api
systemctl restart secbridge-ui

# Logs
journalctl -u secbridge-api -f
journalctl -u secbridge-ui -f
```

---

## Change Default Password

Edit `backend.py` line:
```python
USERS = {
    "admin": "admin"   # ← change this
}
```
Then restart: `systemctl restart secbridge-api`

---

## Ports

| Port | Service |
|------|---------|
| 3000 | Web UI |
| 8000 | API backend |

Open if needed:
```bash
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
```

---

## Troubleshooting

**`/api/apply` returns 500**
Add sudo permission:
```bash
echo "root ALL=(ALL) NOPASSWD: /bin/bash /opt/secbridge/scripts/manage-sources.sh" >> /etc/sudoers
```

**Frontend shows mock data instead of real sources**
→ API is unreachable. Check: `systemctl status secbridge-api`

**Build fails — node not found**
```bash
apt-get install -y nodejs npm   # Ubuntu
dnf install -y nodejs npm       # Rocky Linux
```
