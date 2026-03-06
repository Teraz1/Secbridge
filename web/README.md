# SecBridge Web UI  v3.2

Dashboard for SecBridge — manage sources, view live logs, monitor pipeline health, manage users, and backup config.

> **Requires:** SecBridge v3.1 core installed on the same VM (`main` branch)

---

## Install (one command)

```bash
cd secbridge/web
sudo bash install.sh
```

Opens at `http://YOUR_VM_IP:3000`
Default login: **admin / admin**

---

## What Gets Installed

| Component | Details |
|-----------|---------|
| FastAPI backend | Port 8000 — REST API wrapping sources.json and manage-sources.sh |
| React frontend | Port 3000 — served as static files |
| `secbridge-api` service | Systemd — auto-starts on boot |
| `secbridge-ui` service | Systemd — auto-starts on boot |

---

## Pages

| Page | What it does |
|------|-------------|
| ✦ **Setup Wizard** | 4-step first-time setup — SDL credentials → source → verify → done |
| ⬡ **Dashboard** | Live log throughput, source health, recent events |
| ◈ **Pipeline Map** | Visual end-to-end flow — see where issues are |
| ▤ **Live Logs** | Real-time syslog stream, color-coded by event type |
| ♥ **Health Check** | Services, ports, log files, SDL connection status |
| ▦ **Log Statistics** | Hourly bar chart, source breakdown, event type split |
| ⇄ **Sources** | Add / remove / enable / disable syslog sources |
| ⚙ **Parsers** | View and manage vendor parser files |
| ⤴ **Destinations** | Configure SentinelOne SDL API key and URL |
| 👤 **Users** | Add users, assign roles (admin / analyst / viewer) |
| 📦 **Backup** | Download config backup zip, restore from previous backup |
| ≡ **Settings** | Restart agent, toggle log rotation, view config paths |

---

## File Structure

```
web/
├── install.sh              ← one command install
├── backend.py              ← FastAPI REST API
├── requirements.txt        ← Python deps
├── users.json              ← created on first run (auto)
├── backups/                ← created on first run (auto)
│   └── secbridge-backup-*.zip
├── README.md
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx         ← full React UI (all pages)
        └── main.jsx
```

---

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Login, returns token |
| POST | `/api/logout` | Invalidate token |

### Sources
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sources` | List all sources with live log stats |
| POST | `/api/sources` | Add new source |
| DELETE | `/api/sources/{id}` | Remove source |
| PATCH | `/api/sources/{id}/toggle` | Enable / disable |
| POST | `/api/sources/{id}/test` | Send test syslog message |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Agent, services, ports, SDL reachability |
| POST | `/api/apply` | Apply config → firewall + agent regenerate |
| POST | `/api/restart` | Restart Scalyr Agent |

### Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs/{product}` | Tail log file (last 100 lines) |
| GET | `/api/logs/{product}/stats` | Hourly log counts (last 24h) |

### Destination
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/destination` | Read SDL URL and masked API key |
| POST | `/api/destination` | Save SDL credentials |
| POST | `/api/destination/test` | Test SDL reachability |

### Users
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List users (admin only) |
| POST | `/api/users` | Add user (admin only) |
| DELETE | `/api/users/{username}` | Remove user (admin only) |
| PATCH | `/api/users/password` | Change password (admin only) |

### Backup
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/backup` | Create backup zip |
| GET | `/api/backup/list` | List all backups |
| GET | `/api/backup/download/{file}` | Download backup |
| DELETE | `/api/backup/{file}` | Delete backup |
| POST | `/api/restore` | Restore from uploaded zip |

### Wizard
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/wizard/setup` | One-shot: save SDL creds + add source + apply |

---

## User Roles

| Role | Permissions |
|------|------------|
| `admin` | Full access — all pages, add/remove sources, manage users, backup/restore |
| `analyst` | View logs, health check, pipeline map, log stats — no config changes |
| `viewer` | Dashboard and events only — read only |

---

## Services

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

**Option 1 — Web UI:** Settings → Users page → admin → Change Password

**Option 2 — Direct file edit:**
```bash
nano /opt/secbridge/web/users.json
# Change "password": "admin" to your new password
systemctl restart secbridge-api
```

---

## Ports

| Port | Service |
|------|---------|
| 3000 | Web UI (React) |
| 8000 | API backend (FastAPI) |

Open if needed:
```bash
sudo ufw allow 3000/tcp
sudo ufw allow 8000/tcp
```

---

## Troubleshooting

**Sources show mock data instead of real sources**
→ API unreachable. Check: `systemctl status secbridge-api`

**`/api/apply` or `/api/restart` returns 500**
Add sudo permission:
```bash
echo "root ALL=(ALL) NOPASSWD: /bin/bash /opt/secbridge/scripts/manage-sources.sh" >> /etc/sudoers
echo "root ALL=(ALL) NOPASSWD: /bin/systemctl restart scalyr-agent-2" >> /etc/sudoers
```

**Build fails — node not found**
```bash
# Ubuntu
apt-get install -y nodejs npm
# Rocky Linux
dnf install -y nodejs npm
```

**Log files show 0 lines**
→ No logs received yet. Check device syslog config points to collector IP and correct port.

**SDL test connection fails**
→ Check `ingest_url` in Destinations page — must include `https://` prefix.
