[🇫🇷 Version francaise](README.md)

# RootWarden v1.13.1

> **RootWarden** is a **DevSecOps** platform for centralized Linux server administration.
> Deploy it on your infrastructure to manage SSH, updates, firewall, Fail2ban,
> systemd services, sshd_config audit and CVE vulnerabilities — from a single interface.

---

## Features

### Server Management
- **SSH Keys** — Mass deployment, key age tracking (alert > 90 days)
- **Linux Updates** — APT update/upgrade with real-time streaming, `su -c` fallback if sudo unavailable
- **iptables Firewall** — View, edit, save/restore rules from database
- **Fail2ban** — Service detection (SSH/FTP/Apache/Nginx/Mail), jail activation, ban/unban IP, auto-install
- **systemd Services** — Start, stop, restart Linux services. journalctl logs, auto-categorization, protected services
- **SSH Audit** — Scan sshd_config, security scoring (A-F), one-click fixes, config editor, backups/restore, toggle directives ON/OFF, reload sshd
- **Multi-agent Supervision** — Deploy and configure monitoring agents via SSH. Supports Zabbix Agent 2, Centreon Monitoring Agent, Prometheus Node Exporter and Telegraf. Global config per platform, per-server overrides, remote config editor, backups/restore, multi-agent badges, scan all agents in one click
- **Custom Tags** — Label your servers (web, db, production, dmz...) and filter by tag

### CVE Vulnerability Scanning
- **OpenCVE** — Supports cloud (app.opencve.io) and on-prem v2 (Bearer token)
- **Real-time Streaming** — JSON-lines, per-package progress
- **Filters** — By severity (CRITICAL/HIGH/MEDIUM) and year
- **CSV Export** — One-click download per server
- **Global Summary** — Fleet overview at the top of the page

### Security & Compliance
- **Ed25519 Platform Keypair** — Passwordless SSH auth, progressive migration, secrets removal from DB
- **rootwarden Service Account** — Dedicated Linux user with sudoers NOPASSWD:ALL, zero password required
- **Password Reset by Email** — "Forgot password" link on login page, 1h token, PHPMailer
- **Secure Startup (start.sh)** — Auto chmod 600 on .env, default secret detection, password masking in Docker logs
- **force_password_change** — Mandatory password change on first login (superadmin and new users)
- **Secure First Run** — install.sh generates passwords instead of hardcoding in DB
- **Dual Encryption** — libsodium (sodium:) + AES-256-CBC (aes:), PHP ↔ Python compatible
- **HKDF Key Derivation** — Separate derived keys for passwords (rootwarden-aes) and TOTP secrets (rootwarden-totp)
- **Encrypted TOTP in DB** — 2FA secrets encrypted (Sodium/AES), backward-compatible plaintext
- **2FA TOTP** — Mandatory multi-factor authentication
- **RBAC** — 3 roles (user, admin, superadmin) + 13 granular permissions
- **DB-verified Auth** — checkAuth/checkPermission verify against database on every request, session = UI cache only
- **Anti-escalation** — Self-edit protection on all admin endpoints, superadmin non-modifiable, last superadmin protected
- **Unified CSRF** — checkCsrfToken() supports POST body, X-CSRF-TOKEN header, JSON body (timing-safe)
- **Dual SSH Auth** — Keypair mode (sudo NOPASSWD) + password mode (su -c via temp script), auto-detection
- **Password Expiry** — Configurable per user (Global/Exempt/30-365 days)
- **Session Timeout** — Auto-logout after inactivity (configurable)
- **Audit Log** — All admin actions logged, CSV export, filters
- **Login History** — All attempts tracked (IP, user-agent, status)
- **Compliance Report** — Printable HTML + CSV with SHA-256 hash
- **Terms & Privacy** — Professional pages with GDPR compliance (access/rectification/erasure/portability)
- **Auto DB Backup** — Compressed mysqldump, configurable retention
- **Locally Compiled Tailwind** — CSP without unsafe-eval, no external CDN
- **Isolated Docker Network** — Database on internal network only, no internet access
- **Restricted MySQL Privileges** — Application user without ALL PRIVILEGES (SELECT/INSERT/UPDATE/DELETE + migrations)
- **28+ Security Fixes (3 Audits)** — SQLi, CSRF, XSS, timing attack, etc.

### Notifications
- **Webhooks** — Slack, Teams, Discord, generic (critical CVEs, offline servers, deployments)
- **Email** — HTML CVE reports, user welcome email (SMTP)

### Dashboard
- **Security Alerts** — Users without 2FA, old SSH keys, offline servers, critical CVEs
- **Fleet Status** — Each server with OS version, status, CVEs, last check
- **Quick Access** — Shortcuts to modules based on permissions

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Frontend | PHP 8.4 + Apache, Tailwind CSS (locally compiled), htmx 2.0.4, vanilla JS |
| Backend API | Python 3.13, Flask, Hypercorn (ASGI) |
| Database | MySQL 9.2 |
| Containerization | Docker Compose |
| Docker Network | Dual (internal + external) |
| Encryption | libsodium (PyNaCl) + AES-256-CBC |
| API Proxy | PHP → Python (eliminates CORS, hides API_KEY) |
| i18n | 1424 keys FR/EN, 19 modules per language |
| Tests | pytest (139 tests), ruff (Python linter), php -l (PHP lint) |
| CI/CD | GitHub Actions (lint → test → Docker build) |

---

## Installation

### Prerequisites
- Docker + Docker Compose

### Quick Start

```bash
git clone https://github.com/Timikana/rootwarden.git
cd rootwarden
cp srv-docker.env.example srv-docker.env
# Edit srv-docker.env: generate unique keys (openssl rand -hex 32)
chmod 600 srv-docker.env
./start.sh -d
```

> The `start.sh` script automatically secures permissions and checks for default secrets.

### Access
- Interface: **https://localhost:8443**
- Superadmin account: auto-generated password on first run.
  Check: `docker exec <php_container> cat /var/www/html/.first_run_credentials`
  Password change is mandatory on first login.

### Preprod Environment (optional)

```bash
# Adds a Debian test server + mock OpenCVE
docker-compose --profile preprod up -d
```

### Key Environment Variables

| Variable | Description |
|----------|-----------|
| `SECRET_KEY` | AES/Sodium encryption key (hex 64 chars) |
| `API_KEY` | Frontend → backend authentication |
| `OPENCVE_URL` | OpenCVE URL (cloud or on-prem) |
| `OPENCVE_TOKEN` | Bearer token for OpenCVE v2 on-prem |
| `WEBHOOK_URL` | Webhook URL for Slack/Teams/Discord |
| `SESSION_TIMEOUT` | Session timeout in minutes (default 30) |
| `SSL_MODE` | auto / custom / disabled |
| `INIT_SUPERADMIN_PASSWORD` | Initial superadmin password (empty = auto-generated, recommended) |

See `srv-docker.env.example` for the full list.

---

## Migrations

```bash
# Check migration status
docker exec rootwarden_python python /app/db_migrate.py --status

# Apply pending migrations
docker exec rootwarden_python python /app/db_migrate.py
```

---

## Documentation

Full technical documentation available in the application: **https://localhost:8443/documentation.php**

Reference files:
- `ARCHITECTURE.md` — Map of all files, DB tables, data flows
- `CHANGELOG.md` — Version history (Semantic Versioning)

---

## Production Hardening

### Pre-deployment Checklist

1. **Unique secrets** — Generate all keys with `openssl rand -hex 32`
2. **start.sh** — Use `./start.sh` instead of `docker-compose up` (auto chmod + secret verification)
3. **File permissions** — `chmod 600 srv-docker.env` (automatic via start.sh on Linux)
4. **Remove initial credentials** — After first login:
   ```bash
   docker exec <php_container> rm /var/www/html/.first_run_credentials
   ```
5. **Clear INIT_SUPERADMIN_PASSWORD** — Remove the value from srv-docker.env after installation
6. **SSL** — Use SSL_MODE=custom with your own certificates (Let's Encrypt, enterprise cert)
7. **Host access** — Restrict SSH access to the Docker host to infrastructure admins only
8. **Backups** — Enable BACKUP_ENABLED=true with appropriate retention
9. **Monitoring** — Configure webhooks (Slack/Teams) for CVE alerts and offline servers

---

## FAQ / Troubleshooting

### Can't login after `docker-compose down -v`

A `down -v` deletes volumes (database). On restart, `init.sql` creates accounts
with invalid placeholders. `install.sh` must run to generate real passwords.
If the `www/.installed` flag still exists (bind mount), remove it:

```bash
rm -f www/.installed
./start.sh -d
docker exec <php_container> cat /var/www/html/.first_run_credentials
```

### Python container won't start (unhealthy / FileNotFoundError SSL)

Backend SSL certificates are auto-generated at startup. If the error persists
after a `git pull`, the Docker image is cached with old code:

```bash
docker compose down
docker compose build --no-cache python
docker compose up -d
```

### Default passwords don't work

Passwords are no longer hardcoded in `init.sql`. They are generated by
`install.sh` on first run. Use `start.sh` to start and check initial credentials:

```bash
docker exec <php_container> cat /var/www/html/.first_run_credentials
```

### Navigation is blocked during CVE scan / update

Fixed in v1.9.1 (`session_write_close()` in `api_proxy.php`).
Update if you're on an older version.

### CVE scan returns 0 vulnerabilities when there are some

Check the **CVSS threshold**: the per-server dropdown (next to the Scan button)
may differ from the global threshold. A `9+` (CRITICAL) threshold will filter
all HIGH and MEDIUM CVEs. Lower to `0+` to see everything.

Also check your browser isn't using cached JS (Ctrl+Shift+R).

### `docker compose down -v` — what happens?

| Flag `-v` | DB Data | SSH Keypair | Sessions | Passwords |
|-----------|---------|-------------|----------|-----------|
| Without `-v` | Preserved | Preserved | Preserved | Preserved |
| With `-v` | **Deleted** | **Deleted** | Deleted | Re-generated by install.sh via start.sh |

**Never use `-v` in production** unless you want to start from scratch.
After `down -v`, restart with `./start.sh -d` to re-generate credentials.

---

## Support the Project

If RootWarden is useful to you, you can support its development:

<a href="https://buymeacoffee.com/timikana" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40"></a>

---

## License

MIT

---

*RootWarden v1.13.1 — 2026-04-16*
