[🇫🇷 Version française](README.md)

# 🔐 RootWarden

> **RootWarden** is a **self-hosted DevSecOps** platform for centralised Linux server
> administration. From a single interface: SSH access and sudo rights, updates, firewall,
> Fail2ban, systemd services, `sshd_config` audit, CVE vulnerabilities, monitoring and compliance.

**Version 2.0** — Laravel web portal, Python backend driving the fleet over SSH. The exact
number is shown at the bottom of the portal menu; history is in [CHANGELOG.md](CHANGELOG.md).

---

## Features

The portal menu has four sections. Each entry only appears to accounts holding the matching
permission.

### Fleet & access
- **Platform SSH key** — an Ed25519 keypair owned by RootWarden, deployed as a service account on
  the servers: no password needed once in place.
- **Remote users** — inventory of the accounts present on each server, classification, removal.
- **SSH keys** — deploys users' keys to a selection of servers, with a **mandatory pre-check**:
  nothing is deployed if a single machine fails, and the reason is shown.
- **Sudo rights** — sudo policies per user and per server (presets: no sudo, service restart, apt,
  log reading, full sudo).
- **SFTP/SSH access** — per-user access restrictions.

### Operations
- **Updates** — live `apt update/upgrade`, pending packages, scheduled security updates, delayed
  reboot.
- **Services** — start, stop, restart systemd services, `journalctl` logs.
- **Monitoring** — deploys and configures Zabbix Agent 2, Centreon, Prometheus Node Exporter and
  Telegraf agents; reusable profiles, per-server overrides.
- **Bashrc** — standardised per-user `.bashrc`, with backup and restore.
- **Docker containers** — container inventory and image update watch.
- **Graylog** — deploys Graylog Sidecar and its collectors.

### Security
- **CVE scan** — through OpenCVE (cloud or on-prem), **EPSS + CISA KEV** prioritisation,
  remediation tracking, ITSM ticket creation (Jira, ServiceNow, GLPI, webhook), CSV export.
- **Compliance** — printable report and CSV with a SHA-256 fingerprint.
- **Config drift** — detects configuration deviations.
- **Firewall** — view, edit, history and restore of iptables rules.
- **Fail2ban** — install, jails, IP ban and unban.
- **SSH audit** — `sshd_config` grading (A to F), fixes, backup and restore.
- **Wazuh** — agent deployment and enrolment, rules and decoders.

### Administration
- **Accounts and permissions** — 3 roles (user, admin, superadmin) and fine-grained permissions,
  permanent or **temporary**.
- **Groups & bulk actions** — dynamic or static groups, actions on a whole group.
- **Four-eyes approvals** — sensitive actions require a second administrator's sign-off.
- **Maintenance windows**, **task centre**, **database backups**.
- **Audit log** sealed by a hash chain (tampering is detectable) and **command log**.
- **Global search** and **ChatOps** (Slack, Teams, generic webhook).

### Portal security
- **Mandatory TOTP second factor** for every account, with replay protection.
- **Re-authentication** (step-up) before sensitive actions.
- Account lockout and per-IP attempt limiting.
- Password history and optional HaveIBeenPwned check.
- Server-side revocable sessions, remote sign-out.
- API keys segmented by scope, stored hashed.
- Self-service GDPR export of one's personal data.
- Interface in **French and English**.

---

## Architecture

```
browser ──HTTPS 8443──▶ laravel (portal, Apache)
                           │  authenticated gateway
                           ▼
                        python (backend API, internal network)  ──SSH──▶ Linux servers
                           │
                           ▼
                          db (MySQL, internal network)
```

- Only the portal is published (`8443` over HTTPS, `8080` redirects to HTTPS).
- The backend and the database are only reachable from the internal Docker network.
- The portal never talks to servers directly: every action goes through the backend, with rights
  checked in the database on each call.

## Tech stack

| Component | Technology |
|-----------|------------|
| Portal | Laravel 13, PHP 8.4, Apache — hand-written CSS and JavaScript, no build step |
| Backend | Python 3.13, Flask, Hypercorn, Paramiko |
| Database | MySQL 9.2 (schema managed in `mysql/migrations/`) |
| Deployment | Docker Compose |
| Tests | PHPUnit, pytest, Puppeteer E2E suites |
| CI | GitHub Actions: tests, lint, semgrep, bandit, gitleaks, Trivy, pip-audit, composer audit |

---

## Installation

### Requirements
- Docker and Docker Compose
- Git

### Getting started

```bash
git clone https://github.com/Timikana/rootwarden.git
cd rootwarden
cp srv-docker.env.example srv-docker.env
# Edit srv-docker.env: generate unique keys (openssl rand -hex 32)
chmod 600 srv-docker.env
./start.sh -d
```

The portal is then served at **https://localhost:8443**.

### First account

A fresh database holds a `superadmin` account **with no usable password**. To give it one:

```bash
docker exec -u www-data rootwarden_laravel php artisan rootwarden:premier-compte
```

The password is shown **only once**. It must be changed at first sign-in, where the second factor
(TOTP) is enrolled. The command refuses to run if a usable superadmin already exists: it is only
meant to bootstrap an installation.

### Operations scripts

| Script | When to use it | What it does |
|--------|----------------|--------------|
| `./start.sh [-d]` | Start / restart | env merge, `chmod 600`, warning on default secrets, `docker compose up` |
| `./stop.sh [-v]` | Stop | `docker compose down` (asks for confirmation with `-v`, which deletes volumes) |
| `./maj.sh` | Update | `git pull` → env merge → build → migrations → `up -d` → backend restart |

`./maj.sh --check` shows what would be done without running anything.

**Env merge** (`scripts/env-merge.sh`, called by `start.sh` and `maj.sh`): keys present in
`srv-docker.env.example` and missing from your `srv-docker.env` are appended with their comment.
**Your existing values are never changed.**

### Optional modules

```bash
# In srv-docker.env
WAZUH_ENABLED=false
```

A disabled module disappears from the menu, and the backend no longer exposes its routes.

### Pre-production environment (optional)

```bash
# Adds a Debian test server and a fake OpenCVE
docker compose --profile preprod up -d
```

### Main environment variables

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | Encryption key for secrets stored in the database (hex, 64 characters) |
| `API_KEY` | Portal authentication to the backend |
| `APP_URL` | Public address of the portal (links in emails) |
| `OPENCVE_URL` / `OPENCVE_TOKEN` | Vulnerability source (cloud or on-prem) |
| `WEBHOOK_URL` | Slack, Teams, Discord or generic notifications |
| `MAIL_*` | Email (SMTP) — **disabled by default**: set `MAIL_MAILER=smtp` to send |
| `SSL_MODE` | Portal certificate: `auto`, `custom` or `disabled` |
| `BACKUP_ENABLED` | Automatic database backups |

The full, commented list is in [`srv-docker.env.example`](srv-docker.env.example).

---

## Database migrations

```bash
# Migration status
docker exec rootwarden_python python /app/db_migrate.py --status

# Apply pending migrations (./maj.sh already does it)
docker exec rootwarden_python python /app/db_migrate.py
```

---

## Documentation

- In the portal: menu **Other → Documentation**.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — files, tables, data flows.
- [`OPERATIONS.md`](OPERATIONS.md) — day-to-day operations.
- [`CHANGELOG.md`](CHANGELOG.md) — version history.
- [`docs/migration/`](docs/migration/) — log of the migration to Laravel.
- [`obsidian-rootwarden/`](obsidian-rootwarden/obsidian-rootwarden-vault/) — Obsidian vault (open
  the folder as a vault, graph view with `Ctrl+G`).

---

## Securing a production installation

1. **Unique secrets** — generate every key with `openssl rand -hex 32`.
2. **`./start.sh`** rather than `docker compose up`: it sets `chmod 600`, flags secrets left at
   their default value and asks for confirmation before starting.
3. **Production mode** — in `laravel/.env`: `APP_ENV=production` and `APP_DEBUG=false`.
4. **Secure cookies** — `SESSION_SECURE_COOKIE=true` in `srv-docker.env`.
5. **Certificate** — `SSL_MODE=custom` with your own certificate.
6. **Host access** — restrict SSH access to the Docker host to administrators: root on the host
   gives access to everything.
7. **Backups** — `BACKUP_ENABLED=true` with a suitable retention.
8. **Alerts** — configure a webhook for critical CVEs and unreachable servers.

To report a vulnerability: see [`CONTRIBUTING-SECURITY.md`](CONTRIBUTING-SECURITY.md).

---

## FAQ / Troubleshooting

### The portal shows a 500 error right after installation

Check that `laravel/.env` exists and holds an `APP_KEY`:

```bash
docker exec rootwarden_laravel grep -c '^APP_KEY=base64:' /var/www/html/.env
```

If it is missing, copy `laravel/.env.example` to `laravel/.env`, set `APP_ENV=production` and
`APP_DEBUG=false`, then restart the `laravel` container: the key is generated at startup.

### The Python backend does not start after a `git pull`

The Docker image is cached with the old code:

```bash
docker compose build --no-cache python
docker compose up -d
```

### The CVE scan returns no vulnerability

Check the server's **CVSS threshold**: a `9+` threshold hides every HIGH and MEDIUM CVE.
Also check `OPENCVE_URL` and `OPENCVE_TOKEN`.

### `docker compose down -v`: what happens?

| | Database | Platform SSH keypair |
|---|---|---|
| without `-v` | kept | kept |
| with `-v` | **deleted** | **deleted** |

**Never use `-v` in production**, unless you want to start from scratch.

---

## Support the project

If RootWarden is useful to you, you can support its development:

<a href="https://buymeacoffee.com/timikana" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40"></a>

---

## License

MIT
