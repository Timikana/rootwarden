[🇫🇷 Version francaise](README.md)

# RootWarden v1.37.1

> **RootWarden** is a **DevSecOps** platform for centralized Linux server administration.
> Deploy it on your infrastructure to manage SSH, updates, firewall, Fail2ban,
> systemd services, sshd_config audit and CVE vulnerabilities - from a single interface.

## 🆕 v1.24 → v1.37 — Advanced DevSecOps (⚠️ beta, dev-tested only)

Post-audit wave of features. Each feature is a full vertical slice (idempotent migration + backend + UI + FR/EN i18n + docs + Puppeteer test). **Validated in development only, not yet in production** — see the warning at the top of the [CHANGELOG](CHANGELOG.md). Sensitive features are **OFF by default** (`APPROVAL_ENABLED`, `CHATOPS_ENABLED`, `TICKETING_ENABLED`). Apply migrations **052 → 061**.

**Security / vulnerabilities**
- **EPSS + CISA KEV prioritization** (v1.27) — each CVE enriched with an exploitation probability (EPSS, FIRST.org) and an "actively exploited" flag (CISA KEV); priority sorting, re-prioritize without re-scan.
- **Compliance posture score (CIS-like)** (v1.26) — A-F grade per server (sshd + CVE + fail2ban + drift), included in CSV/PDF exports.
- **Configuration drift detection** (v1.24) — compares desired/actual state (sudo, sshd, fail2ban) without SSH.

**Governance & operations**
- **Machine groups + bulk actions** (v1.28) — dynamic groups (env / criticality / network / tags) or static, group-wide drift/CVE scan tracked in the task center.
- **Maintenance windows** (v1.29) — allowed time windows for mutating actions (update/reboot blocked outside the window, HTTP 423; superadmin bypass).
- **4-eyes approval** (v1.30) — second-admin validation before destructive actions (beyond step-up 2FA).
- **Command log / bastion** (v1.31) — trail of privileged commands actually executed (who / what / where / when / result).
- **Task center** (v1.25) — visibility on background tasks (CVE/SSH/drift scans, backups).

**Integrations**
- **Bidirectional ChatOps** (v1.32) — fleet status + approvals from Slack/Teams (Slack signature or shared token, user mapping, 4-eyes enforced).
- **ITSM ticketing** (v1.33) — CVE finding → Jira / ServiceNow / GLPI / generic webhook ticket (+ auto-create for KEV CVEs).
- **Docker container watch** (v1.37) — per-server inventory + available updates: **image** side (local digest vs registry) and **git** side (commits behind + changelog).

**Operations & UX**
- **Global search** (v1.34) — servers / users / CVEs / tickets / audit in one place, + audit-log viewer (HMAC chain) reachable from the menu.
- **Backup restore from the UI** (v1.35) — integrity test (sha256), superadmin restore with automatic safety backup.
- **Separate Sudo / SFTP pages + plain-language help** (v1.36) — every option (chroot, ForceCommand, forwarding…) explained for non-experts.
- **OWASP Top 10 audit of the new features** (v1.37.1) — 6 fixes (A01 access control, A03 XSS, A10 SSRF).

## 🆕 v1.22.x — Per-user sudo + SFTP policies

- **Fine-grained sudo per (user × server)**: dropdown of 7 presets (apt_only, restart_services, read_logs, systemctl_specific, all_nopasswd, custom, none) directly in `Administration → Access & Permissions`. NOPASSWD inline. "Advanced →" link to full UI.
- **Per-user SFTP policies** (`/adm/server_user_policies.php`): ChrootDirectory, ForceCommand internal-sftp, AllowTcpForwarding, AllowAgentForwarding, X11Forwarding per Linux account.
- **Systematic validation**: `visudo -cf` (sudoers) + `sshd -t` (sshd_config) BEFORE atomic `mv`. `.rwbak` backup with auto-restore on reload failure.
- **Audit + 1-click rollback**: `policy_deployments` table with policy_snapshot JSON + before/after content. "Restore this version" button from history.
- **Desired/actual state pattern** (v1.22.2): `user_machine_access.sudo_preset` = admin intent, applied on next SSH deploy via `configure_servers.py::add_to_sudoers()` rendered by `sudo_manager.render_policy()`.
- **Step-up 2FA** on deploy/remove/rollback (action `policy_action`, 15 min freshness). HMAC audit_log chain with auto-scrub if content > 200 chars.

## What's new in v1.21.2 (API keys UX patch)

- **Redesigned creation form**: 8 quick presets + checklist of 15 modules that auto-generate the scope regexes. Advanced textarea for power users.
- **"API Keys" button** visible in the admin toolbar (previously orphaned).
- **"↻ Renew" button** on each revoked key: re-creates with same scope + same consumer_hint, suffix `-rYYYYMMDD-HHMMSS`. Anti-duplicate guards.
- **`consumer_hint` field**: free-text memo "where is this key used" (`srv-docker.env:API_KEY`, `GitLab CI`, `ansible-vault`). No credential stored, just a reminder shown at renewal.
- **Guided rotation**: UI banner + `maj.sh` warning if active non-auto-generated keys are older than 90 days (yellow) or 180 days (red). Source `created_at`.
- Migration `047_api_keys_consumer_hint.sql` is idempotent.

## What's new in v1.21.1 (bashrc UX patch)

- Bashrc module: **one-click multi-server deploy** via checklist (was a single-server dropdown).
- Vertical list with **"Last deployment"** column, color-coded (green <30d, yellow 30-90d, red >90d, italic gray if never).
- Last deploy date pulled from `user_logs` (excludes dry-runs), rendered in browser timezone.
- "Deploy multi" / "Dry-run multi" purple buttons activate as soon as >1 server is selected. Iterates N servers, deploys to all non-system users, aggregated results with per-server details.
- Collateral CSP fix: rolled back the nonce in `csp_header_value()` (CSP3 was ignoring `unsafe-inline` -> all inline scripts in the repo were silently broken). Re-activation procedure documented in `legacy/includes/csp_nonce.php` for after the full inline-scripts migration.

## What's new in v1.21.0 — OWASP Top 10 Security Hardening

Full OWASP Top 10 audit + 30 findings patched across 3 waves. Zero regression detected via Puppeteer. See [OPERATIONS.md](OPERATIONS.md) for deployment and [CONTRIBUTING-SECURITY.md](CONTRIBUTING-SECURITY.md) for conventions.

**Highlights**:
- Python backend re-verifies role + permissions in DB on every request (no more HTTP header trust)
- AES-256-GCM (AEAD) encryption instead of unauthenticated CBC (bit-flipping defeated)
- Audit log hash chain : HMAC-SHA256 with dedicated `AUDIT_HMAC_KEY` (auto-generated by `env-merge.sh`)
- Step-up auth (re-2FA) on destructive actions (delete_user, update_permissions) + automatic UI modal
- Kill-switch `/revoke_service_account` (superadmin) : bulk userdel + sudoers purge
- Rate limits : 2FA per IP, CVE scan per user (60s), cron schedule min 10 min
- SSRF guard on external URLs (OpenCVE, NVD, webhooks) + machine IP blocklist (loopback, 169.254.x, etc.)
- `api_proxy.php` explicit route whitelist (anti-IDOR on new blueprints)
- `shlex.quote` on all shell arguments (anti-RCE in Wazuh, Graylog, bashrc)
- bcrypt cost 12, centralized log scrubber (passwords/tokens/secrets never in clear)
- CSP nonces (CSP3 ignores unsafe-inline when nonce present)
- Hardened `docker-compose.prod.yml` : `cap_drop ALL`, `read_only`, `tmpfs`, user 1000 (non-root)
- `maj.sh` verifies commit GPG signature (strict mode opt-in via `MAJ_REQUIRE_SIGNED=1`)
- 10 custom Semgrep rules (`.semgrep/rules-rootwarden.yml`) blocking in CI for anti-regression
- Full operational documentation (`OPERATIONS.md`)

---

## Features

### Server Management
- **SSH Keys** - Mass deployment, key age tracking (alert > 90 days)
- **Linux Updates** - APT update/upgrade with real-time streaming, `su -c` fallback if sudo unavailable
- **iptables Firewall** - View, edit, save/restore rules from database
- **Fail2ban** - Service detection (SSH/FTP/Apache/Nginx/Mail), jail activation, ban/unban IP, auto-install
- **systemd Services** - Start, stop, restart Linux services. journalctl logs, auto-categorization, protected services
- **SSH Audit** - Scan sshd_config, security scoring (A-F), one-click fixes, config editor, backups/restore, toggle directives ON/OFF, reload sshd
- **Multi-agent Supervision** - Deploy and configure monitoring agents via SSH. Supports Zabbix Agent 2, Centreon Monitoring Agent, Prometheus Node Exporter and Telegraf. Global config per platform, per-server overrides, remote config editor, backups/restore, multi-agent badges, scan all agents in one click
- **Standardized Bashrc** - Deploy a unified `.bashrc` per Linux user (figlet banner, sysinfo table, alerts, git-aware prompt, aliases). Overwrite or merge mode (custom blocks preserved via `~/.bashrc.local`). Automatic backup, one-click restore, post-deploy syntax check, sha256 idempotence, colorized diff preview.
- **Graylog Sidecar** - Deploy the Graylog Sidecar (filebeat/nxlog/winlogbeat) over SSH. Central server configuration, editable YAML/XML collector templates with YAML validation, auto-registration with the Graylog manager.
- **Wazuh Agent** - Deploy + enroll the Wazuh agent with the manager. Group management, per-server FIM / active response / SCA / rootcheck options, editable rules / decoders / CDB lists (xmllint validation). Manager API integration to push rules.
- **Docker containers** (v1.37) - Per-server container inventory (`docker ps`/`inspect`) + update watch: image digest vs registry (Docker Hub/GHCR/internal) and git commits behind with changelog
- **Groups & bulk actions** (v1.28) - Dynamic groups (env/criticality/network/tags) or static, group-wide drift/CVE scan
- **Maintenance windows** (v1.29) - Allowed time windows for mutating actions (update/reboot)
- **Custom Tags** - Label your servers (web, db, production, dmz...) and filter by tag

### CVE Vulnerability Scanning
- **OpenCVE** - Supports cloud (app.opencve.io) and on-prem v2 (Bearer token)
- **EPSS + CISA KEV prioritization** (v1.27) - exploitation probability (EPSS) + "actively exploited" flag (KEV), priority score, dedicated sorting and badges
- **Finding → ITSM ticket** (v1.33) - Jira / ServiceNow / GLPI / webhook, + auto-create for KEV CVEs
- **Real-time Streaming** - JSON-lines, per-package progress
- **Filters** - By severity (CRITICAL/HIGH/MEDIUM) and year
- **CSV Export** - One-click download per server
- **Global Summary** - Fleet overview at the top of the page

### Security & Compliance
- **Ed25519 Platform Keypair** - Passwordless SSH auth, progressive migration, secrets removal from DB
- **rootwarden Service Account** - Dedicated Linux user with sudoers NOPASSWD:ALL, zero password required
- **Password Reset by Email** - "Forgot password" link on login page, 1h token, PHPMailer
- **Secure Startup (start.sh)** - Auto chmod 600 on .env, default secret detection, password masking in Docker logs
- **force_password_change** - Mandatory password change on first login (superadmin and new users)
- **Secure First Run** - install.sh generates passwords instead of hardcoding in DB
- **Dual Encryption** - libsodium (sodium:) + AES-256-CBC (aes:), PHP ↔ Python compatible
- **HKDF Key Derivation** - Separate derived keys for passwords (rootwarden-aes) and TOTP secrets (rootwarden-totp)
- **Encrypted TOTP in DB** - 2FA secrets encrypted (Sodium/AES), backward-compatible plaintext
- **2FA TOTP** - Mandatory multi-factor authentication
- **RBAC** - 3 roles (user, admin, superadmin) + 13 granular permissions
- **DB-verified Auth** - checkAuth/checkPermission verify against database on every request, session = UI cache only
- **Anti-escalation** - Self-edit protection on all admin endpoints, superadmin non-modifiable, last superadmin protected
- **Unified CSRF** - checkCsrfToken() supports POST body, X-CSRF-TOKEN header, JSON body (timing-safe)
- **Dual SSH Auth** - Keypair mode (sudo NOPASSWD) + password mode (su -c via temp script), auto-detection
- **Password Expiry** - Configurable per user (Global/Exempt/30-365 days)
- **Session Timeout** - Auto-logout after inactivity (configurable)
- **Audit Log** - All admin actions logged, CSV export, filters
- **Login History** - All attempts tracked (IP, user-agent, status)
- **Compliance Report** - Printable HTML + CSV with SHA-256 hash
- **Terms & Privacy** - Professional pages with GDPR compliance (access/rectification/erasure/portability)
- **Auto DB Backup** - Compressed mysqldump, configurable retention
- **Locally Compiled Tailwind** - CSP without unsafe-eval, no external CDN
- **Isolated Docker Network** - Database on internal network only, no internet access
- **Restricted MySQL Privileges** - Application user without ALL PRIVILEGES (SELECT/INSERT/UPDATE/DELETE + migrations)
- **Two-layer brute-force protection** - IP rate limit (5/10min) + per-user lockout with **progressive backoff** (3=1min, 4=5min, 5=15min, 6=1h, 7+=4h). Password spraying detection (>= 5 distinct usernames/10min from same IP → superadmin alert). Admin "Unlock" button.
- **Tamper-evident audit log** - Every `user_logs` row sealed with an SHA2-256 hash chain (prev_hash | user_id | action | unix_ts). `/adm/api/audit_verify.php` recomputes the chain and flags any alteration (MISMATCH / PREV_BROKEN). "Verify integrity" button in audit log.
- **Segmented API keys** - `api_keys` table with route-regex scope (e.g. `["^/cve/", "^/list_machines$"]`). Format `rw_live_XXXXXX_...`, stored as SHA-256. Superadmin CRUD UI with rotation + soft revocation + `last_used_at`/`last_used_ip` tracking. Zero-downtime fallback to legacy `Config.API_KEY` until the table is populated.
- **CI supply-chain security** - gitleaks (committed secrets), bandit (Python SAST), pip-audit + composer audit (SCA), trivy fs (repo) + trivy image (containers). `auto-tag` depends on all scans → no release on critical CVE.
- **Server-side session revocation** - `verify.php` checks `active_sessions` on every request → "Revoke" / "Sign out others" has an immediate effect, invalidating stolen cookies.
- **Password history + HIBP** - Refuses reuse of the last 5 passwords (`password_history` table). Opt-in HaveIBeenPwned check via k-anonymity API (first 5 SHA1 hex sent, configurable threshold).
- **GDPR self-service** - `/profile/export.php` route: any user downloads their personal data as JSON (profile + logs + sessions + prefs, hashes masked). Admin endpoint `/adm/api/anonymize_user.php`: soft-delete preserving audit log (art. 17.3.e).
- **28+ Security Fixes (3 Audits)** - SQLi, CSRF, XSS, timing attack, etc.

### Notifications
- **Webhooks** - Slack, Teams, Discord, generic (critical CVEs, offline servers, deployments)
- **Email** - HTML CVE reports, user welcome email (SMTP)

### Dashboard
- **Security Alerts** - Users without 2FA, old SSH keys, offline servers, critical CVEs
- **Fleet Status** - Each server with OS version, status, CVEs, last check
- **Quick Access** - Shortcuts to modules based on permissions

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
| `URL_HTTPS` | Internal URL (frontend JS) - e.g. `https://lagoon:8443` |
| `URL_PUBLIC_HTTPS` | Public URL for outgoing emails (optional, behind reverse-proxy) - e.g. `https://cleopatre-ssh.magiline.fr` |

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
- `ARCHITECTURE.md` - Map of all files, DB tables, data flows
- `CHANGELOG.md` - Version history (Semantic Versioning)

---

## Production Hardening

### Pre-deployment Checklist

1. **Unique secrets** - Generate all keys with `openssl rand -hex 32`
2. **start.sh** - Use `./start.sh` instead of `docker-compose up` (auto chmod + secret verification)
3. **File permissions** - `chmod 600 srv-docker.env` (automatic via start.sh on Linux)
4. **Remove initial credentials** - After first login:
   ```bash
   docker exec <php_container> rm /var/www/html/.first_run_credentials
   ```
5. **Clear INIT_SUPERADMIN_PASSWORD** - Remove the value from srv-docker.env after installation
6. **SSL** - Use SSL_MODE=custom with your own certificates (Let's Encrypt, enterprise cert)
7. **Host access** - Restrict SSH access to the Docker host to infrastructure admins only
8. **Backups** - Enable BACKUP_ENABLED=true with appropriate retention
9. **Monitoring** - Configure webhooks (Slack/Teams) for CVE alerts and offline servers

---

## FAQ / Troubleshooting

### Can't login after `docker-compose down -v`

A `down -v` deletes volumes (database). On restart, `init.sql` creates accounts
with invalid placeholders. `install.sh` must run to generate real passwords.
If the `legacy/.installed` flag still exists (bind mount), remove it:

```bash
rm -f legacy/.installed
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

### `docker compose down -v` - what happens?

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

*RootWarden v1.20.0 - 2026-05-05*
