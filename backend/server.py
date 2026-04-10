#!/usr/bin/env python3
"""
server.py — Coeur de l'API Flask du projet RootWarden.

Initialise l'application Flask, enregistre les Blueprints de routes,
configure CORS, les logs, les migrations et le scheduler.

Les routes sont decoupees en modules dans le dossier routes/ :
  - routes/monitoring.py  : health check, list machines, statuts, versions, trends
  - routes/updates.py     : APT update, Zabbix, scheduling, dry-run, pending
  - routes/cve.py         : scans CVE, resultats, schedules, whitelist, remediation
  - routes/iptables.py    : regles firewall, validation, historique, rollback
  - routes/ssh.py         : deploy, logs, preflight, keypair plateforme, scan users
  - routes/admin.py       : backups, lifecycle serveur, exclusions

Helpers partages dans routes/helpers.py :
  require_api_key, threaded_route, get_db_connection, server_decrypt_password
"""

import os
import logging

from flask import Flask, Response, request

from config import Config

# ─────────────────────────────────────────────────────────────────────────────
# Migrations de base de donnees — executees au demarrage
# ─────────────────────────────────────────────────────────────────────────────
try:
    from db_migrate import run_migrations
    run_migrations(strict=False)
except Exception as _migrate_err:
    logging.getLogger(__name__).warning(
        "Impossible d'executer les migrations au demarrage : %s", _migrate_err
    )

# ─────────────────────────────────────────────────────────────────────────────
# Generation de la keypair plateforme (auth SSH sans password)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from ssh_key_manager import generate_platform_key
    generate_platform_key()
except Exception as _key_err:
    logging.getLogger(__name__).warning(
        "Impossible de generer la keypair plateforme : %s", _key_err
    )

# ─────────────────────────────────────────────────────────────────────────────
# Application Flask
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB max request body

# ─────────────────────────────────────────────────────────────────────────────
# Enregistrement des Blueprints
# ─────────────────────────────────────────────────────────────────────────────
from routes.monitoring import bp as monitoring_bp
from routes.iptables import bp as iptables_bp
from routes.admin import bp as admin_bp
from routes.cve import bp as cve_bp
from routes.ssh import bp as ssh_bp
from routes.updates import bp as updates_bp
from routes.fail2ban import bp as fail2ban_bp
from routes.services import bp as services_bp

app.register_blueprint(monitoring_bp)
app.register_blueprint(iptables_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(cve_bp)
app.register_blueprint(ssh_bp)
app.register_blueprint(updates_bp)
app.register_blueprint(fail2ban_bp)
app.register_blueprint(services_bp)

# ─────────────────────────────────────────────────────────────────────────────
# CORS manuel (compatible Hypercorn ASGI)
# ─────────────────────────────────────────────────────────────────────────────
allowed_origin = os.getenv("URL_HTTPS", "https://srv-docker:8443")
https_port = os.getenv("HTTPS_PORT", "8443")
allowed_origins = [allowed_origin, f"https://localhost:{https_port}"]


@app.route('/<path:path>', methods=['OPTIONS'])
@app.route('/', methods=['OPTIONS'])
def handle_preflight(path=''):
    """Repond aux requetes CORS preflight (OPTIONS)."""
    origin = request.headers.get('Origin', '')
    resp = Response('OK', status=200, content_type='text/plain')
    if origin in allowed_origins:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Headers'] = 'X-API-KEY, Content-Type'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        resp.headers['Access-Control-Max-Age'] = '3600'
    return resp


@app.after_request
def add_cors_headers(response):
    """Ajoute les headers CORS sur toutes les reponses."""
    origin = request.headers.get('Origin', '')
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'X-API-KEY, Content-Type'
    return response

# ─────────────────────────────────────────────────────────────────────────────
# Configuration des logs
# ─────────────────────────────────────────────────────────────────────────────
log_dir = "/app/logs"
os.makedirs(log_dir, exist_ok=True)

_paramiko_level = logging.DEBUG if Config.LOG_LEVEL == 'DEBUG' else logging.WARNING
logging.getLogger("paramiko").setLevel(_paramiko_level)

server_log_file = os.path.join(log_dir, "server.log")

_log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)
_log_format = (
    '%(asctime)s [%(levelname)s] %(name)s %(funcName)s:%(lineno)d — %(message)s'
    if Config.DEBUG else
    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logging.basicConfig(
    level=_log_level,
    format=_log_format,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(server_log_file),
    ]
)
logger = logging.getLogger(__name__)

if Config.DEBUG:
    logger.warning(
        "⚠️  DEBUG_MODE activé — NE PAS utiliser en production. "
        "Les traces détaillées et les informations sensibles sont visibles dans les logs."
    )

# Init des fichiers de log
for _lf in ['deployment.log', 'iptables.log', 'server.log', 'update_servers.log']:
    _path = os.path.join(log_dir, _lf)
    if not os.path.exists(_path):
        with open(_path, 'w') as f:
            pass
    try:
        os.chmod(_path, 0o640)
    except OSError:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Demarrage du scheduler (scans CVE planifies, purge logs, backups)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from scheduler import start_scheduler
    start_scheduler()
except Exception as _sched_err:
    logging.getLogger(__name__).warning(
        "Impossible de demarrer le scheduler : %s", _sched_err
    )


if __name__ == '__main__':
    ssl_context = ("ssl/srv-docker.pem", "ssl/srv-docker-key.pem")
    print("Demarrage du serveur Flask en HTTPS sur le port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=ssl_context)
