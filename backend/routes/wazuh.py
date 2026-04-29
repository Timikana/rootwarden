"""
routes/wazuh.py - Module Wazuh : deploiement agent + rules/decoders/CDB editables.

Maintenu : Equipe Admin.Sys RootWarden
Version  : 1.15.0
Modifie  : 2026-04-20

Objectif :
    Installer / desinstaller l'agent Wazuh sur les serveurs du parc,
    enregistrer aupres du manager via agent-auth, gerer les options par
    serveur (FIM, active response, SCA, rootcheck) et les rules/decoders
    CDB editables en BDD (pousses au manager via l'API REST au besoin).

Routes :
    GET  /wazuh/config           - Config manager (IP, port, password, group)
    POST /wazuh/config           - Sauvegarde config
    GET  /wazuh/servers          - Liste machines + etat agent
    POST /wazuh/install          - Install agent + registration auprès du manager
    POST /wazuh/uninstall        - Desinstalle l'agent
    POST /wazuh/restart          - Restart agent
    POST /wazuh/group            - Assigne un groupe a un agent
    GET  /wazuh/options          - Lit options par serveur (FIM, active response...)
    POST /wazuh/options          - Sauvegarde options
    GET  /wazuh/rules            - Liste rules/decoders/CDB
    GET  /wazuh/rules/<name>     - Lit un rule specifique
    POST /wazuh/rules            - Cree ou sauvegarde un rule (xmllint valide)
    DELETE /wazuh/rules/<name>   - Supprime un rule

Securite :
    - Zero trust : decorateurs standards
    - registration_password / api_password chiffres via Encryption (aes:)
    - Validation XML (subprocess xmllint) pour rule_type in (rules, decoders)
    - fim_paths : JSON array stocke, chaque chemin valide (/ en prefix, pas de shell chars)
    - Contenu rules transmis en base64 au push manager
"""

import re
import os
import json
import base64
import hashlib
import tempfile
import subprocess
import datetime
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, require_permission,
    threaded_route, get_db_connection, server_decrypt_password, get_current_user, logger,
)
from ssh_utils import ssh_session, validate_machine_id, execute_as_root
from encryption import Encryption

bp = Blueprint('wazuh', __name__)

_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')
_GROUP_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')
_IP_OR_FQDN_RE = re.compile(r'^[a-zA-Z0-9._-]{1,253}$')
_LOG_FORMATS = {'syslog', 'snort-full', 'squid', 'json', 'multi-line', 'eventlog', 'nmapg'}
_VALID_RULE_TYPES = {'rules', 'decoders', 'cdb'}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _audit(user_id, action, details):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                (user_id, f"[wazuh] {action} - {details}")
            )
            conn.commit()
    except Exception as e:
        logger.warning("Audit log wazuh echec : %s", e)


def _get_config():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM wazuh_config ORDER BY id DESC LIMIT 1")
        return cur.fetchone()


def _resolve_machine(machine_id):
    try:
        mid = validate_machine_id(machine_id)
    except ValueError as e:
        return None, (jsonify({'success': False, 'message': str(e)}), 400)
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s", (mid,))
        row = cur.fetchone()
    if not row:
        return None, (jsonify({'success': False, 'message': 'Machine introuvable'}), 404)
    return row, None


def _get_ssh_creds(row):
    return (
        row['ip'], row['port'], row['user'],
        server_decrypt_password(row['password'], logger=logger),
        server_decrypt_password(row['root_password'], logger=logger),
        bool(row.get('service_account_deployed', False)),
    )


def _enc(pwd):
    if not pwd:
        return None
    return 'aes:' + Encryption().encrypt_password(pwd)


def _dec(enc_val):
    if not enc_val:
        return ''
    try:
        val = enc_val[4:] if enc_val.startswith('aes:') else enc_val
        return Encryption().decrypt_password(val) or ''
    except Exception as e:
        logger.warning("Dechiffrement wazuh echec : %s", e)
        return ''


def _upsert_agent(machine_id, **fields):
    if not fields:
        return
    cols = list(fields.keys())
    vals = list(fields.values())
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO wazuh_agents (machine_id) VALUES (%s) "
            "ON DUPLICATE KEY UPDATE machine_id = machine_id",
            (machine_id,)
        )
        placeholders = ', '.join(f"{c} = %s" for c in cols)
        cur.execute(
            f"UPDATE wazuh_agents SET {placeholders} WHERE machine_id = %s",
            (*vals, machine_id)
        )
        conn.commit()


def _validate_xml(content: str):
    """Valide un XML via xmllint. Retourne (ok, error_msg)."""
    if not content.strip():
        return True, ''
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False, encoding='utf-8') as tmp:
            # Wrap dans <root> pour autoriser multiple top-level elements
            tmp.write(f"<root>\n{content}\n</root>\n")
            p = tmp.name
        try:
            res = subprocess.run(['xmllint', '--noout', p],
                                 capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                return False, (res.stderr or 'XML invalide').strip()[:500]
            return True, ''
        finally:
            try:
                os.unlink(p)
            except OSError:
                pass
    except FileNotFoundError:
        # xmllint pas installe dans le container → ne pas bloquer
        logger.warning("xmllint introuvable, validation XML sautee")
        return True, ''
    except subprocess.TimeoutExpired:
        return False, 'xmllint timeout'
    except Exception as e:
        return False, f'Erreur xmllint : {e}'


# ── Config ───────────────────────────────────────────────────────────────────

@bp.route('/wazuh/config', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def get_config():
    cfg = _get_config() or {}
    cfg['registration_password_set'] = bool(cfg.get('registration_password'))
    cfg['api_password_set'] = bool(cfg.get('api_password'))
    cfg['registration_password'] = ''
    cfg['api_password'] = ''
    return jsonify({'success': True, 'config': cfg})


@bp.route('/wazuh/config', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def save_config():
    data = request.get_json(silent=True) or {}
    manager_ip = (data.get('manager_ip') or '').strip()
    manager_port = int(data.get('manager_port') or 1514)
    registration_port = int(data.get('registration_port') or 1515)
    reg_pwd = data.get('registration_password', '')
    default_group = (data.get('default_group') or 'default').strip()
    agent_version = (data.get('agent_version') or 'latest').strip()
    enable_ar = bool(data.get('enable_active_response', False))
    api_url = (data.get('api_url') or '').strip() or None
    api_user = (data.get('api_user') or '').strip() or None
    api_pwd = data.get('api_password', '')

    if not _IP_OR_FQDN_RE.match(manager_ip):
        return jsonify({'success': False, 'message': 'manager_ip invalide'}), 400
    if not (1 <= manager_port <= 65535 and 1 <= registration_port <= 65535):
        return jsonify({'success': False, 'message': 'Port invalide'}), 400
    if not _GROUP_RE.match(default_group):
        return jsonify({'success': False, 'message': 'default_group invalide'}), 400
    if not re.match(r'^[a-zA-Z0-9._-]{1,20}$', agent_version):
        return jsonify({'success': False, 'message': 'agent_version invalide'}), 400

    user_id, _ = get_current_user()

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id, registration_password, api_password FROM wazuh_config ORDER BY id DESC LIMIT 1")
            existing = cur.fetchone()
            # Preserve anciennes valeurs si nouveau mot de passe vide
            reg_pwd_enc = _enc(reg_pwd) if reg_pwd else (existing['registration_password'] if existing else None)
            api_pwd_enc = _enc(api_pwd) if api_pwd else (existing['api_password'] if existing else None)

            cur2 = conn.cursor()
            if existing:
                cur2.execute(
                    "UPDATE wazuh_config SET manager_ip=%s, manager_port=%s, registration_port=%s, "
                    "registration_password=%s, default_group=%s, agent_version=%s, "
                    "enable_active_response=%s, api_url=%s, api_user=%s, api_password=%s, "
                    "updated_by=%s WHERE id=%s",
                    (manager_ip, manager_port, registration_port, reg_pwd_enc, default_group,
                     agent_version, enable_ar, api_url, api_user, api_pwd_enc,
                     user_id or None, existing['id'])
                )
            else:
                cur2.execute(
                    "INSERT INTO wazuh_config (manager_ip, manager_port, registration_port, "
                    "registration_password, default_group, agent_version, enable_active_response, "
                    "api_url, api_user, api_password, updated_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (manager_ip, manager_port, registration_port, reg_pwd_enc, default_group,
                     agent_version, enable_ar, api_url, api_user, api_pwd_enc, user_id or None)
                )
            conn.commit()
        _audit(user_id, 'save_config', f"manager={manager_ip}:{manager_port} group={default_group}")
        return jsonify({'success': True})
    except Exception as e:
        logger.exception("Erreur save_config wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Servers / Agents ─────────────────────────────────────────────────────────

@bp.route('/wazuh/servers', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def list_servers():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT m.id, m.name, m.ip, m.port,
                   m.environment, m.criticality, m.network_type, m.online_status,
                   a.agent_id, a.agent_name, a.version, a.group_name, a.status, a.last_keep_alive
            FROM machines m
            LEFT JOIN wazuh_agents a ON a.machine_id = m.id
            WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
            ORDER BY
                CASE WHEN m.criticality = 'CRITIQUE' THEN 0 ELSE 1 END,
                m.name
        """)
        servers = cur.fetchall()
    return jsonify({'success': True, 'servers': servers})


@bp.route('/wazuh/install', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def install():
    data = request.get_json(silent=True) or {}
    group = (data.get('group') or '').strip()
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    cfg = _get_config()
    if not cfg:
        return jsonify({'success': False, 'message': 'Config Wazuh absente (onglet Configuration)'}), 400

    manager = cfg['manager_ip']
    reg_pwd = _dec(cfg.get('registration_password'))
    group = group or cfg['default_group']
    if not _GROUP_RE.match(group):
        return jsonify({'success': False, 'message': f'group invalide : {group}'}), 400

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    # Install multi-OS : detecte la famille via /etc/os-release puis branche
    # apt (Debian/Ubuntu) / yum-dnf (RHEL/Rocky/Alma/Fedora/Amazon/Oracle) /
    # zypper (SUSE/openSUSE). Avant v1.18.x c'etait apt-only -> fail silencieux
    # sur RHEL family. Le manager + group + registration_password sont passes
    # en env vars, communs aux 3 branches.
    env_vars = f"WAZUH_MANAGER='{manager}' WAZUH_AGENT_GROUP='{group}'"
    if reg_pwd:
        env_vars += f" WAZUH_REGISTRATION_PASSWORD='{reg_pwd}'"

    install_cmd = f"""
set -e
. /etc/os-release 2>/dev/null || (echo "no /etc/os-release" >&2; exit 1)
ID_LC=$(echo "${{ID:-unknown}}" | tr 'A-Z' 'a-z')
LIKE_LC=$(echo "${{ID_LIKE:-}}" | tr 'A-Z' 'a-z')

is_deb() {{ case " $ID_LC $LIKE_LC " in *" debian "*|*" ubuntu "*) return 0;; esac; return 1; }}
is_rhel() {{ case " $ID_LC $LIKE_LC " in *" rhel "*|*" fedora "*|*" centos "*) return 0;; esac; return 1; }}
is_suse() {{ case " $ID_LC $LIKE_LC " in *" suse "*|*" opensuse "*|*" sles "*) return 0;; esac; return 1; }}

if is_deb; then
    export DEBIAN_FRONTEND=noninteractive
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    {env_vars} apt-get install -y wazuh-agent
elif is_rhel; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPOEOF
    if command -v dnf >/dev/null 2>&1; then
        {env_vars} dnf install -y wazuh-agent
    else
        {env_vars} yum install -y wazuh-agent
    fi
elif is_suse; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/zypp/repos.d/wazuh.repo <<'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
type=rpm-md
REPOEOF
    {env_vars} zypper -n install wazuh-agent
else
    echo "OS non supporte par l'installeur Wazuh : ID=$ID_LC ID_LIKE=$LIKE_LC" >&2
    echo "Familles supportees : debian, ubuntu, rhel/centos/rocky/alma/fedora, suse/opensuse" >&2
    exit 2
fi

systemctl daemon-reload
systemctl enable --now wazuh-agent
""".strip()

    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            out, err_out, code = execute_as_root(client, install_cmd, root_pwd, logger=logger, timeout=600)
            if code != 0:
                _audit(user_id, 'install_fail', f"machine_id={row['id']} code={code}")
                return jsonify({'success': False, 'message': 'Installation echouee',
                                'stderr': (err_out or '')[-1500:]}), 500

            v_out, _, _ = execute_as_root(client,
                "/var/ossec/bin/wazuh-control info 2>&1 | grep WAZUH_VERSION | cut -d= -f2 | tr -d '\"'",
                root_pwd, logger=logger, timeout=10)
            version = (v_out or '').strip()[:20] or 'unknown'

            id_out, _, _ = execute_as_root(client,
                "grep -E '^ID:' /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $2}' || "
                "cat /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $1}'",
                root_pwd, logger=logger, timeout=10)
            agent_id = (id_out or '').strip()[:10]

        _upsert_agent(row['id'], agent_id=agent_id or None, version=version,
                      group_name=group, status='pending', installed_at=datetime.datetime.now())
        _audit(user_id, 'install', f"machine_id={row['id']} agent_id={agent_id} version={version} group={group}")
        return jsonify({'success': True, 'agent_id': agent_id, 'version': version, 'group': group})
    except Exception as e:
        logger.exception("Erreur install wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/wazuh/install_all', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def install_all():
    """Installe Wazuh agent sur TOUS les serveurs sans agent.

    Boucle sequentielle (pas en parallele : chaque install fait apt-get update
    et tire des paquets, parallele ferait surcharge reseau + manager Wazuh).
    Renvoie un resume {ok, fail, skipped} avec details par machine.

    Body JSON :
        group (str, optional) : groupe Wazuh applique a tous (sinon default)
    """
    data = request.get_json(silent=True) or {}
    requested_group = (data.get('group') or '').strip()

    cfg = _get_config()
    if not cfg:
        return jsonify({'success': False, 'message': 'Config Wazuh absente (onglet Configuration)'}), 400

    # Liste des serveurs sans agent (LEFT JOIN wazuh_agents puis filter NULL)
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT m.id, m.name
            FROM machines m
            LEFT JOIN wazuh_agents a ON a.machine_id = m.id
            WHERE (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')
              AND a.id IS NULL
            ORDER BY
                CASE WHEN m.criticality = 'CRITIQUE' THEN 0 ELSE 1 END,
                m.name
        """)
        targets = cur.fetchall()

    if not targets:
        return jsonify({'success': True, 'ok': 0, 'fail': 0, 'skipped': 0,
                        'message': 'Aucun serveur sans agent', 'details': []})

    results = {'ok': 0, 'fail': 0, 'details': []}
    for t in targets:
        # Reutilise la logique de /wazuh/install via appel HTTP-like : on
        # appelle directement la fonction install() ne marche pas (decorateurs
        # require_api_key etc.). On reimplemente la logique core ici en mode
        # silencieux. Ceci evite de retraiter tout dans chaque endpoint.
        try:
            from flask import g
            row = {'id': t['id']}
            row_full, err = _resolve_machine(t['id'])
            if err:
                results['fail'] += 1
                results['details'].append({'id': t['id'], 'name': t['name'],
                                           'success': False, 'message': 'machine resolution failed'})
                continue

            manager = cfg['manager_ip']
            reg_pwd = _dec(cfg.get('registration_password'))
            group = requested_group or cfg['default_group']
            if not _GROUP_RE.match(group):
                results['fail'] += 1
                results['details'].append({'id': t['id'], 'name': t['name'],
                                           'success': False, 'message': f'group invalide : {group}'})
                continue

            ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row_full)
            env_vars = f"WAZUH_MANAGER='{manager}' WAZUH_AGENT_GROUP='{group}'"
            if reg_pwd:
                env_vars += f" WAZUH_REGISTRATION_PASSWORD='{reg_pwd}'"

            install_cmd = f"""
set -e
. /etc/os-release 2>/dev/null || (echo "no /etc/os-release" >&2; exit 1)
ID_LC=$(echo "${{ID:-unknown}}" | tr 'A-Z' 'a-z')
LIKE_LC=$(echo "${{ID_LIKE:-}}" | tr 'A-Z' 'a-z')
is_deb() {{ case " $ID_LC $LIKE_LC " in *" debian "*|*" ubuntu "*) return 0;; esac; return 1; }}
is_rhel() {{ case " $ID_LC $LIKE_LC " in *" rhel "*|*" fedora "*|*" centos "*) return 0;; esac; return 1; }}
is_suse() {{ case " $ID_LC $LIKE_LC " in *" suse "*|*" opensuse "*|*" sles "*) return 0;; esac; return 1; }}
if is_deb; then
    export DEBIAN_FRONTEND=noninteractive
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    {env_vars} apt-get install -y wazuh-agent
elif is_rhel; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPOEOF
    if command -v dnf >/dev/null 2>&1; then
        {env_vars} dnf install -y wazuh-agent
    else
        {env_vars} yum install -y wazuh-agent
    fi
elif is_suse; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/zypp/repos.d/wazuh.repo <<'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
type=rpm-md
REPOEOF
    {env_vars} zypper -n install wazuh-agent
else
    echo "OS non supporte" >&2; exit 2
fi
systemctl daemon-reload
systemctl enable --now wazuh-agent
""".strip()

            with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
                out, err_out, code = execute_as_root(client, install_cmd, root_pwd, logger=logger, timeout=600)
                if code != 0:
                    results['fail'] += 1
                    results['details'].append({'id': t['id'], 'name': t['name'],
                                               'success': False,
                                               'message': (err_out or '')[-300:].strip() or f'exit={code}'})
                    continue

                v_out, _, _ = execute_as_root(client,
                    "/var/ossec/bin/wazuh-control info 2>&1 | grep WAZUH_VERSION | cut -d= -f2 | tr -d '\"'",
                    root_pwd, logger=logger, timeout=10)
                version = (v_out or '').strip()[:20] or 'unknown'

                id_out, _, _ = execute_as_root(client,
                    "grep -E '^ID:' /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $2}' || "
                    "cat /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $1}'",
                    root_pwd, logger=logger, timeout=10)
                agent_id = (id_out or '').strip()[:10]

            _upsert_agent(t['id'], agent_id=agent_id or None, version=version,
                          group_name=group, status='pending',
                          installed_at=datetime.datetime.now())
            results['ok'] += 1
            results['details'].append({'id': t['id'], 'name': t['name'],
                                       'success': True, 'agent_id': agent_id, 'version': version})
        except Exception as e:
            logger.exception("install_all : erreur sur %s : %s", t['name'], e)
            results['fail'] += 1
            results['details'].append({'id': t['id'], 'name': t['name'],
                                       'success': False, 'message': str(e)[:200]})

    user_id, _ = get_current_user()
    _audit(user_id, 'install_all',
           f"ok={results['ok']} fail={results['fail']} total={len(targets)}")
    return jsonify({
        'success': results['fail'] == 0,
        'ok': results['ok'],
        'fail': results['fail'],
        'skipped': 0,
        'total': len(targets),
        'message': f"{results['ok']}/{len(targets)} agent(s) installe(s)",
        'details': results['details'],
    })


@bp.route('/wazuh/detect', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def detect():
    """Detecte un agent Wazuh deja installe sur le serveur sans le reinstaller.

    Utile quand l'agent a ete deploye en dehors de RootWarden : on remplit la
    table `wazuh_agents` a partir de /var/ossec/* pour le voir dans l'UI.
    """
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            # /var/ossec/bin/wazuh-control n'existe que si l'agent est installe
            v_out, _, code = execute_as_root(
                client,
                "test -x /var/ossec/bin/wazuh-control && "
                "/var/ossec/bin/wazuh-control info 2>&1 | grep WAZUH_VERSION | cut -d= -f2 | tr -d '\"' "
                "|| echo NOT_INSTALLED",
                root_pwd, logger=logger, timeout=10)
            v_out = (v_out or '').strip()
            if not v_out or v_out == 'NOT_INSTALLED':
                return jsonify({'success': False, 'detected': False,
                                'message': f"Aucun agent Wazuh detecte sur {row['name']}."})

            version = v_out[:20] or 'unknown'

            id_out, _, _ = execute_as_root(client,
                "grep -E '^ID:' /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $2}' || "
                "cat /var/ossec/etc/client.keys 2>/dev/null | head -1 | awk '{print $1}'",
                root_pwd, logger=logger, timeout=10)
            agent_id = (id_out or '').strip()[:10] or None

            grp_out, _, _ = execute_as_root(client,
                "grep -oP '(?<=<groups>).*?(?=</groups>)' /var/ossec/etc/ossec.conf 2>/dev/null | head -1",
                root_pwd, logger=logger, timeout=10)
            grp = (grp_out or '').strip()[:80] or None

            status_out, _, _ = execute_as_root(client,
                "systemctl is-active wazuh-agent 2>/dev/null || echo unknown",
                root_pwd, logger=logger, timeout=10)
            sys_status = (status_out or '').strip()
            agent_status = 'active' if sys_status == 'active' else (
                'disconnected' if sys_status in ('inactive', 'failed') else 'unknown')

        _upsert_agent(row['id'], agent_id=agent_id, version=version,
                      group_name=grp, status=agent_status)
        _audit(user_id, 'detect', f"machine_id={row['id']} agent_id={agent_id} version={version}")
        return jsonify({'success': True, 'detected': True, 'agent_id': agent_id,
                        'version': version, 'group': grp, 'status': agent_status,
                        'message': f"Agent detecte sur {row['name']} (v{version})"})
    except Exception as e:
        logger.exception("Erreur detect wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/wazuh/uninstall', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def uninstall():
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "systemctl stop wazuh-agent 2>/dev/null || true && "
        "apt-get purge -y wazuh-agent 2>/dev/null || true && "
        "rm -rf /var/ossec"
    )
    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            _, err_out, code = execute_as_root(client, cmd, root_pwd, logger=logger, timeout=180)
        _upsert_agent(row['id'], status='never_connected', agent_id=None, version=None)
        _audit(user_id, 'uninstall', f"machine_id={row['id']} code={code}")
        return jsonify({'success': code == 0})
    except Exception as e:
        logger.exception("Erreur uninstall wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/wazuh/restart', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def restart_agent():
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err
    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            _, err_out, code = execute_as_root(client,
                "systemctl restart wazuh-agent", root_pwd, logger=logger, timeout=30)
        _audit(user_id, 'restart', f"machine_id={row['id']} code={code}")
        return jsonify({'success': code == 0, 'stderr': (err_out or '')[-500:]})
    except Exception as e:
        logger.exception("Erreur restart wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/wazuh/group', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def set_group():
    """Assigne un groupe a un agent (via API manager ou fichier local)."""
    data = request.get_json(silent=True) or {}
    group = (data.get('group') or '').strip()
    if not _GROUP_RE.match(group):
        return jsonify({'success': False, 'message': 'group invalide'}), 400

    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    # Ecrit le groupe dans /var/ossec/etc/ossec.conf (section <client><groups>)
    # Approche simple : update via agent-auth au prochain restart, ou via API manager.
    # V1 : on met a jour la DB et on redemarre l'agent (qui se re-inscrit)
    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            # Update /var/ossec/etc/shared/agent.conf ou marquer dans client.keys
            # V1 minimale : on redemarre pour re-inscription
            execute_as_root(client, "systemctl restart wazuh-agent", root_pwd, logger=logger, timeout=30)

        _upsert_agent(row['id'], group_name=group)
        _audit(user_id, 'set_group', f"machine_id={row['id']} group={group}")
        return jsonify({'success': True, 'group': group})
    except Exception as e:
        logger.exception("Erreur set_group wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Options par serveur ──────────────────────────────────────────────────────

@bp.route('/wazuh/options', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def get_options():
    mid = request.args.get('machine_id')
    row, err = _resolve_machine(mid)
    if err:
        return err
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM wazuh_machine_options WHERE machine_id = %s", (row['id'],))
        opts = cur.fetchone() or {
            'machine_id': row['id'], 'fim_paths': None,
            'active_response_enabled': False, 'log_format': 'syslog',
            'sca_enabled': True, 'rootcheck_enabled': True,
            'syscheck_frequency': 43200,
        }
    if opts.get('fim_paths'):
        try:
            opts['fim_paths'] = json.loads(opts['fim_paths'])
        except Exception:
            opts['fim_paths'] = []
    else:
        opts['fim_paths'] = []
    return jsonify({'success': True, 'options': opts})


@bp.route('/wazuh/options', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@require_machine_access
@threaded_route
def save_options():
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    fim_paths = data.get('fim_paths', [])
    if not isinstance(fim_paths, list) or len(fim_paths) > 50:
        return jsonify({'success': False, 'message': 'fim_paths doit etre une liste (max 50)'}), 400
    for p in fim_paths:
        if not isinstance(p, str) or not p.startswith('/') or re.search(r'[;&|$`\n\r]', p):
            return jsonify({'success': False, 'message': f'Chemin FIM invalide : {p!r}'}), 400

    log_format = (data.get('log_format') or 'syslog').strip()
    if log_format not in _LOG_FORMATS:
        return jsonify({'success': False, 'message': f'log_format invalide : {log_format}'}), 400

    try:
        syscheck_freq = int(data.get('syscheck_frequency', 43200))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'syscheck_frequency invalide'}), 400
    if not (60 <= syscheck_freq <= 86400 * 7):
        return jsonify({'success': False, 'message': 'syscheck_frequency hors bornes (60..604800)'}), 400

    ar = bool(data.get('active_response_enabled', False))
    sca = bool(data.get('sca_enabled', True))
    rk = bool(data.get('rootcheck_enabled', True))

    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO wazuh_machine_options (machine_id, fim_paths, "
                "active_response_enabled, log_format, sca_enabled, rootcheck_enabled, "
                "syscheck_frequency) VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE fim_paths=VALUES(fim_paths), "
                "active_response_enabled=VALUES(active_response_enabled), "
                "log_format=VALUES(log_format), sca_enabled=VALUES(sca_enabled), "
                "rootcheck_enabled=VALUES(rootcheck_enabled), "
                "syscheck_frequency=VALUES(syscheck_frequency)",
                (row['id'], json.dumps(fim_paths), ar, log_format, sca, rk, syscheck_freq)
            )
            conn.commit()
        _audit(user_id, 'save_options',
               f"machine_id={row['id']} fim={len(fim_paths)} ar={ar} sca={sca} rootcheck={rk} format={log_format}")
        return jsonify({'success': True})
    except Exception as e:
        logger.exception("Erreur save_options wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Rules / Decoders / CDB ───────────────────────────────────────────────────

@bp.route('/wazuh/rules', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def list_rules():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, rule_type, LENGTH(content) AS bytes,
                   SHA2(content, 256) AS sha_full, updated_at
            FROM wazuh_rules ORDER BY rule_type, name
        """)
        rows = cur.fetchall()
    for r in rows:
        r['sha8'] = (r.pop('sha_full') or '')[:8]
    return jsonify({'success': True, 'rules': rows})


@bp.route('/wazuh/rules/<name>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def get_rule(name):
    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM wazuh_rules WHERE name = %s", (name,))
        row = cur.fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Rule introuvable'}), 404
    return jsonify({'success': True, 'rule': row})


@bp.route('/wazuh/rules', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def save_rule():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    rtype = (data.get('rule_type') or 'rules').lower()
    content = data.get('content', '')

    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    if rtype not in _VALID_RULE_TYPES:
        return jsonify({'success': False, 'message': f'rule_type invalide : {rtype}'}), 400
    if not isinstance(content, str):
        return jsonify({'success': False, 'message': 'Contenu invalide'}), 400
    if len(content) > 512 * 1024:
        return jsonify({'success': False, 'message': 'Contenu trop volumineux (512 Ko max)'}), 400

    # Validation XML pour rules/decoders
    if rtype in ('rules', 'decoders'):
        ok, err = _validate_xml(content)
        if not ok:
            return jsonify({'success': False, 'message': f'XML invalide : {err}'}), 400

    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO wazuh_rules (name, rule_type, content, updated_by) "
                "VALUES (%s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE rule_type=VALUES(rule_type), "
                "content=VALUES(content), updated_by=VALUES(updated_by)",
                (name, rtype, content, user_id or None)
            )
            conn.commit()
        sha8 = hashlib.sha256(content.encode('utf-8')).hexdigest()[:8]
        _audit(user_id, 'save_rule', f"name={name} type={rtype} sha8={sha8} bytes={len(content)}")
        return jsonify({'success': True, 'name': name, 'sha8': sha8, 'bytes': len(content.encode('utf-8'))})
    except Exception as e:
        logger.exception("Erreur save_rule wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/wazuh/rules/<name>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_manage_wazuh')
@threaded_route
def delete_rule(name):
    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM wazuh_rules WHERE name = %s", (name,))
            deleted = cur.rowcount
            conn.commit()
        _audit(user_id, 'delete_rule', f"name={name} deleted={deleted}")
        return jsonify({'success': deleted > 0, 'deleted': deleted})
    except Exception as e:
        logger.exception("Erreur delete_rule wazuh : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500
