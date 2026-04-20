"""
routes/bashrc.py — Module Bashrc : deploiement standardise du .bashrc par utilisateur.

Maintenu  : Equipe Admin.Sys RootWarden
Version   : 1.14.0
Modifie   : 2026-04-20

Objectif :
    Deployer un .bashrc standardise (banniere figlet, tableau sysinfo, alias,
    prompt git-aware) sur chaque utilisateur Linux d'un serveur cible, en
    retravaillant les residus de configuration preexistants.

Routes :
    GET  /bashrc/users          — Liste des utilisateurs + etat bashrc
    POST /bashrc/prerequisites  — Installe figlet si manquant
    POST /bashrc/preview        — Diff avant deploiement
    POST /bashrc/deploy         — Deploie le .bashrc (overwrite|merge)
    POST /bashrc/restore        — Restaure .bashrc.bak.* le plus recent
    GET  /bashrc/backups        — Liste des backups dispo par user
    GET  /bashrc/template       — Lit le template actif (BDD)
    POST /bashrc/template       — Sauvegarde le template (editable via UI)

Securite :
    - Contenu transfere exclusivement en base64 (pas d'injection shell)
    - Usernames valides via regex stricte ^[a-z_][a-z0-9_-]*$
    - Toutes les verifications via SSH (pas docker exec) — le test-server
      Docker a des namespaces filesystem differents
    - Idempotence : pas de backup si sha256 identique au template deploye

Dependencies :
    routes.helpers (decorateurs + helpers DB/encryption)
    ssh_utils (ssh_session, execute_as_root, validate_machine_id)
"""

import os
import re
import json
import base64
import hashlib
import datetime
import difflib
import subprocess
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, require_permission,
    threaded_route, get_db_connection, server_decrypt_password, get_current_user, logger,
)
from ssh_utils import ssh_session, validate_machine_id, execute_as_root

bp = Blueprint('bashrc', __name__)

# ── Regex de validation ──────────────────────────────────────────────────────
_USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
_BACKUP_NAME_RE = re.compile(r'^\.bashrc\.bak\.\d{8}_\d{6}$')
_VALID_MODES = {'overwrite', 'merge'}

# ── Template standard ────────────────────────────────────────────────────────
# Source DB prioritaire (editable via UI /bashrc/ onglet Template).
# Fallback : fichier backend/templates/bashrc_standard.sh si la DB est vide.
_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / 'templates' / 'bashrc_standard.sh'
_DEFAULT_TEMPLATE_NAME = 'default'


def _load_template_from_file() -> str:
    """Charge le template .bashrc standardise depuis le disque (fallback)."""
    if not _TEMPLATE_PATH.is_file():
        raise FileNotFoundError(f"Template introuvable : {_TEMPLATE_PATH}")
    return _TEMPLATE_PATH.read_text(encoding='utf-8')


def _load_template(name: str = _DEFAULT_TEMPLATE_NAME) -> str:
    """Charge le template depuis la BDD. Si vide, seed depuis le fichier."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT content FROM bashrc_templates WHERE name = %s", (name,))
            row = cur.fetchone()
            if row and row.get('content'):
                return row['content']
            # Auto-seed : premier chargement → lit le fichier et le persiste
            file_content = _load_template_from_file()
            cur2 = conn.cursor()
            cur2.execute(
                "INSERT INTO bashrc_templates (name, content) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE content = VALUES(content)",
                (name, file_content)
            )
            conn.commit()
            return file_content
    except Exception as e:
        logger.warning("Lecture template DB echouee (%s), fallback fichier : %s", name, e)
        return _load_template_from_file()


def _save_template(name: str, content: str, user_id: int) -> None:
    """Sauvegarde un template en BDD."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO bashrc_templates (name, content, updated_by) VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE content = VALUES(content), updated_by = VALUES(updated_by)",
            (name, content, user_id or None)
        )
        conn.commit()


def _template_sha256(name: str = _DEFAULT_TEMPLATE_NAME) -> str:
    """SHA256 du template (pour l'idempotence)."""
    return hashlib.sha256(_load_template(name).encode('utf-8')).hexdigest()


# ── Helpers DB ───────────────────────────────────────────────────────────────

def _resolve_machine(machine_id):
    """Lookup credentials SSH en BDD. Retourne (row, error_response)."""
    try:
        mid = validate_machine_id(machine_id)
    except ValueError as e:
        return None, (jsonify({'success': False, 'message': str(e)}), 400)

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed "
            "FROM machines WHERE id = %s", (mid,))
        row = cur.fetchone()
    if not row:
        return None, (jsonify({'success': False, 'message': 'Machine introuvable'}), 404)
    return row, None


def _get_ssh_creds(row):
    """Extrait et dechiffre les credentials SSH d'une row machine."""
    return (
        row['ip'], row['port'], row['user'],
        server_decrypt_password(row['password'], logger=logger),
        server_decrypt_password(row['root_password'], logger=logger),
        bool(row.get('service_account_deployed', False)),
    )


def _audit_log(user_id: int, action: str, details: str):
    """Journalise une action dans user_logs."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                (user_id, f"[bashrc] {action} — {details}")
            )
            conn.commit()
    except Exception as e:
        logger.warning("Audit log bashrc echec : %s", e)


# ── Helpers SSH ──────────────────────────────────────────────────────────────

def _ssh_exec(client, cmd: str, root_password: str = None, as_root: bool = False, timeout: int = 30):
    """Execute une commande SSH (en user ou root). Retourne (stdout, stderr, exit_code)."""
    if as_root:
        out, err, code = execute_as_root(client, cmd, root_password, logger=logger, timeout=timeout)
        return out, err, code
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    code = stdout.channel.recv_exit_status()
    return out, err, code


def _list_users(client, root_password: str):
    """Retourne la liste des utilisateurs Linux (root + UID >= 1000, shells valides)."""
    cmd = (
        "awk -F: '($3 == 0 || $3 >= 1000) && "
        "$7 !~ /(nologin|false|sync|halt|shutdown)$/ "
        "{print $1\":\"$3\":\"$6\":\"$7}' /etc/passwd"
    )
    out, err, code = _ssh_exec(client, cmd, root_password, as_root=True, timeout=10)
    if code != 0:
        logger.warning("_list_users echec (code=%s) : %s", code, err)
        return []
    users = []
    for line in out.strip().splitlines():
        parts = line.split(':')
        if len(parts) != 4:
            continue
        name, uid, home, shell = parts
        if not _USERNAME_RE.match(name):
            continue
        users.append({
            'name': name,
            'uid': int(uid),
            'home': home.strip(),
            'shell': shell.strip(),
        })
    return users


def _inspect_bashrc(client, root_password: str, home: str, user: str):
    """Inspecte l'etat du .bashrc d'un user : existe, taille, mtime, sha256, custom blocks."""
    bashrc = f"{home}/.bashrc"
    # stat + sha256 + detection blocs custom (entre marqueurs) + content length
    cmd = (
        f"if [ -f '{bashrc}' ]; then "
        f"  sz=$(stat -c %s '{bashrc}' 2>/dev/null); "
        f"  mt=$(stat -c %Y '{bashrc}' 2>/dev/null); "
        f"  sha=$(sha256sum '{bashrc}' 2>/dev/null | cut -c1-8); "
        f"  cust=$(grep -c '>>> USER CUSTOM >>>' '{bashrc}' 2>/dev/null || echo 0); "
        f"  echo \"EXISTS|$sz|$mt|$sha|$cust\"; "
        f"else echo 'ABSENT|0|0|--------|0'; fi"
    )
    out, _, code = _ssh_exec(client, cmd, root_password, as_root=True, timeout=10)
    if code != 0:
        return {'exists': False, 'size': 0, 'mtime': 0, 'sha8': '--------', 'has_custom': False}
    parts = out.strip().splitlines()[-1].split('|')
    if len(parts) != 5:
        return {'exists': False, 'size': 0, 'mtime': 0, 'sha8': '--------', 'has_custom': False}
    status, sz, mt, sha, cust = parts
    return {
        'exists': status == 'EXISTS',
        'size': int(sz) if sz.isdigit() else 0,
        'mtime': int(mt) if mt.isdigit() else 0,
        'sha8': sha,
        'has_custom': (cust.strip().isdigit() and int(cust.strip()) > 0),
    }


def _read_remote_bashrc(client, root_password: str, home: str) -> str:
    """Lit le contenu du .bashrc distant (base64 pour eviter tout encoding issue)."""
    cmd = f"if [ -f '{home}/.bashrc' ]; then base64 -w0 '{home}/.bashrc'; fi"
    out, _, code = _ssh_exec(client, cmd, root_password, as_root=True, timeout=15)
    if code != 0 or not out.strip():
        return ""
    try:
        return base64.b64decode(out.strip()).decode('utf-8', errors='replace')
    except Exception:
        return ""


def _extract_custom_blocks(content: str) -> str:
    """Extrait les blocs entre marqueurs USER CUSTOM. Retourne le contenu concatene ou ''."""
    if not content:
        return ""
    blocks = re.findall(
        r'#\s*>>>\s*USER CUSTOM\s*>>>\s*\n(.*?)\n\s*#\s*<<<\s*USER CUSTOM\s*<<<',
        content, re.DOTALL
    )
    return "\n".join(b.rstrip() for b in blocks).strip()


def _build_diff(old: str, new: str, label: str = 'bashrc') -> str:
    """Unified diff colorise cote serveur (markers +/- + @@). Retourne du texte brut."""
    diff = difflib.unified_diff(
        old.splitlines(keepends=False),
        new.splitlines(keepends=False),
        fromfile=f'{label} (actuel)',
        tofile=f'{label} (standardise)',
        lineterm='',
    )
    return "\n".join(diff)


def _check_figlet(client, root_password: str) -> bool:
    """True si figlet est installe sur le serveur."""
    out, _, code = _ssh_exec(client, "command -v figlet >/dev/null 2>&1 && echo OK || echo KO",
                              root_password, as_root=False, timeout=5)
    return 'OK' in out


# ──────────────────────────────────────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@bp.route('/bashrc/users', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def list_users():
    """Retourne la liste des utilisateurs Linux + etat de leur .bashrc."""
    machine_id = request.args.get('machine_id')
    row, err = _resolve_machine(machine_id)
    if err:
        return err

    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            users = _list_users(client, root_pwd)
            figlet_present = _check_figlet(client, root_pwd)

            template_sha = _template_sha256()[:8]
            for u in users:
                state = _inspect_bashrc(client, root_pwd, u['home'], u['name'])
                u.update(state)
                u['matches_template'] = (state.get('sha8', '') == template_sha)

        return jsonify({
            'success': True,
            'machine_id': int(row['id']),
            'figlet_present': figlet_present,
            'template_sha8': template_sha,
            'users': users,
        })
    except Exception as e:
        logger.exception("Erreur list_users bashrc : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500


@bp.route('/bashrc/prerequisites', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def install_prerequisites():
    """Installe figlet sur le serveur si absent."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    row, err = _resolve_machine(machine_id)
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)

    try:
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            if _check_figlet(client, root_pwd):
                return jsonify({
                    'success': True, 'already_installed': True,
                    'message': 'figlet deja present.'
                })

            cmd = "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get install -y figlet"
            out, err_out, code = execute_as_root(client, cmd, root_pwd, logger=logger, timeout=180)
            ok = (code == 0) and _check_figlet(client, root_pwd)

            _audit_log(user_id, 'install_figlet',
                       f"machine_id={row['id']} ok={ok} code={code}")

            return jsonify({
                'success': ok,
                'already_installed': False,
                'exit_code': code,
                'stdout': (out or '')[-2000:],
                'stderr': (err_out or '')[-500:],
                'message': 'figlet installe.' if ok else "Echec d'installation de figlet.",
            }), (200 if ok else 500)
    except Exception as e:
        logger.exception("Erreur install_prerequisites : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500


@bp.route('/bashrc/preview', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def preview():
    """Retourne un diff entre le bashrc actuel et le template standard."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    users = data.get('users') or []
    mode = data.get('mode', 'overwrite')

    if mode not in _VALID_MODES:
        return jsonify({'success': False, 'message': f"Mode invalide : {mode}"}), 400
    if not users or not isinstance(users, list):
        return jsonify({'success': False, 'message': "Liste d'utilisateurs requise."}), 400
    for u in users:
        if not isinstance(u, str) or not _USERNAME_RE.match(u):
            return jsonify({'success': False, 'message': f"Username invalide : {u!r}"}), 400

    row, err = _resolve_machine(machine_id)
    if err:
        return err

    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)
    template = _load_template()

    try:
        results = []
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            all_users = {u['name']: u for u in _list_users(client, root_pwd)}
            for uname in users:
                u = all_users.get(uname)
                if not u:
                    results.append({'user': uname, 'error': 'Utilisateur introuvable'})
                    continue
                current = _read_remote_bashrc(client, root_pwd, u['home'])
                effective = template
                custom = ''
                if mode == 'merge':
                    custom = _extract_custom_blocks(current)
                    if custom:
                        effective = template + f"\n# ── USER CUSTOM (reinjected) ──\n{custom}\n"
                diff = _build_diff(current, effective, label=f".bashrc ({uname})")
                results.append({
                    'user': uname,
                    'home': u['home'],
                    'current_bytes': len(current),
                    'new_bytes': len(effective),
                    'custom_detected': bool(custom),
                    'diff': diff,
                })

        return jsonify({'success': True, 'mode': mode, 'results': results})
    except Exception as e:
        logger.exception("Erreur preview bashrc : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500


@bp.route('/bashrc/deploy', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def deploy():
    """Deploie le .bashrc standardise sur les utilisateurs selectionnes."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    users = data.get('users') or []
    mode = data.get('mode', 'overwrite')
    dry_run = bool(data.get('dry_run', False))

    if mode not in _VALID_MODES:
        return jsonify({'success': False, 'message': f"Mode invalide : {mode}"}), 400
    if not users or not isinstance(users, list):
        return jsonify({'success': False, 'message': "Liste d'utilisateurs requise."}), 400
    for u in users:
        if not isinstance(u, str) or not _USERNAME_RE.match(u):
            return jsonify({'success': False, 'message': f"Username invalide : {u!r}"}), 400

    row, err = _resolve_machine(machine_id)
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)
    template = _load_template()
    template_sha = _template_sha256()
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    try:
        results = []
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            all_users = {u['name']: u for u in _list_users(client, root_pwd)}
            for uname in users:
                u = all_users.get(uname)
                if not u:
                    results.append({'user': uname, 'ok': False, 'error': 'Utilisateur introuvable'})
                    continue

                home = u['home']
                bashrc = f"{home}/.bashrc"
                current = _read_remote_bashrc(client, root_pwd, home)
                current_sha = hashlib.sha256(current.encode('utf-8')).hexdigest() if current else ''

                # Idempotence
                if current and current_sha == template_sha and mode == 'overwrite':
                    results.append({
                        'user': uname, 'ok': True, 'skipped': True,
                        'reason': 'Deja conforme au template (sha256 identique).',
                    })
                    continue

                effective = template
                custom = ''
                if mode == 'merge':
                    custom = _extract_custom_blocks(current)
                    if custom:
                        # On stocke le bloc custom dans ~/.bashrc.local (sourcee section 13)
                        b64_custom = base64.b64encode(
                            (f"# Migre depuis ancien .bashrc le {ts}\n{custom}\n").encode('utf-8')
                        ).decode('ascii')

                if dry_run:
                    results.append({
                        'user': uname, 'ok': True, 'dry_run': True,
                        'would_backup': bool(current),
                        'custom_detected': bool(custom),
                        'new_bytes': len(effective),
                    })
                    continue

                # Backup (seulement si fichier existant)
                backup_name = f".bashrc.bak.{ts}"
                if current:
                    bkp_cmd = f"cp -a '{bashrc}' '{home}/{backup_name}' && chmod 600 '{home}/{backup_name}'"
                    _, bkp_err, bkp_code = _ssh_exec(client, bkp_cmd, root_pwd, as_root=True, timeout=10)
                    if bkp_code != 0:
                        results.append({'user': uname, 'ok': False,
                                        'error': f'Backup echoue : {bkp_err.strip()}'})
                        continue

                # Deploiement via base64 (pattern securise)
                b64 = base64.b64encode(effective.encode('utf-8')).decode('ascii')
                write_cmd = (
                    f"printf '%s' '{b64}' | base64 -d > '{bashrc}' && "
                    f"chmod 644 '{bashrc}' && "
                    f"chown {uname}:{uname} '{bashrc}'"
                )
                _, wr_err, wr_code = _ssh_exec(client, write_cmd, root_pwd, as_root=True, timeout=15)
                if wr_code != 0:
                    results.append({'user': uname, 'ok': False,
                                    'error': f'Ecriture echouee : {wr_err.strip()}'})
                    continue

                # Ecriture du bloc custom dans ~/.bashrc.local si mode merge
                if mode == 'merge' and custom:
                    local_b64 = base64.b64encode(
                        (f"# Migre depuis ancien .bashrc le {ts}\n{custom}\n").encode('utf-8')
                    ).decode('ascii')
                    local_cmd = (
                        f"printf '%s' '{local_b64}' | base64 -d >> '{home}/.bashrc.local' && "
                        f"chmod 644 '{home}/.bashrc.local' && "
                        f"chown {uname}:{uname} '{home}/.bashrc.local'"
                    )
                    _ssh_exec(client, local_cmd, root_pwd, as_root=True, timeout=10)

                # Validation syntaxique
                _, syn_err, syn_code = _ssh_exec(client, f"bash -n '{bashrc}'",
                                                  root_pwd, as_root=True, timeout=10)
                syntax_ok = (syn_code == 0)

                results.append({
                    'user': uname, 'ok': True, 'skipped': False,
                    'backup': backup_name if current else None,
                    'custom_migrated': bool(custom and mode == 'merge'),
                    'syntax_ok': syntax_ok,
                    'syntax_err': syn_err.strip() if not syntax_ok else '',
                })

        summary = {
            'total': len(results),
            'ok': sum(1 for r in results if r.get('ok')),
            'failed': sum(1 for r in results if not r.get('ok')),
            'skipped': sum(1 for r in results if r.get('skipped')),
        }
        _audit_log(user_id, 'deploy',
                   f"machine_id={row['id']} mode={mode} users={users} "
                   f"dry_run={dry_run} summary={summary}")

        return jsonify({'success': True, 'mode': mode, 'dry_run': dry_run,
                        'summary': summary, 'results': results})
    except Exception as e:
        logger.exception("Erreur deploy bashrc : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500


@bp.route('/bashrc/restore', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def restore():
    """Restaure le .bashrc.bak.* le plus recent pour un utilisateur."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    uname = data.get('user', '')
    backup = data.get('backup', '')  # optionnel : nom precis

    if not _USERNAME_RE.match(uname or ''):
        return jsonify({'success': False, 'message': f"Username invalide : {uname!r}"}), 400
    if backup and not _BACKUP_NAME_RE.match(backup):
        return jsonify({'success': False, 'message': f"Nom de backup invalide : {backup!r}"}), 400

    row, err = _resolve_machine(machine_id)
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)

    try:
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            all_users = {u['name']: u for u in _list_users(client, root_pwd)}
            u = all_users.get(uname)
            if not u:
                return jsonify({'success': False, 'message': 'Utilisateur introuvable'}), 404
            home = u['home']

            if not backup:
                # Recherche du backup le plus recent
                cmd = f"ls -1t '{home}'/.bashrc.bak.* 2>/dev/null | head -1"
                out, _, _ = _ssh_exec(client, cmd, root_pwd, as_root=True, timeout=10)
                latest = out.strip()
                if not latest:
                    return jsonify({'success': False, 'message': 'Aucun backup disponible'}), 404
                backup_path = latest
                backup = os.path.basename(latest)
                if not _BACKUP_NAME_RE.match(backup):
                    return jsonify({'success': False, 'message': 'Nom de backup inattendu'}), 400
            else:
                backup_path = f"{home}/{backup}"

            restore_cmd = (
                f"[ -f '{backup_path}' ] && "
                f"cp -a '{backup_path}' '{home}/.bashrc' && "
                f"chmod 644 '{home}/.bashrc' && "
                f"chown {uname}:{uname} '{home}/.bashrc'"
            )
            _, err_out, code = _ssh_exec(client, restore_cmd, root_pwd, as_root=True, timeout=15)
            ok = (code == 0)

            _audit_log(user_id, 'restore',
                       f"machine_id={row['id']} user={uname} backup={backup} ok={ok}")
            return jsonify({
                'success': ok,
                'user': uname, 'backup': backup,
                'message': 'Backup restaure.' if ok else f"Echec : {err_out.strip()}",
            }), (200 if ok else 500)
    except Exception as e:
        logger.exception("Erreur restore bashrc : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500


@bp.route('/bashrc/template', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@threaded_route
def get_template():
    """Retourne le template actif (BDD)."""
    try:
        content = _load_template()
        return jsonify({
            'success': True,
            'name': _DEFAULT_TEMPLATE_NAME,
            'content': content,
            'sha8': _template_sha256()[:8],
            'lines': content.count('\n') + 1,
            'bytes': len(content.encode('utf-8')),
        })
    except Exception as e:
        logger.exception("Erreur get_template : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


def _validate_bash_syntax(content: str):
    """Valide la syntaxe bash via `bash -n`. Retourne (ok, error_msg)."""
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False, encoding='utf-8') as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            res = subprocess.run(['bash', '-n', tmp_path],
                                 capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                return False, (res.stderr or 'Syntaxe invalide').strip()[:500]
            return True, ''
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except subprocess.TimeoutExpired:
        return False, 'Validation bash -n timeout'
    except Exception as e:
        return False, f'Erreur validation : {e}'


@bp.route('/bashrc/template', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@threaded_route
def save_template():
    """Sauvegarde le template (edition via UI). Valide la syntaxe bash avant write."""
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    if not isinstance(content, str) or len(content) == 0:
        return jsonify({'success': False, 'message': 'Contenu vide'}), 400
    if len(content) > 512 * 1024:
        return jsonify({'success': False, 'message': 'Contenu trop volumineux (512 Ko max)'}), 400

    # Validation syntaxe bash
    ok, err = _validate_bash_syntax(content)
    if not ok:
        return jsonify({'success': False, 'message': f"Syntaxe bash invalide : {err}"}), 400

    user_id, _ = get_current_user()
    try:
        # Diff pour audit log
        old_content = _load_template(_DEFAULT_TEMPLATE_NAME)
        diff_lines = list(difflib.unified_diff(
            old_content.splitlines(), content.splitlines(),
            fromfile='before', tofile='after', lineterm='', n=0,
        ))
        diff_summary = (
            f"+{sum(1 for l in diff_lines if l.startswith('+') and not l.startswith('+++'))}/"
            f"-{sum(1 for l in diff_lines if l.startswith('-') and not l.startswith('---'))}"
        )

        _save_template(_DEFAULT_TEMPLATE_NAME, content, user_id)
        sha8 = hashlib.sha256(content.encode('utf-8')).hexdigest()[:8]
        _audit_log(user_id, 'save_template',
                   f"name={_DEFAULT_TEMPLATE_NAME} sha8={sha8} bytes={len(content)} diff={diff_summary}")
        return jsonify({
            'success': True,
            'name': _DEFAULT_TEMPLATE_NAME,
            'sha8': sha8,
            'bytes': len(content.encode('utf-8')),
            'lines': content.count('\n') + 1,
            'diff_summary': diff_summary,
        })
    except Exception as e:
        logger.exception("Erreur save_template : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/bashrc/backups', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_bashrc')
@require_machine_access
@threaded_route
def list_backups():
    """Liste les backups .bashrc.bak.* disponibles pour un utilisateur."""
    machine_id = request.args.get('machine_id')
    uname = request.args.get('user', '')

    if not _USERNAME_RE.match(uname or ''):
        return jsonify({'success': False, 'message': f"Username invalide : {uname!r}"}), 400

    row, err = _resolve_machine(machine_id)
    if err:
        return err

    ip, port, ssh_user, ssh_pwd, root_pwd, svc = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pwd, logger, service_account=svc) as client:
            all_users = {u['name']: u for u in _list_users(client, root_pwd)}
            u = all_users.get(uname)
            if not u:
                return jsonify({'success': False, 'message': 'Utilisateur introuvable'}), 404
            home = u['home']

            cmd = (
                f"LC_ALL=C ls -la --time-style=+%s '{home}'/.bashrc.bak.* 2>/dev/null "
                f"| awk '{{print $5\"|\"$6\"|\"$NF}}'"
            )
            out, _, _ = _ssh_exec(client, cmd, root_pwd, as_root=True, timeout=10)
            backups = []
            for line in out.strip().splitlines():
                parts = line.split('|')
                if len(parts) != 3:
                    continue
                size, mtime, path = parts
                name = os.path.basename(path)
                if not _BACKUP_NAME_RE.match(name):
                    continue
                backups.append({
                    'name': name,
                    'size': int(size) if size.isdigit() else 0,
                    'mtime': int(mtime) if mtime.isdigit() else 0,
                })
            backups.sort(key=lambda b: b['mtime'], reverse=True)
            return jsonify({'success': True, 'user': uname, 'backups': backups})
    except Exception as e:
        logger.exception("Erreur list_backups bashrc : %s", e)
        return jsonify({'success': False, 'message': f"Erreur SSH : {e}"}), 500
