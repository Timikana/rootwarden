"""
ssh_audit.py — Helpers pour l'audit de configuration SSH (sshd_config) sur serveurs distants.

Fonctions pures qui prennent un client Paramiko + root_password et executent
des commandes d'analyse via execute_as_root().

Fonctions principales :
    get_sshd_config()       — Recupere le contenu de /etc/ssh/sshd_config
    get_ssh_version()       — Recupere la version d'OpenSSH
    audit_sshd_config()     — Analyse la config contre les regles de securite
    backup_sshd_config()    — Cree un backup date de sshd_config
    apply_fix()             — Applique un correctif + validation + reload
"""
import re
import logging
import datetime

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

# ── Regles d'audit ────────────────────────────────────────────────────────────

AUDIT_RULES = [
    # CRITICAL
    {'key': 'PermitRootLogin', 'check': 'bad_values', 'bad': ['yes', 'without-password', 'prohibit-password'],
     'severity': 'critical', 'msg_key': 'permit_root_login', 'fix': 'no'},
    {'key': 'PermitEmptyPasswords', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'critical', 'msg_key': 'permit_empty_passwords', 'fix': 'no'},
    # HIGH
    {'key': 'PasswordAuthentication', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'high', 'msg_key': 'password_auth', 'fix': 'no'},
    {'key': 'X11Forwarding', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'high', 'msg_key': 'x11_forwarding', 'fix': 'no'},
    {'key': 'UsePAM', 'check': 'bad_values', 'bad': ['no'],
     'severity': 'high', 'msg_key': 'use_pam', 'fix': 'yes'},
    {'key': 'ChallengeResponseAuthentication', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'high', 'msg_key': 'challenge_response', 'fix': 'no'},
    # MEDIUM
    {'key': 'MaxAuthTries', 'check': 'int_gt', 'threshold': 4,
     'severity': 'medium', 'msg_key': 'max_auth_tries', 'fix': '3'},
    {'key': 'LoginGraceTime', 'check': 'int_gt', 'threshold': 60,
     'severity': 'medium', 'msg_key': 'login_grace_time', 'fix': '30'},
    {'key': 'ClientAliveInterval', 'check': 'int_eq', 'threshold': 0,
     'severity': 'medium', 'msg_key': 'client_alive_interval', 'fix': '300'},
    {'key': 'ClientAliveCountMax', 'check': 'int_gt', 'threshold': 3,
     'severity': 'medium', 'msg_key': 'client_alive_count', 'fix': '2'},
    {'key': 'AllowTcpForwarding', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'medium', 'msg_key': 'tcp_forwarding', 'fix': 'no'},
    {'key': 'AllowAgentForwarding', 'check': 'bad_values', 'bad': ['yes'],
     'severity': 'medium', 'msg_key': 'agent_forwarding', 'fix': 'no'},
    # LOW
    {'key': 'Protocol', 'check': 'bad_values', 'bad': ['1'],
     'severity': 'low', 'msg_key': 'protocol_v1', 'fix': '2'},
    {'key': 'LogLevel', 'check': 'bad_values', 'bad': ['QUIET'],
     'severity': 'low', 'msg_key': 'log_level', 'fix': 'VERBOSE'},
    {'key': 'MaxSessions', 'check': 'int_gt', 'threshold': 10,
     'severity': 'low', 'msg_key': 'max_sessions', 'fix': '5'},
    # INFO
    {'key': 'Banner', 'check': 'missing',
     'severity': 'info', 'msg_key': 'banner', 'fix': '/etc/issue.net'},
]

SEVERITY_POINTS = {'critical': 25, 'high': 15, 'medium': 10, 'low': 5, 'info': 0}

ALLOWED_DIRECTIVES = {rule['key'] for rule in AUDIT_RULES}

# Valeurs autorisees par directive (whitelist stricte pour eviter injection)
ALLOWED_VALUES = {}
for _r in AUDIT_RULES:
    ALLOWED_VALUES[_r['key']] = _r.get('fix', '')
VALUE_RE = re.compile(r'^[a-zA-Z0-9/._-]+$')  # Fallback regex si pas dans whitelist


# ── Parsing ───────────────────────────────────────────────────────────────────

def _parse_sshd_config(text):
    """Parse le contenu de sshd_config en dict {directive: valeur}.

    Ignore les commentaires et les lignes vides.
    Les directives en double conservent la premiere occurrence (comportement sshd).
    """
    config = {}
    if not text:
        return config
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            if key not in config:
                config[key] = value
    return config


# ── Recuperation de la config et version SSH ──────────────────────────────────

def get_sshd_config(client, root_pass):
    """Recupere le contenu complet de /etc/ssh/sshd_config (+ fichiers Include).

    Retourne la config sous forme de texte brut.
    """
    cmd = "cat /etc/ssh/sshd_config 2>/dev/null"
    stdout, stderr, rc = execute_as_root(client, cmd, root_pass, logger=_log)
    if rc != 0:
        _log.warning("Impossible de lire sshd_config: rc=%d stderr=%s", rc, stderr)
        return ''

    config_text = stdout or ''

    # Tente de recuperer les fichiers Include (avec validation anti-traversal)
    _INCLUDE_PATH_RE = re.compile(r'^/etc/ssh/[a-zA-Z0-9_./*-]+$')
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith('include '):
            include_path = stripped.split(None, 1)[1].strip()
            if not _INCLUDE_PATH_RE.match(include_path):
                _log.warning("Include path rejected (path traversal?): %s", include_path)
                continue
            inc_cmd = f"cat {include_path} 2>/dev/null"
            inc_out, _, inc_rc = execute_as_root(client, inc_cmd, root_pass, logger=_log)
            if inc_rc == 0 and inc_out:
                config_text += '\n# --- Include: ' + include_path + ' ---\n'
                config_text += inc_out

    return config_text


def get_ssh_version(client, root_pass):
    """Recupere la version d'OpenSSH installee sur le serveur."""
    stdout, _, rc = execute_as_root(client, "sshd -V 2>&1 || ssh -V 2>&1", root_pass, logger=_log)
    if rc == 0 and stdout:
        # Extraction de la ligne contenant OpenSSH
        for line in stdout.splitlines():
            if 'OpenSSH' in line:
                return line.strip()
    return stdout.strip() if stdout else 'unknown'


# ── Audit ─────────────────────────────────────────────────────────────────────

def audit_sshd_config(config_text, policies=None):
    """Analyse la config sshd_config contre les regles de securite.

    Args:
        config_text: Contenu brut de sshd_config.
        policies: dict {directive: 'audit'|'ignore'} pour exclure des regles.

    Returns:
        dict avec score, grade, findings (list), counts (dict par severite).
    """
    parsed = _parse_sshd_config(config_text)
    policies = policies or {}
    findings = []
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    total_penalty = 0

    for rule in AUDIT_RULES:
        key = rule['key']
        severity = rule['severity']

        # Respect des policies d'exclusion
        if policies.get(key) == 'ignore':
            continue

        value = parsed.get(key)
        triggered = False
        check = rule['check']

        if check == 'bad_values':
            if value and value.lower() in [b.lower() for b in rule['bad']]:
                triggered = True
        elif check == 'int_gt':
            if value is not None:
                try:
                    if int(value) > rule['threshold']:
                        triggered = True
                except ValueError:
                    pass
        elif check == 'int_eq':
            if value is not None:
                try:
                    if int(value) == rule['threshold']:
                        triggered = True
                except ValueError:
                    pass
            else:
                # Directive absente et threshold == 0 : considere comme 0
                if rule['threshold'] == 0:
                    triggered = True
        elif check == 'missing':
            if value is None:
                triggered = True

        if triggered:
            counts[severity] += 1
            total_penalty += SEVERITY_POINTS[severity]
            findings.append({
                'key': key,
                'current_value': value or '(absent)',
                'severity': severity,
                'msg_key': rule['msg_key'],
                'fix': rule['fix'],
            })

    score = max(0, 100 - total_penalty)
    grade = _calculate_grade(score)

    return {
        'score': score,
        'grade': grade,
        'findings': findings,
        'counts': counts,
    }


def _calculate_grade(score):
    """Convertit un score numerique (0-100) en note lettre."""
    if score >= 90:
        return 'A'
    if score >= 75:
        return 'B'
    if score >= 60:
        return 'C'
    if score >= 40:
        return 'D'
    return 'F'


# ── Validation ────────────────────────────────────────────────────────────────

def _validate_directive(key):
    """Verifie que la directive est dans la whitelist autorisee."""
    if key not in ALLOWED_DIRECTIVES:
        return False, f"Directive '{key}' non autorisee."
    return True, None


def _validate_value(value, directive=None):
    """Verifie que la valeur est autorisee (whitelist par directive, puis regex fallback)."""
    if not value:
        return False, "Valeur vide."
    # Verification par whitelist de valeurs connues
    if directive and directive in ALLOWED_VALUES:
        if value != ALLOWED_VALUES[directive]:
            return False, f"Valeur '{value}' non autorisee pour {directive}. Attendu: {ALLOWED_VALUES[directive]}"
        return True, None
    if not VALUE_RE.match(value):
        return False, f"Valeur '{value}' contient des caracteres non autorises."
    return True, None


# ── Backup et correction ─────────────────────────────────────────────────────

def backup_sshd_config(client, root_pass):
    """Cree un backup date de /etc/ssh/sshd_config.

    Retourne le chemin du fichier backup.
    """
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"/etc/ssh/sshd_config.bak.{timestamp}"
    cmd = f"cp /etc/ssh/sshd_config {backup_path}"
    _, stderr, rc = execute_as_root(client, cmd, root_pass, logger=_log)
    if rc != 0:
        _log.error("Echec backup sshd_config: %s", stderr)
        raise RuntimeError(f"Echec du backup: {stderr}")
    _log.info("Backup sshd_config cree: %s", backup_path)
    return backup_path


def apply_fix(client, root_pass, key, value):
    """Applique un correctif sur une directive sshd_config.

    Etapes :
        1. Valide la directive et la valeur
        2. Cree un backup
        3. Modifie la directive (sed ou ajout)
        4. Valide la config avec sshd -t
        5. Si valide : systemctl reload sshd
        6. Si invalide : restaure le backup

    Args:
        client: Client Paramiko connecte.
        root_pass: Mot de passe root.
        key: Directive sshd_config a modifier.
        value: Nouvelle valeur.

    Returns:
        (success: bool, message: str)
    """
    # Validation
    ok, err = _validate_directive(key)
    if not ok:
        return False, err
    ok, err = _validate_value(value, directive=key)
    if not ok:
        return False, err

    # Backup
    try:
        backup_path = backup_sshd_config(client, root_pass)
    except RuntimeError as e:
        return False, str(e)

    # Modification : commenter l'ancienne directive + ajouter la nouvelle en fin de fichier
    # Utilise grep + printf pour eviter toute injection sed
    import base64
    new_line = f"{key} {value}"
    b64_line = base64.b64encode(new_line.encode()).decode()
    fix_cmd = (
        f"grep -qiE '^\\s*#?\\s*{key}\\b' /etc/ssh/sshd_config && "
        f"sed -i '/^\\s*#*\\s*{key}\\b/s/^/# /' /etc/ssh/sshd_config; "
        f"printf '%s\\n' \"$(echo {b64_line} | base64 -d)\" >> /etc/ssh/sshd_config"
    )
    _, stderr, rc = execute_as_root(client, fix_cmd, root_pass, logger=_log)
    if rc != 0:
        _log.error("Echec modification sshd_config pour %s: %s", key, stderr)
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Echec de la modification: {stderr}"

    # Validation de la config
    _, stderr_t, rc_t = execute_as_root(client, "sshd -t", root_pass, logger=_log)
    if rc_t != 0:
        _log.warning("sshd -t echoue apres modification de %s: %s — restauration du backup", key, stderr_t)
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Configuration invalide apres modification: {stderr_t}"

    # Reload sshd (plus sur que restart)
    _, stderr_r, rc_r = execute_as_root(client, "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null", root_pass, logger=_log)
    if rc_r != 0:
        _log.warning("Reload sshd echoue: %s — la config est valide, reload manuel necessaire", stderr_r)
        return True, f"{key} modifie avec succes. Attention : reload echoue ({stderr_r}), reload manuel necessaire."

    _log.info("Directive %s corrigee a '%s' et sshd reloaded avec succes", key, value)
    return True, f"{key} modifie a '{value}' et sshd reloaded avec succes."


# ── Save / Toggle / Backups / Restore / Reload ──────────────────────────────

def save_sshd_config(client, root_pass, new_config):
    """Replace sshd_config with new content. Backup first, validate with sshd -t, rollback if invalid."""
    import base64
    # Backup
    try:
        backup_path = backup_sshd_config(client, root_pass)
    except RuntimeError as e:
        return False, str(e)

    # Write new config via base64 to avoid shell injection
    b64 = base64.b64encode(new_config.encode()).decode()
    cmd = f"echo {b64} | base64 -d > /etc/ssh/sshd_config"
    _, stderr, rc = execute_as_root(client, cmd, root_pass, logger=_log)
    if rc != 0:
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Write failed: {stderr}"

    # Validate
    _, stderr_t, rc_t = execute_as_root(client, "sshd -t", root_pass, logger=_log)
    if rc_t != 0:
        _log.warning("sshd -t failed after save — restoring backup")
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Config invalid (sshd -t): {stderr_t}"

    return True, f"Config saved and validated. Backup: {backup_path}"


def toggle_directive(client, root_pass, key, enable):
    """Comment out (disable) or uncomment (enable) a directive in sshd_config."""
    ok, err = _validate_directive(key)
    if not ok:
        return False, err

    try:
        backup_path = backup_sshd_config(client, root_pass)
    except RuntimeError as e:
        return False, str(e)

    if enable:
        # Uncomment: remove leading # from lines matching the key
        cmd = f"sed -i 's/^\\s*#\\s*\\({key}\\b\\)/\\1/' /etc/ssh/sshd_config"
    else:
        # Comment: add # before lines matching the key
        cmd = f"sed -i 's/^\\s*\\({key}\\b\\)/# \\1/' /etc/ssh/sshd_config"

    _, stderr, rc = execute_as_root(client, cmd, root_pass, logger=_log)
    if rc != 0:
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Toggle failed: {stderr}"

    # Validate
    _, stderr_t, rc_t = execute_as_root(client, "sshd -t", root_pass, logger=_log)
    if rc_t != 0:
        execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Config invalid after toggle: {stderr_t}"

    action = "enabled" if enable else "disabled"
    return True, f"{key} {action}"


def list_backups(client, root_pass):
    """List sshd_config backup files in /etc/ssh/."""
    out, _, rc = execute_as_root(
        client, "ls -la /etc/ssh/sshd_config.bak.* 2>/dev/null || echo 'NONE'",
        root_pass, logger=_log, timeout=5)
    if 'NONE' in out or rc != 0:
        return []

    backups = []
    _BACKUP_LINE_RE = re.compile(r'(\S+)\s+(\d+)\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$')
    for line in out.strip().splitlines():
        m = _BACKUP_LINE_RE.search(line)
        if m:
            filename = m.group(5).strip().split('/')[-1]
            size = int(m.group(3))
            date_str = m.group(4).strip()
            backups.append({'filename': filename, 'size': size, 'date': date_str})
    return sorted(backups, key=lambda b: b['filename'], reverse=True)


_BACKUP_NAME_RE = re.compile(r'^sshd_config\.bak\.\d{14}$')

def restore_backup(client, root_pass, backup_name):
    """Restore a backup file to sshd_config. Validate with sshd -t."""
    # Validate backup name (anti path-traversal)
    if not _BACKUP_NAME_RE.match(backup_name):
        return False, f"Invalid backup name: {backup_name}"

    backup_path = f"/etc/ssh/{backup_name}"

    # Check backup exists
    _, _, rc = execute_as_root(client, f"test -f {backup_path}", root_pass, logger=_log, timeout=5)
    if rc != 0:
        return False, f"Backup not found: {backup_name}"

    # Backup current config before restoring
    current_backup = None
    try:
        current_backup = backup_sshd_config(client, root_pass)
    except RuntimeError:
        pass  # Not critical

    # Restore
    _, stderr, rc = execute_as_root(client, f"cp {backup_path} /etc/ssh/sshd_config", root_pass, logger=_log)
    if rc != 0:
        return False, f"Restore failed: {stderr}"

    # Validate
    _, stderr_t, rc_t = execute_as_root(client, "sshd -t", root_pass, logger=_log)
    if rc_t != 0:
        # Restore the current backup we just made
        if current_backup:
            execute_as_root(client, f"cp {current_backup} /etc/ssh/sshd_config", root_pass, logger=_log)
        return False, f"Restored config invalid (sshd -t): {stderr_t}"

    return True, f"Backup {backup_name} restored"


def reload_sshd(client, root_pass):
    """Reload (or restart) the sshd service."""
    _, stderr, rc = execute_as_root(
        client,
        "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null",
        root_pass, logger=_log, timeout=15)
    if rc != 0:
        return False, f"Reload/restart sshd failed: {stderr}"
    return True, "sshd reloaded"
