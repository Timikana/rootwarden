"""
sftp_manager.py - Gestion des politiques SFTP/SSH par utilisateur distant.

Genere des fichiers /etc/ssh/sshd_config.d/rootwarden-<user>.conf contenant un
bloc `Match User <user>` qui surcharge la conf sshd globale pour cet utilisateur.

Pattern identique a sudo_manager.py mais avec sshd -t (au lieu de visudo -cf)
comme validation et systemctl reload sshd au lieu d'un mv atomique.

Sequence de deploiement :
    1. Generer le bloc Match User depuis les parametres
    2. Ecrire dans /tmp/rootwarden-sftp-<rand>.tmp
    3. Tester avec sshd -t -f <tmpfile_global> apres avoir cree un sshd_config
       temporaire qui include le fichier (sshd -t ne valide pas un fichier seul,
       il faut le rendre lu via Include - ou plus simple : ecrire dans le repo
       sshd_config.d/ ET tester sshd -t global, en restaurant si KO)
    4. Si OK, systemctl reload sshd. Si reload KO, restaurer et alerter.
    5. Le rollback restaure l'ancien contenu et reload sshd.

Securite :
- Username sanitize via _validate_username() (regex Linux standard)
- Path traversal bloque par regex sur chroot_dir / working_dir
- sshd -t global avant reload : eviter de bricker SSH du serveur cible
- Chmod 0644 + chown root:root sur sshd_config.d/ (standard sshd)
"""
import re
import secrets
import logging

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

_USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
_PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]{1,510}$')

SSHD_CONFIG_D_DIR = '/etc/ssh/sshd_config.d'
FILE_PREFIX = 'rootwarden-'
FILE_SUFFIX = '.conf'


def _validate_username(username: str) -> str:
    username = (username or '').strip()
    if not _USERNAME_RE.match(username):
        raise ValueError(f"Nom d'utilisateur invalide : {username!r}")
    return username


def _validate_path(path: str, field: str = 'path') -> str:
    """Valide un chemin absolu Unix sans traversal."""
    path = (path or '').strip()
    if not _PATH_RE.match(path):
        raise ValueError(f"Chemin {field} invalide : {path!r} (doit etre absolu, sans traversal)")
    if '..' in path.split('/'):
        raise ValueError(f"Chemin {field} contient '..' : {path!r}")
    return path


def _target_path(username: str) -> str:
    safe = _validate_username(username)
    return f"{SSHD_CONFIG_D_DIR}/{FILE_PREFIX}{safe}{FILE_SUFFIX}"


# ── Rendering du bloc Match User ────────────────────────────────────────────

def render_policy(policy: dict) -> str:
    """Genere le contenu du bloc Match User pour cet utilisateur.

    Format attendu :
        {
            'username': 'sftpuser',
            'sftp_only': True,
            'chroot_dir': '/srv/sftp/sftpuser' (ou None),
            'working_dir': '/upload' (ou None - cd au login pour SFTP),
            'allow_password_auth': False,
            'allow_tcp_forwarding': False,
            'allow_agent_forwarding': False,
            'x11_forwarding': False,
        }

    Retourne le contenu complet du fichier sshd_config.d/.
    """
    username = _validate_username(policy['username'])
    sftp_only = bool(policy.get('sftp_only', False))
    chroot_dir = policy.get('chroot_dir')
    working_dir = policy.get('working_dir')
    allow_pw = bool(policy.get('allow_password_auth', True))
    allow_tcp = bool(policy.get('allow_tcp_forwarding', True))
    allow_agent = bool(policy.get('allow_agent_forwarding', True))
    x11 = bool(policy.get('x11_forwarding', False))

    lines = [
        "# Genere par RootWarden - NE PAS EDITER MANUELLEMENT",
        "# Toute modification sera ecrasee au prochain deploy.",
        f"# user={username} sftp_only={sftp_only}",
        f"Match User {username}",
        f"    PasswordAuthentication {'yes' if allow_pw else 'no'}",
        f"    AllowTcpForwarding {'yes' if allow_tcp else 'no'}",
        f"    AllowAgentForwarding {'yes' if allow_agent else 'no'}",
        f"    X11Forwarding {'yes' if x11 else 'no'}",
    ]

    if chroot_dir:
        chroot_dir = _validate_path(chroot_dir, 'chroot_dir')
        lines.append(f"    ChrootDirectory {chroot_dir}")

    if sftp_only:
        lines.extend([
            "    ForceCommand internal-sftp" + (f" -d {working_dir}" if working_dir else ""),
            "    PermitTunnel no",
            "    PermitTTY no",
        ])
    elif working_dir:
        working_dir = _validate_path(working_dir, 'working_dir')
        # Pour shell normal : injecter un cd <dir> via ForceCommand n'est pas
        # une bonne idee (casse les .profile/.bashrc). On documente l'intention
        # mais on n'applique pas - le admin doit setter HOME ou utiliser .profile.
        lines.append(f"    # working_dir={working_dir} (informatif - non applique automatiquement en shell mode)")

    return '\n'.join(lines) + '\n'


# ── Operations SSH : audit / deploy / rollback / remove ─────────────────────

def audit_policy(client, root_password: str, username: str) -> tuple[bool, str]:
    """Lit le fichier sshd_config.d/rootwarden-<user>.conf distant."""
    path = _target_path(username)
    cmd = f"test -f {path} && cat {path} || echo __NOT_FOUND__"
    out, _, _ = execute_as_root(client, cmd, root_password, timeout=15)
    if '__NOT_FOUND__' in out:
        return False, ''
    return True, out.strip()


def _make_tmpfile(client, root_password: str) -> str:
    rand = secrets.token_hex(8)
    tmpfile = f"/tmp/rootwarden-sftp-{rand}.tmp"
    execute_as_root(client, f"install -m 0644 -o root -g root /dev/null {tmpfile}",
                    root_password, timeout=10)
    return tmpfile


def _write_to_remote(client, root_password: str, content: str, target: str) -> None:
    marker = f"RW_HEREDOC_{secrets.token_hex(6)}"
    cmd = f"cat > {target} <<'{marker}'\n{content}\n{marker}\n"
    execute_as_root(client, cmd, root_password, timeout=15)


def validate_sshd_config(client, root_password: str) -> tuple[bool, str]:
    """Lance sshd -t pour valider la conf sshd globale (incluant tous les
    fichiers dans sshd_config.d/). Retourne (ok, output)."""
    out, err, code = execute_as_root(
        client, "sshd -t 2>&1 || echo __SSHD_KO__",
        root_password, timeout=15)
    if '__SSHD_KO__' in out or code != 0:
        return False, out
    return True, (out + err).strip() or 'OK'


def deploy_policy(client, root_password: str, policy: dict) -> dict:
    """Deploye une politique SFTP/SSH sur le serveur distant.

    Strategie defense en profondeur : on ecrit le fichier final, on teste sshd -t
    globalement, et SI KO on restaure l'ancien contenu (ou supprime) avant
    de leve l'erreur. Tres important : un sshd_config casse peut couper l'acces
    SSH au reboot.
    """
    username = _validate_username(policy['username'])
    target = _target_path(username)
    new_content = render_policy(policy)

    existed, previous_content = audit_policy(client, root_password, username)

    # 1. Ecrire dans tmpfile pour pouvoir restaurer si sshd -t echoue
    tmpfile = _make_tmpfile(client, root_password)
    backup_in_place = f"{target}.rwbak"

    try:
        _write_to_remote(client, root_password, new_content, tmpfile)

        # 2. Backup l'ancien fichier si existe, puis mv le tmpfile en place
        if existed:
            execute_as_root(client, f"cp -a {target} {backup_in_place}",
                            root_password, timeout=10)
        execute_as_root(
            client,
            f"mv {tmpfile} {target} && chown root:root {target} && chmod 0644 {target}",
            root_password, timeout=15
        )

        # 3. sshd -t global
        ok, validation_output = validate_sshd_config(client, root_password)
        if not ok:
            # Rollback : restaurer le backup ou supprimer si rien n'existait
            if existed:
                execute_as_root(client, f"mv {backup_in_place} {target}",
                                root_password, timeout=10)
            else:
                execute_as_root(client, f"rm -f {target}", root_password, timeout=10)
            return {
                'success': False,
                'target_path': target,
                'previous_content': previous_content if existed else None,
                'new_content': new_content,
                'validation_output': validation_output,
                'error': 'sshd -t : politique invalide, deploy annule et restaure',
            }

        # 4. Reload sshd. Si reload echoue, restaurer.
        out, _, code = execute_as_root(
            client, "systemctl reload ssh 2>&1 || systemctl reload sshd 2>&1",
            root_password, timeout=20)
        if code != 0:
            if existed:
                execute_as_root(client, f"mv {backup_in_place} {target}",
                                root_password, timeout=10)
            else:
                execute_as_root(client, f"rm -f {target}", root_password, timeout=10)
            return {
                'success': False,
                'target_path': target,
                'previous_content': previous_content if existed else None,
                'new_content': new_content,
                'validation_output': validation_output,
                'error': f"systemctl reload ssh echoue : {out}",
            }

        # 5. Tout est OK, supprimer le backup
        execute_as_root(client, f"rm -f {backup_in_place}",
                        root_password, timeout=5)

        return {
            'success': True,
            'target_path': target,
            'previous_content': previous_content if existed else None,
            'new_content': new_content,
            'validation_output': validation_output,
        }
    finally:
        execute_as_root(client, f"rm -f {tmpfile}", root_password, timeout=5)


def remove_policy(client, root_password: str, username: str) -> dict:
    """Supprime le bloc Match User et reload sshd. Idempotent."""
    username = _validate_username(username)
    target = _target_path(username)
    existed, previous_content = audit_policy(client, root_password, username)

    if not existed:
        return {
            'success': True,
            'target_path': target,
            'previous_content': None,
            'new_content': '',
        }

    backup_in_place = f"{target}.rwbak"
    execute_as_root(client, f"cp -a {target} {backup_in_place} && rm -f {target}",
                    root_password, timeout=10)

    ok, validation_output = validate_sshd_config(client, root_password)
    if not ok:
        execute_as_root(client, f"mv {backup_in_place} {target}",
                        root_password, timeout=10)
        return {
            'success': False,
            'target_path': target,
            'previous_content': previous_content,
            'new_content': '',
            'validation_output': validation_output,
            'error': 'sshd -t : suppression refusee, fichier restaure',
        }

    execute_as_root(client, "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null",
                    root_password, timeout=20)
    execute_as_root(client, f"rm -f {backup_in_place}", root_password, timeout=5)

    return {
        'success': True,
        'target_path': target,
        'previous_content': previous_content,
        'new_content': '',
        'validation_output': validation_output,
    }


def rollback_policy(client, root_password: str, username: str,
                     previous_content: str) -> dict:
    """Restaure le contenu precedent. Si previous_content est vide -> remove."""
    username = _validate_username(username)

    if not previous_content or not previous_content.strip():
        return remove_policy(client, root_password, username)

    # Construire un dict policy depuis le contenu serait fragile. On ecrit
    # directement le contenu brut, en s'assurant que sshd -t passe.
    target = _target_path(username)
    tmpfile = _make_tmpfile(client, root_password)
    backup_in_place = f"{target}.rwbak"

    try:
        _write_to_remote(client, root_password, previous_content, tmpfile)
        existed, _ = audit_policy(client, root_password, username)
        if existed:
            execute_as_root(client, f"cp -a {target} {backup_in_place}",
                            root_password, timeout=10)
        execute_as_root(
            client,
            f"mv {tmpfile} {target} && chown root:root {target} && chmod 0644 {target}",
            root_password, timeout=15
        )

        ok, validation_output = validate_sshd_config(client, root_password)
        if not ok:
            if existed:
                execute_as_root(client, f"mv {backup_in_place} {target}",
                                root_password, timeout=10)
            else:
                execute_as_root(client, f"rm -f {target}", root_password, timeout=10)
            return {
                'success': False,
                'target_path': target,
                'validation_output': validation_output,
                'error': 'sshd -t : contenu precedent invalide, rollback annule',
            }

        execute_as_root(client, "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null",
                        root_password, timeout=20)
        execute_as_root(client, f"rm -f {backup_in_place}", root_password, timeout=5)

        return {
            'success': True,
            'target_path': target,
            'restored_content': previous_content,
            'validation_output': validation_output,
        }
    finally:
        execute_as_root(client, f"rm -f {tmpfile}", root_password, timeout=5)
