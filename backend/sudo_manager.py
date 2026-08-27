"""
sudo_manager.py - Gestion des politiques sudo par utilisateur distant.

Pattern identique aux autres managers (fail2ban, iptables, services) : fonctions
pures qui prennent un client Paramiko + root_password et executent des commandes
via execute_as_root().

Sequence de deploiement type :
    1. Generer le contenu sudoers depuis le preset + parametres
    2. Ecrire dans un fichier temporaire /tmp/rootwarden-sudo-<rand>.tmp
    3. Valider avec visudo -cf <tmpfile>  (CRITIQUE : refuser si invalide)
    4. Si OK, sauvegarder l'ancien contenu (pour rollback), puis :
        mv tmpfile /etc/sudoers.d/rootwarden-<user> && chmod 0440 && chown root:root
    5. Si KO, supprimer le tmpfile et lever ValueError avec la sortie visudo

Securite :
- Username sanitize via _validate_username() : pattern [a-z_][a-z0-9_-]{0,31}
- Visudo -cf systematique : un fichier sudoers casse peut bricker l'admin du
  serveur (cf. OWASP A04 Insecure Design - chaine "deploy puis casse").
- Chemins cibles : exclusivement sous /etc/sudoers.d/rootwarden-*. Pas de
  modification de /etc/sudoers principal.
"""
import re
import secrets
import logging

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

# Username Linux : conforme a `useradd` standard - cf. NAME_REGEX de adduser(8)
_USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')

# Chemin cible figé pour eviter path traversal via username
SUDOERS_D_DIR = '/etc/sudoers.d'
FILE_PREFIX = 'rootwarden-'


def _validate_username(username: str) -> str:
    """Valide un nom d'utilisateur Linux. Bloque path traversal et chars sudoers."""
    username = (username or '').strip()
    if not _USERNAME_RE.match(username):
        raise ValueError(f"Nom d'utilisateur invalide : {username!r}")
    return username


def _target_path(username: str) -> str:
    """Retourne le chemin absolu du fichier sudoers.d pour cet utilisateur."""
    safe = _validate_username(username)
    return f"{SUDOERS_D_DIR}/{FILE_PREFIX}{safe}"


# ── Rendering : 5 presets metier + custom ───────────────────────────────────

def _runas_spec(runas: str) -> str:
    """Construit le Runas_Spec (defaut root). Valide la chaine."""
    runas = (runas or 'root').strip()
    if not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', runas):
        raise ValueError(f"Runas invalide : {runas!r}")
    return f"({runas})"


def _tag(nopasswd: bool) -> str:
    return 'NOPASSWD:' if nopasswd else ''


def render_preset_all_nopasswd(username: str, runas: str = 'root', nopasswd: bool = True) -> str:
    """Acces root complet sans mot de passe. RESERVE aux comptes de service."""
    return f"{username} ALL={_runas_spec(runas)} {_tag(nopasswd)}ALL"


def render_preset_restart_services(username: str, runas: str = 'root', nopasswd: bool = True) -> str:
    return (
        f"{username} ALL={_runas_spec(runas)} {_tag(nopasswd)}"
        "/bin/systemctl restart *, /bin/systemctl reload *, /bin/systemctl status *"
    )


def render_preset_apt_only(username: str, runas: str = 'root', nopasswd: bool = True) -> str:
    """AVERTISSEMENT : ce preset est EQUIVALENT ROOT. `apt install/upgrade`
    execute des scripts de mainteneur (.deb postinst) en root -> un utilisateur
    avec ce preset peut obtenir un shell root via un paquet construit. Il n'existe
    pas de moyen sur de "limiter a apt" sans donner root. A n'accorder qu'a des
    operateurs deja de confiance. (cf. CONTRIBUTING-SECURITY.md / presets sudo)"""
    return (
        f"{username} ALL={_runas_spec(runas)} {_tag(nopasswd)}"
        "/usr/bin/apt update, /usr/bin/apt upgrade -y, /usr/bin/apt install *, "
        "/usr/bin/apt-get update, /usr/bin/apt-get upgrade -y, /usr/bin/apt-get install *"
    )


def render_preset_read_logs(username: str, runas: str = 'root', nopasswd: bool = True) -> str:
    """Lecture seule des logs. Durci : retrait de `less` (permettait `!sh` =
    shell root) ; `cat`/`tail` ne peuvent pas spawn de shell ; `journalctl` force
    `--no-pager` (sinon ouvre un pager -> evasion shell). Le matching sudoers est
    par prefixe : `journalctl --no-pager *` impose le flag, et sudo execute la
    commande directement (pas via un shell) donc pas d'injection de metacaracteres."""
    return (
        f"{username} ALL={_runas_spec(runas)} {_tag(nopasswd)}"
        "/usr/bin/tail /var/log/*, /usr/bin/cat /var/log/*, "
        "/bin/journalctl --no-pager, /bin/journalctl --no-pager *"
    )


def render_preset_systemctl_specific(username: str, services: list[str],
                                      runas: str = 'root', nopasswd: bool = True) -> str:
    """Liste explicite de services systemctl autorises."""
    if not services:
        raise ValueError("systemctl_specific : liste de services vide")
    _SVC_RE = re.compile(r'^[A-Za-z0-9@._-]+$')
    safe_cmds = []
    for svc in services:
        svc = svc.strip()
        if not _SVC_RE.match(svc):
            raise ValueError(f"Nom de service invalide : {svc!r}")
        safe_cmds.extend([
            f"/bin/systemctl restart {svc}",
            f"/bin/systemctl reload {svc}",
            f"/bin/systemctl status {svc}",
        ])
    return f"{username} ALL={_runas_spec(runas)} {_tag(nopasswd)}{', '.join(safe_cmds)}"


def render_preset_custom(username: str, custom_rules: str) -> str:
    """Politique brute saisie par l'admin. Pas de templating, mais visudo -cf
    validera quand meme cote serveur. Le username est prefixe automatiquement
    si la chaine ne commence pas deja par lui."""
    if not custom_rules or not custom_rules.strip():
        raise ValueError("custom_rules vide")
    lines = []
    for line in custom_rules.strip().splitlines():
        line = line.rstrip()
        if not line or line.lstrip().startswith('#'):
            lines.append(line)
            continue
        # Prefixer le username si la ligne ne commence pas par lui ou %group
        first = line.split(None, 1)[0] if line.split() else ''
        if first not in (username, f'%{username}') and not first.startswith('Defaults'):
            line = f"{username} {line}"
        lines.append(line)
    return '\n'.join(lines)


PRESET_RENDERERS = {
    'all_nopasswd': render_preset_all_nopasswd,
    'restart_services': render_preset_restart_services,
    'apt_only': render_preset_apt_only,
    'read_logs': render_preset_read_logs,
    'systemctl_specific': render_preset_systemctl_specific,
}


def render_policy(policy: dict) -> str:
    """Genere le contenu sudoers complet a partir d'un dict policy.

    Format attendu :
        {
            'username': 'john',
            'preset': 'apt_only' | 'all_nopasswd' | ... | 'custom',
            'nopasswd': True,
            'runas': 'root',
            'custom_rules': '...'  (uniquement si preset='custom')
            'services': ['nginx', 'php8.2-fpm']  (uniquement si preset='systemctl_specific')
        }

    Retourne le contenu complet du fichier sudoers.d, header + 1 ligne(s).
    """
    username = _validate_username(policy['username'])
    # ══ E-144, SECONDE OCCURRENCE — celle que le plan ne nommait pas ══════
    #
    # Corriger la seule route aurait laisse ce repli ARME pour tout autre
    # appelant de `render_policy`. Ici comme la-bas : `apt_only` porte
    # « AVERTISSEMENT : ce preset est EQUIVALENT ROOT » dans sa propre
    # docstring (`:80`), et un prereglage de privileges ne se devine pas.
    preset = policy.get('preset')
    if not preset:
        raise ValueError(
            "preset requis : aucun prereglage sudo n'est applique par defaut")
    nopasswd = bool(policy.get('nopasswd', False))
    runas = policy.get('runas', 'root')

    header = (
        "# Genere par RootWarden - NE PAS EDITER MANUELLEMENT\n"
        "# Toute modification sera ecrasee au prochain deploy.\n"
        f"# user={username} preset={preset} nopasswd={nopasswd} runas={runas}\n"
    )

    if preset == 'custom':
        body = render_preset_custom(username, policy.get('custom_rules', ''))
    elif preset == 'systemctl_specific':
        body = render_preset_systemctl_specific(
            username, policy.get('services', []), runas, nopasswd)
    elif preset in PRESET_RENDERERS:
        body = PRESET_RENDERERS[preset](username, runas, nopasswd)
    else:
        raise ValueError(f"Preset sudo inconnu : {preset!r}")

    return header + body + '\n'


# ── Operations SSH : audit / deploy / rollback / remove ─────────────────────

def audit_policy(client, root_password: str, username: str) -> tuple[bool, str]:
    """Lit le fichier sudoers.d/rootwarden-<user> distant.
    Retourne (exists, content). Content est '' si exists=False."""
    path = _target_path(username)
    cmd = f"test -f {path} && cat {path} || echo __NOT_FOUND__"
    out, _, _ = execute_as_root(client, cmd, root_password, timeout=15)
    if '__NOT_FOUND__' in out:
        return False, ''
    return True, out.strip()


def _make_tmpfile(client, root_password: str) -> str:
    """Cree un fichier temporaire sur le remote avec un nom aleatoire."""
    rand = secrets.token_hex(8)
    tmpfile = f"/tmp/rootwarden-sudo-{rand}.tmp"
    execute_as_root(client, f"install -m 0600 -o root -g root /dev/null {tmpfile}",
                    root_password, timeout=10)
    return tmpfile


def _write_to_remote(client, root_password: str, content: str, target: str) -> None:
    """Ecrit content dans target via 'cat > target <<EOF'. Utilise un marker
    aleatoire pour eviter toute collision avec le contenu."""
    marker = f"RW_HEREDOC_{secrets.token_hex(6)}"
    cmd = f"cat > {target} <<'{marker}'\n{content}\n{marker}\n"
    execute_as_root(client, cmd, root_password, timeout=15)


def validate_sudoers(client, root_password: str, path: str) -> tuple[bool, str]:
    """Lance visudo -cf <path>. Retourne (ok, output)."""
    out, err, code = execute_as_root(
        client, f"visudo -cf {path} 2>&1 || echo __VISUDO_KO__",
        root_password, timeout=15)
    if '__VISUDO_KO__' in out or code != 0:
        return False, out
    return True, out.strip()


def deploy_policy(client, root_password: str, policy: dict) -> dict:
    """Deploye une politique sudoers sur le serveur distant.

    Retourne un dict :
        {
            'success': True/False,
            'target_path': '/etc/sudoers.d/rootwarden-<user>',
            'previous_content': '...' or None si fichier inexistant,
            'new_content': '...',
            'validation_output': '...',
        }

    Pour usage cote route : ce dict alimente la table policy_deployments
    afin de permettre un rollback ulterieur.
    """
    username = _validate_username(policy['username'])
    target = _target_path(username)
    new_content = render_policy(policy)

    # 1. Snapshot du contenu existant avant modification (pour rollback)
    existed, previous_content = audit_policy(client, root_password, username)

    # 2. Ecrire dans un tmpfile + visudo -cf
    tmpfile = _make_tmpfile(client, root_password)
    try:
        _write_to_remote(client, root_password, new_content, tmpfile)
        ok, validation_output = validate_sudoers(client, root_password, tmpfile)
        if not ok:
            return {
                'success': False,
                'target_path': target,
                'previous_content': previous_content if existed else None,
                'new_content': new_content,
                'validation_output': validation_output,
                'error': 'visudo -cf : politique invalide, deploy annule',
            }

        # 3. Move + chmod + chown atomique
        cmd = (
            f"mv {tmpfile} {target} && chown root:root {target} && chmod 0440 {target}"
        )
        execute_as_root(client, cmd, root_password, timeout=15)

        return {
            'success': True,
            'target_path': target,
            'previous_content': previous_content if existed else None,
            'new_content': new_content,
            'validation_output': validation_output,
        }
    finally:
        # Cleanup tmpfile en cas d'echec (sinon le mv l'a deja consomme)
        execute_as_root(client, f"rm -f {tmpfile}", root_password, timeout=5)


def remove_policy(client, root_password: str, username: str) -> dict:
    """Supprime le fichier sudoers.d/rootwarden-<user> distant.
    Idempotent : retourne success=True meme si le fichier n'existait pas."""
    username = _validate_username(username)
    target = _target_path(username)
    existed, previous_content = audit_policy(client, root_password, username)
    execute_as_root(client, f"rm -f {target}", root_password, timeout=10)
    return {
        'success': True,
        'target_path': target,
        'previous_content': previous_content if existed else None,
        'new_content': '',
    }


def rollback_policy(client, root_password: str, username: str,
                     previous_content: str) -> dict:
    """Restaure le contenu precedent (issu de policy_deployments.previous_file_content).
    Si previous_content est vide ou None, equivalent a remove_policy()."""
    username = _validate_username(username)
    target = _target_path(username)

    if not previous_content or not previous_content.strip():
        return remove_policy(client, root_password, username)

    # Meme sequence que deploy_policy mais avec previous_content
    tmpfile = _make_tmpfile(client, root_password)
    try:
        _write_to_remote(client, root_password, previous_content, tmpfile)
        ok, validation_output = validate_sudoers(client, root_password, tmpfile)
        if not ok:
            return {
                'success': False,
                'target_path': target,
                'validation_output': validation_output,
                'error': 'visudo -cf : contenu precedent invalide, rollback impossible',
            }
        cmd = (
            f"mv {tmpfile} {target} && chown root:root {target} && chmod 0440 {target}"
        )
        execute_as_root(client, cmd, root_password, timeout=15)
        return {
            'success': True,
            'target_path': target,
            'restored_content': previous_content,
            'validation_output': validation_output,
        }
    finally:
        execute_as_root(client, f"rm -f {tmpfile}", root_password, timeout=5)
