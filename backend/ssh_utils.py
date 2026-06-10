#!/usr/bin/env python3
"""
ssh_utils.py - Utilitaires SSH et base de données pour le projet RootWarden.

Rôle :
    Centralise toutes les primitives SSH (connexion, élévation de privilèges,
    exécution de commandes) et les fonctions d'accès à la base de données MySQL
    utilisées par server.py, configure_servers.py et iptables_manager.py.

Fonctions principales :
    connect_ssh()              - Ouvre une connexion SSH Paramiko (authentification par mot de passe).
    ssh_session()              - Context manager : connexion SSH avec fermeture garantie.
    execute_as_root()          - Exécute une commande en root via sudo -S (fallback : su -c).
    execute_as_root_stream()   - Idem, en streaming (générateur de chunks pour réponses SSE/plain).
    load_data_from_db()        - Charge machines + utilisateurs depuis MySQL.
    load_selected_machines()   - Charge un sous-ensemble de machines par IDs.
    ensure_sudo_installed()    - Installe sudo via su- si absent (bootstrap Debian minimal).
    validate_machine_id()      - Valide et convertit un machine_id reçu en requête.
    clean_output()             - Supprime les séquences ANSI d'une sortie shell.

Élévation de privilèges :
    1. Méthode recommandée : ``sudo -S -p ''`` - le mot de passe est envoyé via stdin,
       jamais dans la commande. Retourne un exit code réel.
    2. Fallback : ``su root -c`` - utilisé sur les systèmes sans sudo (Debian minimal).
    3. Bootstrap uniquement : ``_switch_to_root_shell()`` - ouvre un shell interactif
       via ``su -`` pour installer sudo si absent.

Sécurité :
    - Le mot de passe root est transmis exclusivement via stdin (jamais en argument).
    - Les clés de chiffrement sont lues depuis Config - jamais codées en dur.
    - Le déchiffrement des secrets passe par encryption.Encryption.decrypt_password
      (AES-GCM AEAD). Le déchiffreur legacy "best-effort" a été retiré (audit A02).

Dépendances :
    paramiko, mysql-connector-python, PyCryptodome, cryptography,
    config.Config, encryption.Encryption.
"""

import contextlib
import logging
import re
import shlex
import time
import paramiko
import mysql.connector
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
import select
from config import Config
from encryption import Encryption

# ===================================================
# Clé de déchiffrement AES (32 caractères pour AES-256)
# ===================================================
SECRET_KEY = Config.SECRET_KEY

# ===================================================
# Configuration MySQL
# ===================================================
db_config = Config.DB_CONFIG

# db_config = {
#     'host': 'db',          # Ou "localhost" si vous n'êtes pas en Docker
#     'user': 'rootwarden_user',
#     'password': 'rootwarden_password',
#     'database': 'rootwarden'
# }

# ===================================================
# Fonctions utilitaires (nettoyage, padding, etc.)
# ===================================================
def validate_machine_id(value) -> int:
    """
    Valide et convertit un machine_id reçu depuis une requête JSON.

    Accepte entiers, chaînes numériques et tout type convertible en int.
    Protège contre les injections en refusant les valeurs négatives, nulles ou non numériques.

    Args:
        value: Valeur brute extraite du JSON (int, str, float…).

    Returns:
        int: machine_id validé, strictement positif.

    Raises:
        ValueError: Si la valeur n'est pas convertible en entier ou est <= 0.
    """
    try:
        mid = int(value)
        if mid <= 0:
            raise ValueError()
        return mid
    except (TypeError, ValueError):
        raise ValueError(f"machine_id invalide : {value!r}")


@contextlib.contextmanager
def ssh_session(ip: str, port: int, ssh_user: str, ssh_password: str, logger=None,
                force_password: bool = False, service_account: bool = False):
    """
    Context manager : ouvre une connexion SSH et garantit sa fermeture.

    Usage :
        with ssh_session(ip, port, user, pwd, logger) as client:
            out, err, code = execute_as_root(client, "apt update", root_password)
        # Forcer le password (ignorer la keypair) :
        with ssh_session(ip, port, user, pwd, logger, force_password=True) as client:
            ...
        # Utiliser le compte de service rootwarden (sudoers NOPASSWD) :
        with ssh_session(ip, port, user, pwd, logger, service_account=True) as client:
            ...
    """
    client = None
    try:
        client = connect_ssh(ip, ssh_user, ssh_password, port, logger=logger,
                             force_password=force_password, service_account=service_account)
        yield client
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def clean_output(output: str) -> str:
    """
    Supprime les séquences d'échappement ANSI d'une chaîne et fait un strip().
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', output).strip()

def unpad(data: bytes) -> bytes:
    """
    Retire le padding PKCS7 et valide son intégrité.

    Vérifie que le dernier octet indique une longueur de padding entre 1 et 16,
    et que tous les octets de padding ont la même valeur (validation stricte).

    Args:
        data (bytes): Données paddées (multiple de 16 octets).

    Returns:
        bytes: Données sans padding.

    Raises:
        ValueError: Si les données sont vides, si la longueur de padding est hors
                    plage [1-16], ou si le padding est corrompu.
    """
    if not data:
        raise ValueError("Données vides lors de la suppression du padding.")
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError(f"Longueur de padding invalide : {padding_length}")
    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            raise ValueError("Padding PKCS7 invalide détecté.")
    return data[:-padding_length]

# ===================================================
# (retire v1.23.1) Dechiffrement legacy "best-effort"
# ===================================================
# La fonction decrypt_password() a ete SUPPRIMEE (audit A02). Elle devinait
# un plaintext par heuristique (decode errors=ignore, troncature null byte,
# extraction d'octets imprimables, padding PKCS7 arbitraire) -> annulait la
# garantie integrite/anti-padding-oracle. Le dechiffrement passe desormais
# exclusivement par encryption.Encryption.decrypt_password (AES-GCM AEAD).

# ===================================================
# Gestion SSH (connexion, root)
# ===================================================
def _is_safe_ssh_host(host: str) -> bool:
    """Blocklist SSH host (A10-SSRF-N4). True si autorise.

    Refuse explicitement loopback (127/8), link-local (169.254/16), 0/8,
    IPv6 loopback/link-local. Les IPs privees RFC1918 et FQDN sont OK
    (cas legitime : LAN d'entreprise).
    """
    if not host:
        return False
    s = host.strip()
    if (s.startswith('127.') or s.startswith('169.254.') or s.startswith('0.')
            or s == '::1' or s.lower().startswith('fe80:')
            or s.lower() in ('localhost', '0:0:0:0:0:0:0:0', '::')):
        return False
    return True


def connect_ssh(host: str, username: str, password: str, port: int = 22,
                logger=None, force_password: bool = False,
                service_account: bool = False) -> paramiko.SSHClient:
    """
    Etablit une connexion SSH - essaie d'abord la keypair plateforme,
    puis tombe en fallback sur le password.

    Ordre d'authentification :
      0. Compte de service 'rootwarden' via keypair (si service_account=True)
      1. Keypair Ed25519 de la plateforme (si le fichier existe et force_password=False)
      2. Password (fallback, ou si force_password=True)

    Le champ `client._rootwarden_auth_method` est defini apres connexion
    pour savoir quel mode a ete utilise ('service_account', 'keypair' ou 'password').

    Args:
        host (str)         : Adresse IP ou nom d'hote.
        username (str)     : Utilisateur SSH.
        password (str)     : Mot de passe (fallback ou sudo).
        port (int)         : Port SSH (defaut 22).
        logger             : Logger Python optionnel.
        force_password (bool) : Si True, ignore la keypair et utilise le password.
        service_account (bool): Si True, tente le compte 'rootwarden' (NOPASSWD sudo).

    Returns:
        paramiko.SSHClient: Client SSH connecte.
    """
    _logger = logger or logging.getLogger(__name__)

    # Patch A10-SSRF-N4 (OWASP A10) : defense-in-depth - refuse les hosts
    # loopback/link-local meme si la validation cote PHP a ete contournee
    # (script interne, futur blueprint, etc). Les IPs privees RFC1918
    # restent autorisees pour les LAN d'entreprise.
    if not _is_safe_ssh_host(host):
        raise ValueError(f"Host SSH refuse (loopback/link-local) : {host}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _enable_keepalive(c):
        """Active le keepalive SSH (30s) pour eviter les timeouts sur les operations longues."""
        transport = c.get_transport()
        if transport:
            transport.set_keepalive(30)

    # Tentative 0 : compte de service 'rootwarden' via keypair (NOPASSWD sudo)
    if service_account and not force_password:
        try:
            from ssh_key_manager import get_platform_private_key
            pkey = get_platform_private_key()
            if pkey:
                client.connect(
                    hostname=host, port=port, username='rootwarden',
                    pkey=pkey,
                    look_for_keys=False, allow_agent=False,
                    timeout=10
                )
                client._rootwarden_auth_method = 'service_account'
                _enable_keepalive(client)
                _logger.info("SSH service account auth OK → %s:%d", host, port)
                return client
        except paramiko.AuthenticationException:
            _logger.debug("SSH service account auth echouee pour %s:%d - fallback", host, port)
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as e:
            _logger.debug("SSH service account non disponible (%s) - fallback", e)
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Tentative 1 : keypair plateforme
    if not force_password:
        try:
            from ssh_key_manager import get_platform_private_key
            pkey = get_platform_private_key()
            if pkey:
                client.connect(
                    hostname=host, port=port, username=username,
                    pkey=pkey,
                    look_for_keys=False, allow_agent=False
                )
                client._rootwarden_auth_method = 'keypair'
                _enable_keepalive(client)
                _logger.info("SSH keypair auth OK → %s:%d (user=%s)", host, port, username)
                return client
        except paramiko.AuthenticationException:
            _logger.debug("SSH keypair auth echouee pour %s:%d - fallback password", host, port)
            # Fermer et recreer le client pour le fallback
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as e:
            _logger.debug("SSH keypair non disponible (%s) - fallback password", e)
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Tentative 2 : password (fallback ou force)
    if not password:
        raise paramiko.AuthenticationException(
            f"Pas de password et keypair non deployee pour {host}:{port}"
        )

    try:
        client.connect(
            hostname=host, port=port, username=username,
            password=password,
            look_for_keys=False, allow_agent=False
        )
        client._rootwarden_auth_method = 'password'
        _enable_keepalive(client)
        _logger.info("SSH password auth OK → %s:%d (user=%s)", host, port, username)
        return client
    except paramiko.AuthenticationException:
        _logger.error("Erreur d'authentification à %s:%d pour %s", host, port, username)
        raise
    except Exception as e:
        _logger.error("Erreur connexion SSH à %s:%d : %s", host, port, e)
        raise

def _switch_to_root_shell(client: paramiko.SSHClient, root_password: str,
                           logger=None) -> paramiko.Channel:
    """
    Usage INTERNE uniquement (bootstrap sudo).
    Ouvre un shell interactif et passe en root via su -.
    Préférer execute_as_root() pour toutes les autres opérations.
    """
    _log = logger or logging.getLogger(__name__)
    try:
        channel = client.invoke_shell()
        time.sleep(1)
        if channel.recv_ready():
            channel.recv(1024)
        channel.send("su -\n")
        time.sleep(1)
        channel.send(f"{root_password}\n")
        time.sleep(2)
        channel.send("exec bash --norc --noprofile\n")
        time.sleep(1)
        output = ""
        deadline = time.time() + 5
        while time.time() < deadline:
            if channel.recv_ready():
                output += channel.recv(1024).decode('utf-8', errors='ignore')
                if '#' in output:
                    break
            time.sleep(0.3)
        if '#' not in output:
            raise Exception("Échec su - : prompt root non détecté.")
        _log.info("Shell root (bootstrap) ouvert.")
        return channel
    except Exception as e:
        _log.error("_switch_to_root_shell : %s", e)
        raise


# Gardé pour compatibilité avec du code externe éventuel
switch_to_root = _switch_to_root_shell


def _su_exec(client: paramiko.SSHClient, command: str, root_password: str,
             logger=None, timeout: int = 120):
    """
    Execute une commande en root via ``su`` (fallback si sudo absent).

    Strategie **temp script** pour contourner les 3 bugs PTY :
      1. Ecrit la commande dans un script temporaire (en tant que user normal,
         pas de root, pas de PTY)
      2. Execute le script via ``su root -c 'sh /tmp/.rw_xxx.sh'`` (PTY pour le
         mot de passe su uniquement)
      3. Parse la sortie entre des markers pour extraire le vrai stdout et le
         vrai exit code - les markers ne sont QUE dans le script, jamais dans
         l'echo PTY de la ligne de commande

    Pourquoi ca marche :
      - Les pipes/redirections sont dans le script .sh, interpretes par ``sh``,
        pas par le PTY → les ecritures fonctionnent reellement
      - Les markers ``RW_BEGIN`` / ``RW_END_N`` n'apparaissent qu'une fois
        (output du echo dans le script), pas dans l'echo PTY (qui n'affiche
        que ``su root -c 'sh /tmp/.rw_xxx.sh'``)
      - Le vrai exit code est capture dans le script via ``$?``
    """
    _log = logger or logging.getLogger(__name__)
    import base64
    import uuid

    _MARKER_BEGIN = 'RW_BEGIN_d4e5f6'
    _MARKER_END   = 'RW_END_d4e5f6'
    tmp_name = f"/tmp/.rw_{uuid.uuid4().hex[:12]}.sh"

    try:
        # ── Etape 1 : ecrire le script temp (user normal, pas de PTY) ────────
        script = f"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\necho {_MARKER_BEGIN}\n{command}\n_rc=$?\necho {_MARKER_END}_$_rc\nexit $_rc\n"
        b64_script = base64.b64encode(script.encode()).decode()
        write_cmd = f"printf '%s' '{b64_script}' | base64 -d > {tmp_name} && chmod 700 {tmp_name}"

        w_stdin, w_stdout, w_stderr = client.exec_command(write_cmd, timeout=10)
        w_stdout.read()
        w_rc = w_stdout.channel.recv_exit_status()
        if w_rc != 0:
            w_err = w_stderr.read().decode('utf-8', errors='replace')
            _log.error("_su_exec: echec ecriture script temp: %s", w_err)
            return "", w_err, w_rc

        # ── Etape 2 : executer le script en root via su (PTY pour le mdp) ────
        su_cmd = f"su root -c {shlex.quote('sh ' + tmp_name)}"
        stdin, stdout, stderr = client.exec_command(su_cmd, get_pty=True, timeout=timeout)

        # Attendre le prompt de mot de passe (max 5 s)
        prompt_buf = ""
        deadline_prompt = time.time() + 5
        while time.time() < deadline_prompt:
            r, _, _ = select.select([stdout.channel], [], [], 0.3)
            if r:
                chunk = stdout.channel.recv(256).decode('utf-8', errors='replace')
                prompt_buf += chunk
                if any(k in prompt_buf.lower() for k in ('password', 'mot de passe', 'assword:')):
                    break
            elif prompt_buf:
                break

        stdin.write(root_password + '\n')
        stdin.flush()

        # Lire la sortie jusqu'a la fin
        raw = ""
        last_data = time.time()
        deadline_cmd = time.time() + timeout
        while time.time() < deadline_cmd:
            r, _, _ = select.select([stdout.channel], [], [], 0.5)
            if r:
                chunk = stdout.channel.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    break
                raw += chunk
                last_data = time.time()
            elif stdout.channel.exit_status_ready():
                while stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096).decode('utf-8', errors='replace')
                    if chunk:
                        raw += chunk
                break
            elif raw and (time.time() - last_data) >= 3.0:
                break

        stdout.channel.recv_exit_status()

        # ── Etape 3 : parser la sortie ───────────────────────────────────────
        # Nettoyer \r, null bytes, sequences ANSI
        raw = raw.replace('\r\n', '\n').replace('\r', '').replace('\x00', '')
        ansi_re = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        raw = ansi_re.sub('', raw)

        real_code = 0
        out = ""

        # Chercher les markers - ils n'apparaissent qu'une fois (dans le script)
        lines = raw.split('\n')
        begin_idx = None
        end_idx = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == _MARKER_BEGIN and begin_idx is None:
                begin_idx = i
            elif _MARKER_END in stripped and begin_idx is not None:
                end_idx = i
                break

        if begin_idx is not None and end_idx is not None:
            out = '\n'.join(lines[begin_idx + 1:end_idx])
            # Extraire le vrai exit code
            end_content = lines[end_idx].strip()
            m = re.search(r'_(\d+)$', end_content)
            if m:
                real_code = int(m.group(1))
        else:
            # Fallback : sortie brute (ne devrait pas arriver)
            out = raw
            _log.warning("_su_exec: markers non trouves pour cmd='%s...'", command[:60])

        _log.info("_su_exec code=%d cmd='%s...'", real_code, command[:60])
        return clean_output(out), "", real_code

    except Exception as e:
        _log.error("_su_exec '%s': %s", command[:60], e)
        raise

    finally:
        # ── Etape 4 : nettoyage du script temp (best effort) ────────────────
        try:
            client.exec_command(f"rm -f {tmp_name}", timeout=5)
        except Exception:
            pass


# Erreurs stderr qui indiquent que sudo n'est pas utilisable sur ce serveur
_SUDO_UNAVAILABLE = (
    'sudo: command not found',
    'sudo: not found',
    'sudo : commande introuvable',
    'sudo : introuvable',
    'not in the sudoers',
    'pas dans le fichier sudoers',
    'is not allowed to run sudo',
    "n'est pas autorise",
    'sudo: unable to resolve',
    'aucun mot de passe',
    'no password was provided',
    'incorrect password attempt',
    'saisie de mot de passe incorrecte',
    'sorry, try again',
    'essayez de nouveau',
)


def execute_as_root(client: paramiko.SSHClient, command: str, root_password: str,
                    logger=None, timeout: int = 120):
    """
    Exécute une commande en root avec détection automatique de la méthode :

    0. Si connecté via le compte de service rootwarden (NOPASSWD sudo),
       exécute directement ``sudo sh -c`` sans envoyer de mot de passe.
    1. Essaie ``sudo -S`` (recommandé, exit code réel, pas de prompt à détecter).
    2. Si sudo est absent ou l'utilisateur n'est pas dans les sudoers,
       retombe sur ``su root -c`` - compatible avec Debian sans sudo configuré.

    Le mot de passe est toujours transmis via stdin, jamais dans la commande.

    Returns:
        (stdout: str, stderr: str, exit_code: int)
    """
    _log = logger or logging.getLogger(__name__)

    # Compte de service rootwarden : NOPASSWD sudo, pas besoin de password
    if getattr(client, '_rootwarden_auth_method', '') == 'service_account':
        nopasswd_cmd = f"sudo sh -c {shlex.quote(command)}"
        try:
            stdin, stdout, stderr = client.exec_command(nopasswd_cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            code = stdout.channel.recv_exit_status()
            if code != 0:
                _log.warning("execute_as_root (service_account) code=%d cmd='%s...' err=%s",
                             code, command[:60], err[:200])
            else:
                _log.info("execute_as_root OK (service_account): %s", command[:60])
            return clean_output(out), clean_output(err), code
        except Exception as e:
            _log.error("execute_as_root service_account '%s': %s", command[:60], e)
            raise

    sudo_cmd = f"sudo -S -p '' sh -c {shlex.quote(command)}"
    try:
        stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout)
        stdin.write(root_password + '\n')
        stdin.flush()
        stdin.channel.shutdown_write()

        out  = stdout.read().decode('utf-8', errors='replace')
        err  = stderr.read().decode('utf-8', errors='replace')
        code = stdout.channel.recv_exit_status()

        # sudo non disponible → fallback su -c
        if code != 0 and any(msg in err for msg in _SUDO_UNAVAILABLE):
            _log.info("sudo indisponible ('%s'), fallback su -c", err.strip()[:80])
            return _su_exec(client, command, root_password, logger=logger, timeout=timeout)

        if code != 0:
            _log.warning("execute_as_root code=%d cmd='%s...' err=%s",
                         code, command[:60], err[:200])
        else:
            _log.info("execute_as_root OK (code 0): %s", command[:60])

        return clean_output(out), clean_output(err), code

    except Exception as e:
        _log.error("execute_as_root '%s': %s", command[:60], e)
        raise


def execute_as_root_stream(client: paramiko.SSHClient, command: str,
                            root_password: str, logger=None):
    """
    Exécute une commande en root via ``sudo -S`` et renvoie la sortie en streaming.

    Si connecté via le compte de service rootwarden (NOPASSWD sudo),
    exécute directement ``sudo sh -c`` sans envoyer de mot de passe ni PTY.

    Utilise ``exec_command`` avec PTY → stdout et stderr fusionnés, sortie en temps réel.
    ``select.select`` évite tout blocage ; exit_status_ready() détecte la fin de commande.
    """
    _log = logger or logging.getLogger(__name__)
    _ansi_re = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    # Compte de service rootwarden : NOPASSWD sudo, pas de PTY ni password
    if getattr(client, '_rootwarden_auth_method', '') == 'service_account':
        nopasswd_cmd = f"sudo sh -c {shlex.quote(command)}"
        _log.info("execute_as_root_stream (service_account): %s", command[:60])
        try:
            stdin, stdout, stderr = client.exec_command(nopasswd_cmd)
            yield "Début de l'exécution...\n"
            while True:
                r, _, _ = select.select([stdout.channel], [], [], 0.5)
                if r:
                    chunk = stdout.channel.recv(4096)
                    if not chunk:
                        break
                    text = _ansi_re.sub('', chunk.decode('utf-8', errors='replace'))
                    if text.strip():
                        yield text
                elif stdout.channel.exit_status_ready():
                    while stdout.channel.recv_ready():
                        chunk = stdout.channel.recv(4096)
                        if chunk:
                            text = _ansi_re.sub('', chunk.decode('utf-8', errors='replace'))
                            if text.strip():
                                yield text
                    break
            code = stdout.channel.recv_exit_status()
            yield f"\nExécution terminée (code {code}).\n"
        except Exception as e:
            _log.error("execute_as_root_stream service_account '%s': %s", command[:60], e)
            yield f"ERROR: {e}\n"
        return

    # Detecte si sudo est utilisable : envoyer le mot de passe via sudo -S
    # et verifier si stderr contient un message d'erreur connu (sudoers, etc.)
    _sin, _sout, _serr = client.exec_command("sudo -S -p '' true", timeout=5)
    _sin.write(root_password + '\n')
    _sin.flush()
    try:
        _sin.channel.shutdown_write()
    except Exception:
        pass
    _sudo_out = _sout.read().decode('utf-8', errors='replace')
    _sudo_err = _serr.read().decode('utf-8', errors='replace')
    _sudo_rc = _sout.channel.recv_exit_status()
    can_sudo = _sudo_rc == 0 and not any(msg in _sudo_err for msg in _SUDO_UNAVAILABLE)

    if can_sudo:
        root_cmd = f"sudo -S -p '' sh -c {shlex.quote(command)}"
    else:
        # Fallback su : ecrire un script temp pour les memes raisons que _su_exec
        import base64 as _b64
        import uuid as _uuid
        _tmp = f"/tmp/.rw_stream_{_uuid.uuid4().hex[:8]}.sh"
        _script = f"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n{command}\n"
        _b64s = _b64.b64encode(_script.encode()).decode()
        _wcmd = f"printf '%s' '{_b64s}' | base64 -d > {_tmp} && chmod 700 {_tmp}"
        _ws, _wo, _we = client.exec_command(_wcmd, timeout=10)
        _wo.read()
        _wo.channel.recv_exit_status()
        root_cmd = f"su root -c {shlex.quote('sh ' + _tmp)}"
    _log.info("execute_as_root_stream: %s (mode=%s)", command[:60], 'sudo' if can_sudo else 'su')

    try:
        stdin, stdout, stderr = client.exec_command(root_cmd, get_pty=True)
        if not can_sudo:
            # su affiche "Mot de passe :" - attendre l'invite avant d'envoyer
            import time as _time
            _time.sleep(1)
        stdin.write(root_password + '\n')
        stdin.flush()

        yield "Début de l'exécution...\n"

        # Patch A09 : l'echo PTY du mot de passe (root_password + '\n') est la
        # PREMIERE ligne renvoyee. L'ancien `text.replace(root_password, '')`
        # echouait si l'echo etait scinde sur une frontiere recv(4096) -> fuite
        # partielle du mot de passe dans le flux. On bufferise desormais jusqu'au
        # premier '\n' et on jette tout ce qui precede (la ligne d'echo entiere),
        # quel que soit le decoupage en chunks.
        _skip_password = True
        _skip_buf = ''

        def _strip_pw_echo(text):
            """Retourne (texte_a_emettre, skip_encore_actif)."""
            nonlocal _skip_buf
            _skip_buf += text
            nl = _skip_buf.find('\n')
            if nl == -1:
                return '', True       # encore dans la ligne d'echo, ne rien emettre
            remainder = _skip_buf[nl + 1:]
            _skip_buf = ''
            return remainder, False   # ligne d'echo jetee, suite normale

        while True:
            r, _, _ = select.select([stdout.channel], [], [], 0.5)
            if r:
                chunk = stdout.channel.recv(4096)
                if not chunk:
                    break
                text = chunk.decode('utf-8', errors='replace')
                if _skip_password:
                    text, _skip_password = _strip_pw_echo(text)
                    if _skip_password:
                        continue
                text = _ansi_re.sub('', text)
                if text.strip():
                    yield text
            elif stdout.channel.exit_status_ready():
                while stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096)
                    if chunk:
                        text = chunk.decode('utf-8', errors='replace')
                        if _skip_password:
                            text, _skip_password = _strip_pw_echo(text)
                            if _skip_password:
                                continue
                        text = _ansi_re.sub('', text)
                        if text.strip():
                            yield text
                break

        code = stdout.channel.recv_exit_status()
        yield f"\nExécution terminée (code {code}).\n"

        # Nettoyage du script temp (mode su)
        if not can_sudo and '_tmp' in dir():
            try:
                client.exec_command(f"rm -f {_tmp}", timeout=5)
            except Exception:
                pass

    except Exception as e:
        _log.error("execute_as_root_stream '%s': %s", command[:60], e)
        yield f"ERROR: {e}\n"


# ── Alias de compatibilité descendante ──────────────────────────────────────
# Ces noms sont encore utilisés dans iptables_manager.py et configure_servers.py.
# Ils seront supprimés dans une future version.

def execute_command_as_root(channel_or_client, command, logger=None, timeout=120,
                             root_password=None):
    """
    Alias de compatibilité.
    Si service account (SSHClient avec _rootwarden_auth_method='service_account'),
    utilise sudo directement sans password.
    Si ``root_password`` est fourni, utilise le nouveau execute_as_root().
    Sinon, tombe en mode dégradé (shell interactif legacy).
    """
    # Service account : utilise sudo NOPASSWD via exec_command
    if isinstance(channel_or_client, paramiko.SSHClient) and \
       getattr(channel_or_client, '_rootwarden_auth_method', '') == 'service_account':
        _log = logger or logging.getLogger(__name__)
        sudo_cmd = f"sudo bash -c {shlex.quote(command)}"
        stdin, stdout, stderr = channel_or_client.exec_command(sudo_cmd, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        code = stdout.channel.recv_exit_status()
        if code != 0:
            _log.warning("execute_command_as_root (SA) code=%d cmd='%s...' err=%s", code, command[:60], err[:200])
        return clean_output(out)

    if root_password is not None:
        out, _err, _code = execute_as_root(channel_or_client, command,
                                           root_password, logger=logger, timeout=timeout)
        return out
    # Mode legacy : channel interactif (à supprimer quand tous les call sites seront migrés)
    _log = logger or logging.getLogger(__name__)
    channel = channel_or_client
    _log.warning("execute_command_as_root en mode legacy (channel interactif) pour '%s'",
                 command[:60])
    channel.send(f"{command}\n")
    output = ""
    last_data = time.time()
    deadline  = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([channel], [], [], 0.5)
        if r:
            chunk = channel.recv(4096).decode('utf-8', errors='replace')
            if not chunk:
                break
            output += chunk
            last_data = time.time()
            c = clean_output(output)
            if c.endswith('#') or c.rstrip().endswith('$ '):
                break
        elif output and (time.time() - last_data) >= 3.0:
            break
    return clean_output(output)

def execute_command_as_root_exec(client, command: str, root_password: str):
    """
    Exécute une commande en root via ``sudo -S`` et renvoie la sortie ligne par ligne.

    Contrairement à ``execute_as_root``, cette fonction est un générateur (``yield``),
    adapté aux contextes où la sortie doit être traitée en streaming ligne à ligne
    (ex. : mise à jour de la config Zabbix dans update_zabbix_config_exec).

    Le mot de passe est toujours envoyé via stdin pour éviter toute fuite dans
    les listes de processus (``ps aux``) ou les journaux système.

    Args:
        client (paramiko.SSHClient): Connexion SSH ouverte.
        command (str)              : Commande shell à exécuter en root.
        root_password (str)        : Mot de passe root en clair.

    Yields:
        str: Lignes de sortie de la commande.
    """
    stdin, stdout, stderr = client.exec_command(f"sudo -S sh -c {shlex.quote(command)}", get_pty=True)
    # Passer le mot de passe via stdin
    stdin.write(root_password + '\n')
    stdin.flush()
    for line in iter(stdout.readline, ""):
        yield line

# ===================================================
# Lecture de la BDD (machines, users)
# ===================================================
def load_data_from_db(logger=None) -> tuple[list, list]:
    """
    Charge toutes les machines et tous les utilisateurs depuis la base de données.

    Effectue deux requêtes :
        1. ``SELECT … FROM machines`` - toutes les machines avec identifiants SSH.
        2. Jointure ``users LEFT JOIN user_machine_access`` - tous les utilisateurs
           avec leur liste de machine_ids autorisés (regroupés par user_id).

    Args:
        logger: Logger Python optionnel. Si None, utilise ``logging.getLogger()``.

    Returns:
        tuple[list[dict], list[dict]]:
            - machines : liste de dicts (id, name, ip, port, user, password, root_password).
            - users    : liste de dicts (name, active, sudo, ssh_key, allowed_servers[]).

    Raises:
        Exception: Tout échec de connexion ou de requête MySQL est propagé après log.
    """
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Table machines
        cursor.execute("SELECT id, name, ip, port, user, password, root_password, platform_key_deployed, service_account_deployed FROM machines")
        machines = cursor.fetchall()

        # Jointure users -> user_machine_access (avec preset sudo par machine v1.22.0+)
        cursor.execute("""
            SELECT
                u.id AS user_id,
                u.name AS user_name,
                u.active,
                u.sudo,
                u.ssh_key,
                uma.machine_id,
                uma.sudo_preset,
                uma.sudo_nopasswd,
                uma.sudo_runas,
                uma.sudo_custom_rules
            FROM users u
            LEFT JOIN user_machine_access uma ON u.id = uma.user_id
        """)
        user_machines = cursor.fetchall()

        cursor.close()
        db.close()

        # Regrouper par user_id - on stocke aussi le preset sudo par machine (desired state)
        users_dict = {}
        for record in user_machines:
            uid = record['user_id']
            if uid not in users_dict:
                users_dict[uid] = {
                    "name": record['user_name'],
                    "active": record['active'],
                    "sudo": record['sudo'],
                    "ssh_key": record['ssh_key'],
                    "allowed_servers": [],
                    "sudo_policies": {},  # v1.22.2 : machine_id -> {preset, nopasswd, runas, custom_rules}
                }
            mid = record.get('machine_id')
            if mid:
                users_dict[uid]['allowed_servers'].append(mid)
                users_dict[uid]['sudo_policies'][mid] = {
                    'preset': record.get('sudo_preset') or 'none',
                    'nopasswd': bool(record.get('sudo_nopasswd')),
                    'runas': record.get('sudo_runas') or 'root',
                    'custom_rules': record.get('sudo_custom_rules') or '',
                }

        users = list(users_dict.values())

        # Logs pour débogage
        if logger:
            logger.debug(f"Machines chargées : {machines}")
            logger.debug(f"Utilisateurs chargés : {users}")
        else:
            logging.debug(f"Machines chargées : {machines}")
            logging.debug(f"Utilisateurs chargés : {users}")

        return machines, users

    except Exception as e:
        if logger:
            logger.error(f"Erreur lors du chargement MySQL : {e}")
        else:
            logging.error(f"Erreur lors du chargement MySQL : {e}")
        raise
def ensure_sudo_installed(client: paramiko.SSHClient, root_password: str,
                           logger=None):
    """
    Vérifie la présence de sudo et l'installe si absent (bootstrap Debian minimal).

    Comme sudo peut ne pas être installé, cette fonction utilise obligatoirement
    ``_switch_to_root_shell()`` (su -) pour ouvrir un shell root interactif,
    puis exécute ``apt-get install -y sudo`` si dpkg indique que le paquet manque.

    Note : Cette fonction doit être appelée en premier, avant tout appel à
    ``execute_as_root()``, sur les machines Debian fraîchement installées.

    Args:
        client (paramiko.SSHClient): Connexion SSH ouverte.
        root_password (str)        : Mot de passe root en clair.
        logger                     : Logger Python optionnel.

    Raises:
        Exception: Si l'ouverture du shell root ou l'installation de sudo échoue.
    """
    _log = logger or logging.getLogger(__name__)
    try:
        _log.info("Vérification de 'sudo'.")
        channel = _switch_to_root_shell(client, root_password, logger=_log)
        try:
            out = execute_command_as_root(channel,
                "dpkg-query -W -f='${Status}' sudo 2>/dev/null || echo 'missing'",
                logger=_log)
            if "install ok installed" not in out:
                _log.info("'sudo' absent - installation en cours.")
                execute_command_as_root(channel,
                    "apt-get update && apt-get install -y sudo", logger=_log)
                _log.info("'sudo' installé.")
            else:
                _log.info("'sudo' déjà présent.")
        finally:
            try:
                channel.close()
            except Exception:
                pass
    except Exception as e:
        _log.error("ensure_sudo_installed : %s", e)
        raise
