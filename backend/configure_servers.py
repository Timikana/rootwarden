#!/usr/bin/env python3
"""
configure_servers.py - Déploiement de la configuration SSH en masse pour RootWarden.

Rôle :
    Ce module orchestre la configuration automatique d'un ensemble de serveurs Linux
    distants : création/suppression d'utilisateurs, déploiement des clés SSH,
    mise à jour du fichier .bashrc et gestion des droits sudo.
    Le déploiement est parallélisé via ThreadPoolExecutor.

Dépendances clés :
    - ssh_utils            : connexion SSH, exécution de commandes en root, chargement BDD
    - encryption.Encryption: déchiffrement des mots de passe stockés en base
    - config.Config        : paramètres de connexion à la base de données
    - mysql.connector      : lecture des exclusions d'utilisateurs (table user_exclusions)

Sécurité :
    Les mots de passe sont stockés chiffrés en base et déchiffrés à l'exécution.
    Le décorateur retry() gère les échecs transitoires de connexion SSH.
    Les noms d'utilisateurs lus depuis /etc/passwd sont filtrés (alphanum + -_.@)
    avant toute utilisation dans une commande shell.

Usage CLI :
    python configure_servers.py <machine_id> [<machine_id> ...] [--log PATH] [--workers N]
"""

import sys
import logging
import string
import secrets
import time
import argparse
import functools
import mysql.connector
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager
from config import Config
from encryption import Encryption

import re

from ssh_utils import (
    connect_ssh,
    switch_to_root,
    execute_command_as_root,
    clean_output,
    load_data_from_db,
    ensure_sudo_installed
)

# Patch A03 (command injection, defense en profondeur) : configure_servers.py
# etait le SEUL module a interpoler username brut dans des commandes shell root
# (useradd/chown/mkdir/sudoers...) sans la validation pourtant presente dans
# sudo_manager, sftp_manager et routes/ssh.py. Meme regex stricte ici.
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')


# Motifs de refus d'un nom de compte. CE SONT DES CODES, pas des phrases :
# l'ecran les affiche et doit pouvoir SEPARER les causes. « pas de bouton parce
# que le nom est invalide » et « pas de bouton parce que je n'ai pas la
# permission » sont deux causes pour un meme vide, et un texte libre ne se
# distingue pas par programme.
MOTIF_NOM_VIDE = 'vide'
MOTIF_NOM_TROP_LONG = 'trop_long'
MOTIF_NOM_COMPOSANT_DE_CHEMIN = 'composant_de_chemin'
MOTIF_NOM_CARACTERES_INTERDITS = 'caracteres_interdits'


def _motif_nom_invalide(username):
    """Rend le CODE du motif de refus, ou None si le nom est valide.

    UNE SEULE REGLE, DEUX FORMES. `_valid_username` en derive plutot que de
    porter sa propre copie : une regle recopiee finit par diverger de celle qui
    decide, et ce chantier en compte deja trois occurrences (E-195, E-196,
    E-197). Ici la question « valide ? » et la question « pourquoi pas ? » ont
    la meme source, par construction.

    L'ordre des tests porte le sens, il n'est pas arbitraire : un nom vide
    passerait `strip('.') == ''` et serait annonce « composant de chemin », ce
    qui serait faux. Le motif le plus PRECIS gagne.
    """
    nom = str(username or '')
    if not nom:
        return MOTIF_NOM_VIDE
    if len(nom) > 32:
        return MOTIF_NOM_TROP_LONG
    if nom.strip('.') == '':
        # `.`, `..`, `...` — E-197. Total pour la classe, la ou tester deux
        # valeurs a la main laisserait passer la troisieme.
        return MOTIF_NOM_COMPOSANT_DE_CHEMIN
    if not _USERNAME_RE.match(nom):
        return MOTIF_NOM_CARACTERES_INTERDITS
    return None


def _valid_username(username) -> bool:
    """True si username est un nom de compte Linux sur (alphanumerique + . _ -, 1-32).

    E-197. La classe de caracteres seule ne suffit pas : elle accepte `.` et
    `..`, qui ne sont pas des noms de compte mais des COMPOSANTS DE CHEMIN. Or
    ce nom est interpole dans des chemins executes en root — la cle SSH
    (`/home/<nom>/.ssh/authorized_keys`) et les deux fichiers sudoers. Mesure du
    2026-08-27 :

        '..'  ->  rm -f /.ssh/authorized_keys        (et /etc pour le legacy)
        '.'   ->  rm -f /home/.ssh/authorized_keys   (et /etc/sudoers.d)

    Le nom vient de `server_user_inventory`, donc de ce qui a ete lu dans le
    `/etc/passwd` de la machine — et ce scan ne valide pas ce qu'il insere.

    CE N'EST PAS UNE ELEVATION DE PRIVILEGE : seul le root de cette machine peut
    poser un tel nom, et la commande s'execute sur cette meme machine. Ce qui
    est reel est un `rm -f` root sur un chemin qui n'est PAS celui vise.

    POURQUOI PAS L'EXPRESSION STRICTE QUI EXISTE DEJA DEUX FOIS DANS LE DEPOT
    `sudo_manager.py:32` et `sftp_manager.py:34` portent `^[a-z_][a-z0-9_-]{0,31}$`,
    identiques a l'octet, et elles refusent bien `.` et `..`. Les reprendre ici
    etait la premiere idee — elle CASSE le cas normal. Mesure sur les 41 noms
    reels du parc : elle refuserait **`Debian-exim`**, **`Debian-snmp`** et
    **`Timikana`**. Les deux premiers sont des comptes systeme Debian standard,
    presents sur toute machine du parc.

    La raison est un DOMAINE, pas une severite : ces deux modules valident des
    noms que RootWarden GERE, ou la regle de `useradd` est la bonne. Ce fichier
    valide des noms DECOUVERTS dans le `/etc/passwd` d'une machine reelle, ou
    les majuscules existent. Trois implementations, mais DEUX notions — les
    fondre serait E-195 a nouveau.

    Le correctif est donc etroit : la classe de caracteres reste, et ce qui est
    refuse est ce qui n'est fait que de points.
    """
    return _motif_nom_invalide(username) is None

# ===================================================
# Classe CustomFormatter pour Gérer l'Absence du Champ 'machine'
# ===================================================
class CustomFormatter(logging.Formatter):
    """
    Formateur de log personnalisé qui garantit la présence du champ 'machine'.

    Si un enregistrement de log ne possède pas l'attribut 'machine' (par exemple
    les messages émis depuis des bibliothèques tierces), la valeur 'UNKNOWN' est
    injectée avant le formatage afin d'éviter une KeyError dans le format string.
    """

    def format(self, record):
        if not hasattr(record, 'machine'):
            record.machine = 'UNKNOWN'
        return super().format(record)

# ===================================================
# Classe AddMachineFilter pour Ajouter 'machine' par Défaut
# ===================================================
class AddMachineFilter(logging.Filter):
    """
    Filtre de log qui ajoute silencieusement l'attribut 'machine' si absent.

    Utilisé sur le logger racine pour s'assurer que tous les messages - y compris
    ceux générés par des bibliothèques non instrumentées - passent le formatage
    sans erreur.
    """

    def filter(self, record):
        if not hasattr(record, 'machine'):
            record.machine = 'UNKNOWN'
        return True

# ===================================================
# Classe LoggerAdapter pour Ajouter le Nom de la Machine
# ===================================================
class MachineLoggerAdapter(logging.LoggerAdapter):
    """
    Adaptateur de logger qui injecte le nom de la machine dans chaque entrée de log.

    Attributs attendus dans ``extra`` :
        machine (str): Nom de la machine SSH en cours de configuration.

    Usage :
        logger = MachineLoggerAdapter(logging.getLogger(__name__), {'machine': 'srv-01'})
        logger.info("Connexion établie")  # → "... - srv-01 - INFO - Connexion établie"
    """

    def process(self, msg, kwargs):
        return msg, {'extra': {'machine': self.extra['machine']}}

# ===================================================
# Fonction de Réessai pour les Opérations SSH
# ===================================================
def retry(ExceptionToCheck, tries=3, delay=2, backoff=2):
    """
    Décorateur de réessai exponentiel pour les opérations SSH fragiles.

    En cas d'exception de type ``ExceptionToCheck``, la fonction décorée est
    relancée jusqu'à ``tries`` fois, avec un délai qui double à chaque tentative
    (``delay * backoff^n``). Le logger est extrait de ``self.logger`` si l'objet
    décoré est une méthode d'instance possédant cet attribut.

    Args:
        ExceptionToCheck: Type d'exception à intercepter pour relancer (ex: Exception).
        tries   (int):  Nombre total de tentatives (défaut : 3).
        delay   (float): Délai initial entre deux tentatives en secondes (défaut : 2).
        backoff (float): Multiplicateur du délai à chaque nouvelle tentative (défaut : 2).

    Returns:
        Décorateur applicable à n'importe quelle fonction ou méthode.

    Example::

        @retry(Exception, tries=4, delay=2, backoff=2)
        def connect(self):
            return connect_ssh(...)
    """
    def deco_retry(f):
        @functools.wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            self = args[0]  # Supposant que le premier argument est 'self'
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    if hasattr(self, 'logger') and isinstance(self.logger, MachineLoggerAdapter):
                        self.logger.warning(f"Échec avec l'erreur {e}, nouvelle tentative dans {mdelay} secondes...")
                    else:
                        print(f"Échec avec l'erreur {e}, nouvelle tentative dans {mdelay} secondes...")
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry
    return deco_retry

# ===================================================
# Fonction pour Configurer le Logging avec Rotation et Filtre
# ===================================================
def setup_logging(log_file: str):
    """
    Configure le système de logging avec rotation de fichier et filtre 'machine'.

    Met en place un RotatingFileHandler (max 1 Mo, 5 sauvegardes) avec le formateur
    CustomFormatter et le filtre AddMachineFilter sur le logger racine.
    La propagation vers les gestionnaires parents est désactivée pour éviter
    les doublons de log.

    Args:
        log_file (str): Chemin du fichier de log (ex: /app/logs/deployment.log).
    """
    handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=5)
    formatter = CustomFormatter('%(asctime)s - %(machine)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # Patch A09-NEW-01 : applique le scrubber aussi sur les FileHandler
    # supplementaires (deployment.log, iptables.log, update_servers.log).
    try:
        from log_scrub import attach_scrub
        attach_scrub(handler)
    except Exception:
        pass
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    # Ajouter le filtre pour s'assurer que 'machine' est toujours présent
    logger.addFilter(AddMachineFilter())
    
    # Éviter la propagation des logs vers les gestionnaires parents
    logger.propagate = False

# ===================================================
# Gestion des Sudoers avec sudoers.d
# ===================================================
#
# Convention de nommage UNIFIEE (fix regression) : le fichier sudoers d'un
# utilisateur gere est /etc/sudoers.d/rootwarden-<user>, IDENTIQUE a celui ecrit
# par sudo_manager.deploy_policy (page /adm/server_user_policies.php). Avant, ce
# chemin (deploiement de cle SSH) ecrivait /etc/sudoers.d/<user> tandis que la
# page policies ecrivait /etc/sudoers.d/rootwarden-<user> : DEUX fichiers pour le
# meme user. Comme /etc/sudoers.d est lu en ordre lexical et que la DERNIERE regle
# qui matche gagne, 'rootwarden-<user>' (lu apres '<user>') l'emportait -> une
# regle sans NOPASSWD pouvait ecraser un deploiement NOPASSWD (et inversement),
# d'ou "j'ai mis NOPASSWD mais sudo redemande le mot de passe".
# On ecrit donc le meme fichier des deux cotes (un redeploiement ECRASE au lieu
# d'accumuler) et on purge l'ancien fichier a nom nu. Le compte de service
# (/etc/sudoers.d/rootwarden, gere par routes/ssh.py) n'est JAMAIS touche.
_SUDOERS_PREFIX = 'rootwarden-'
_RESERVED_SA_USER = Config.NOM_COMPTE_SERVICE  # son /etc/sudoers.d/<nom> est intouchable
# Le nom vient de `Config`, source unique partagee avec l'authentification.
# Le recopier ici ferait deux valeurs qui finiraient par diverger.


def _sudoers_target(username: str) -> str:
    """Chemin unifie du fichier sudoers.d d'un utilisateur gere."""
    return f"/etc/sudoers.d/{_SUDOERS_PREFIX}{username}"


def _absence_verifiee(channel, chemins, logger=None) -> bool:
    """Vrai si AUCUN des chemins n'existe plus sur la machine distante.

    E-192. `execute_command_as_root` rend la SORTIE, jamais le code : il le
    calcule sur son chemin `service_account` (`ssh_utils.py:831`) et le JETTE,
    et il le jette aussi en depaquetant `execute_as_root`. Un `rm -f` refuse est
    donc indiscernable d'un `rm -f` reussi pour tous ses appelants.

    On ne verifie donc pas la COMMANDE mais son EFFET — c'est la regle du
    chantier : « une reussite annoncee n'est pas une reussite verifiee ».

    LE MARQUEUR EST POSITIF ET FAIL-CLOSED, et il est assemble par
    CONCATENATION SHELL. Sur les machines en mode `su`/`sudo` interactif, le
    canal ECHOTE la commande envoyee (v1.37.11) : un marqueur ecrit en clair
    reviendrait dans la sortie sans que rien n'ait ete verifie. La ligne echotee
    porte `__RW_""ABSENT_OK__`, la sortie reelle porte `__RW_ABSENT_OK__` — et
    on le cherche comme LIGNE ENTIERE, jamais en sous-chaine.

    Tout ce qui n'est pas ce marqueur exact vaut « non verifie ».
    """
    tests = " && ".join(f"test ! -e {c}" for c in chemins)
    try:
        sortie = execute_command_as_root(
            channel, f'{tests} && echo "__RW_""ABSENT_OK__"', logger=logger) or ''
    except Exception as e:
        if logger:
            logger.error(f"_absence_verifiee : sonde echouee ({e})")
        return False
    return any(ligne.strip() == '__RW_ABSENT_OK__' for ligne in str(sortie).splitlines())


def _purge_legacy_sudoers(channel, username: str, logger=None) -> None:
    """Supprime l'ancien fichier a nom nu /etc/sudoers.d/<user> (naming pre-fix),
    sauf s'il s'agit du compte de service rootwarden (fichier reserve)."""
    if username == _RESERVED_SA_USER:
        return  # ne jamais toucher /etc/sudoers.d/rootwarden (compte de service)
    try:
        execute_command_as_root(channel, f"rm -f /etc/sudoers.d/{username}", logger=logger)
    except Exception as e:
        if logger:
            logger.warning(f"[{username}] purge legacy sudoers echouee (non bloquant) : {e}")
def add_to_sudoers(channel, username: str, logger=None, policy: dict = None):
    """
    Ajoute un utilisateur aux sudoers en creant un fichier dans /etc/sudoers.d/.

    v1.22.2 - Lecture du desired state user_machine_access.sudo_preset :
        Si policy={'preset':..., 'nopasswd':..., 'runas':..., 'custom_rules':...}
        fourni, on rend le contenu via sudo_manager.render_policy() puis on valide
        par visudo -cf avant mv atomique. Si preset='none', on supprime le fichier.
        Si policy=None ou preset absent, fallback historique : NOPASSWD: ALL.

    Le fichier deploye est /etc/sudoers.d/<username> avec mode 0440 root:root
    (standard sudoers - sinon visudo le refuse).
    """
    if not _valid_username(username):
        if logger:
            logger.error(f"add_to_sudoers : username invalide refuse : {username!r}")
        return
    # Cas preset='none' : ne rien deployer, et supprimer si existait
    if policy and policy.get('preset') == 'none':
        remove_from_sudoers(channel, username, logger=logger)
        return

    # Cas preset configure -> rendre via sudo_manager + visudo -cf
    if policy and policy.get('preset'):
        try:
            import sudo_manager
            policy_full = {
                'username': username,
                'preset': policy.get('preset', 'all_nopasswd'),
                'nopasswd': bool(policy.get('nopasswd', True)),
                'runas': policy.get('runas') or 'root',
                'custom_rules': policy.get('custom_rules') or '',
                'services': policy.get('services') or [],
            }
            content = sudo_manager.render_policy(policy_full)
        except (ValueError, ImportError) as e:
            if logger:
                logger.error(f"[{username}] Render sudo policy invalide ({e}), fallback NOPASSWD ALL")
            policy = None  # Force fallback ci-dessous

    # Fallback historique (preset absent ou render KO) : NOPASSWD ALL
    if not policy or not policy.get('preset'):
        content = f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n"

    try:
        sudoers_file = _sudoers_target(username)  # /etc/sudoers.d/rootwarden-<user> (unifie)
        import base64 as _b64
        import secrets as _secrets
        b64 = _b64.b64encode(content.encode('utf-8')).decode()
        tmp = f"/tmp/rootwarden-sudo-{_secrets.token_hex(6)}.tmp"
        # 1. ecrire dans tmp + chmod
        execute_command_as_root(
            channel,
            f"printf '%s' '{b64}' | base64 -d > {tmp} && chown root:root {tmp} && chmod 0440 {tmp}",
            logger=logger)
        # 2. visudo -cf : valider AVANT d'installer.
        #
        # PIEGE mode legacy (shell interactif PTY, machines bootstrap su/sudo) :
        # le terminal ECHOTE la commande envoyee, echo inclus dans la sortie lue.
        # L'ancien test `'__VISUDO_KO__' in out` matchait donc l'echo de la
        # commande elle-meme (qui contenait le marqueur en clair) et annulait
        # TOUS les deploiements sudoers en mode legacy, meme quand visudo
        # validait -> "visudo -cf refuse la politique" systematique, aucun
        # fichier NOPASSWD installe (bug prod). Parade :
        #   - marqueurs assembles par concatenation shell ("__VISUDO_""OK__") :
        #     la ligne echotee ne contient jamais le marqueur contigu, seul
        #     l'echo REELLEMENT execute le produit ;
        #   - verification d'un marqueur POSITIF emis seulement si visudo
        #     reussit. Fail-closed : sortie tronquee/illisible => on n'installe
        #     rien (un sudoers invalide peut casser sudo sur toute la machine).
        out = execute_command_as_root(
            channel,
            f'if visudo -cf {tmp} 2>&1; then echo "__VISUDO_""OK__"; '
            f'else echo "__VISUDO_""KO__"; fi',
            logger=logger)
        out_s = out if isinstance(out, str) else ''
        if '__VISUDO_KO__' in out_s or '__VISUDO_OK__' not in out_s:
            # Nettoyage du tmp dans les deux cas d'abandon (plus de rm dans la
            # commande distante : il contiendrait le chemin 2 fois et allonge
            # l'echo ; un rm dedie est idempotent).
            execute_command_as_root(channel, f"rm -f {tmp}", logger=logger)
            if logger:
                if '__VISUDO_KO__' in out_s:
                    logger.error(f"[{username}] visudo -cf refuse la politique - deploy annule : {out_s[-300:]}")
                else:
                    logger.error(f"[{username}] visudo -cf : resultat illisible (fail-closed) - deploy annule")
            return
        # 3. mv atomique
        execute_command_as_root(channel, f"mv {tmp} {sudoers_file}", logger=logger)
        # 4. purge de l'ancien fichier a nom nu (evite un doublon qui, lu apres
        #    rootwarden-<user> ? non : lu AVANT, mais il pourrait subsister avec une
        #    regle contradictoire). On garde une seule source de verite par user.
        _purge_legacy_sudoers(channel, username, logger=logger)
        if logger:
            preset_label = (policy or {}).get('preset', 'legacy_all_nopasswd')
            logger.info(f"[{username}] Sudoers deploye ({sudoers_file}, preset={preset_label})")
    except Exception as e:
        if logger:
            logger.error(f"[{username}] Erreur lors de l'ajout aux sudoers : {e}")

def remove_from_sudoers(channel, username: str, logger=None):
    """
    Retire un utilisateur des sudoers en supprimant son fichier dans /etc/sudoers.d/.

    La suppression est idempotente : si le fichier n'existe pas, l'opération
    se termine sans erreur grâce à l'option ``-f`` de rm.

    Args:
        channel  : Channel SSH root (retourné par switch_to_root).
        username : Nom de l'utilisateur Linux à retirer des sudoers.
        logger   : Logger optionnel pour tracer l'opération.
    """
    if not _valid_username(username):
        if logger:
            logger.error(f"remove_from_sudoers : username invalide refuse : {username!r}")
        return
    try:
        # Supprime le fichier unifie ET l'ancien fichier a nom nu (naming pre-fix),
        # pour ne laisser AUCUNE regle residuelle.
        #
        # Portee de la garde de `_purge_legacy_sudoers`, ecrite precisement
        # parce que la formulation precedente a induit TROIS lectures fausses le
        # 2026-08-27 : elle ne s'applique que si `username` — un utilisateur
        # GERE par le portail — vaut litteralement `rootwarden`. C'est un
        # garde-fou de COLLISION DE NOMS, pas une protection generale du fichier
        # du compte de service : cette fonction n'est jamais appelee avec autre
        # chose qu'un nom d'utilisateur du portail, donc elle ne croise pas
        # `/etc/sudoers.d/rootwarden` dans le cas ordinaire.
        #
        # Corollaire, et il compte : RIEN ici ne retire un fichier sudoers
        # ORPHELIN — sans compte porteur. Aucune routine du produit ne balaie ce
        # repertoire.
        execute_command_as_root(channel, f"rm -f {_sudoers_target(username)}", logger=logger)
        _purge_legacy_sudoers(channel, username, logger=logger)
        if logger:
            logger.info(f"[{username}] Retiré des sudoers (fichier unifie + legacy).")
    except Exception as e:
        if logger:
            logger.error(f"[{username}] Erreur lors du retrait des sudoers : {e}")

# ===================================================
# Fonctions Utilitaires Améliorées
# ===================================================
def user_exists(channel, username: str, logger=None) -> bool:
    """
    Vérifie si un utilisateur existe sur le serveur distant.

    Utilise la commande ``id -u <username>`` : si la sortie est un entier,
    l'utilisateur existe. Aucun droit root requis.

    Args:
        channel  : Channel SSH root (retourné par switch_to_root).
        username : Nom de l'utilisateur à vérifier.
        logger   : Logger optionnel.

    Returns:
        True si l'utilisateur existe, False sinon (ou en cas d'erreur).
    """
    if not _valid_username(username):
        if logger:
            logger.error(f"user_exists : username invalide refuse : {username!r}")
        return False
    try:
        output = execute_command_as_root(channel, f"id -u {username}", logger=logger)
        # PIEGE mode legacy (PTY) : la sortie contient l'echo de la commande et
        # le prompt -> `output.strip().isdigit()` etait TOUJOURS False et les
        # utilisateurs existants etaient revus comme "a creer" (useradd
        # echouait ensuite en silence). On cherche donc une LIGNE entierement
        # numerique (l'UID), robuste en mode exec (sortie propre) comme en
        # mode legacy (echo + prompt : jamais purement numeriques).
        out_s = output if isinstance(output, str) else ''
        exists = any(ln.strip().isdigit() for ln in out_s.splitlines())
        if logger:
            logger.info(f"[{username}] Existence de l'utilisateur vérifiée : {exists}")
        return exists
    except Exception as e:
        if logger:
            logger.error(f"Erreur lors de la vérification de l'existence de l'utilisateur {username} : {e}")
        return False

# def manage_ssh_keys(channel, user: dict, logger=None):
#     """
#     Ajoute ou supprime la clé SSH de l'utilisateur (champ `ssh_key`).
#     """
#     username = user['name']
#     ssh_key = user.get('ssh_key', '')
#     active = user.get('active', False)

#     authorized_keys_path = f"/home/{username}/.ssh/authorized_keys"
#     try:
#         if active and ssh_key:
#             if logger:
#                 logger.info(f"[{username}] Ajout de la clé SSH.")
#             execute_command_as_root(channel, f"mkdir -p /home/{username}/.ssh", logger=logger)
#             execute_command_as_root(channel, f"echo '{ssh_key}' > {authorized_keys_path}", logger=logger)
#             execute_command_as_root(channel, f"chmod 700 /home/{username}/.ssh && chmod 600 {authorized_keys_path}", logger=logger)
#             execute_command_as_root(channel, f"chown -R {username}:{username} /home/{username}", logger=logger)
#         elif not active:
#             if logger:
#                 logger.info(f"[{username}] Suppression de la clé SSH.")
#             execute_command_as_root(channel, f"rm -f {authorized_keys_path}", logger=logger)
#     except Exception as e:
#         if logger:
#             logger.error(f"[{username}] Erreur lors de la gestion de la clé SSH : {e}")

def manage_ssh_keys(channel, user: dict, logger=None):
    """
    Gere le deploiement de la cle SSH de l'utilisateur.
    Utilise base64 pour ecrire la cle sans interpolation shell (protection injection).
    """
    import base64 as _b64
    username = user.get('name')
    ssh_key = (user.get('ssh_key') or '').strip()
    active = user.get('active', False)

    if not username:
        if logger:
            logger.error("Nom d'utilisateur manquant dans la definition de l'utilisateur.")
        return
    if not _valid_username(username):
        if logger:
            logger.error(f"manage_ssh_keys : username invalide refuse : {username!r}")
        return

    authorized_keys_path = f"/home/{username}/.ssh/authorized_keys"

    try:
        if active and ssh_key:
            if logger:
                logger.info(f"[{username}] Deploiement de la cle SSH.")

            mkdir_command = (
                f"mkdir -p /home/{username}/.ssh && "
                f"chown {username}:{username} /home/{username}/.ssh && "
                f"chmod 700 /home/{username}/.ssh"
            )
            execute_command_as_root(channel, mkdir_command, logger=logger)

            # Ecriture via base64 - aucune interpolation shell possible
            b64_key = _b64.b64encode(ssh_key.encode()).decode()
            key_command = (
                f"printf '%s' '{b64_key}' | base64 -d > {authorized_keys_path} && "
                f"chown {username}:{username} {authorized_keys_path} && "
                f"chmod 600 {authorized_keys_path}"
            )
            execute_command_as_root(channel, key_command, logger=logger)
        else:
            if logger:
                logger.info(f"[{username}] Suppression de la cle SSH.")
            execute_command_as_root(channel, f"rm -f {authorized_keys_path}", logger=logger)
    except Exception as e:
        if logger:
            logger.error(f"[{username}] Erreur lors du deploiement de la cle SSH : {e}")

def deploy_user_config(channel, user: dict, logger=None):
    """
    Met a jour la configuration de l'utilisateur en une seule operation.

    - Deploie la cle SSH (ou la supprime si inactif).

    Note : le deploiement du .bashrc est gere exclusivement par le module
    dedie /bashrc/ (blueprint backend/routes/bashrc.py). Plus de deploiement
    implicite ici.
    """
    username = user.get('name')
    if not username:
        if logger:
            logger.error("Nom d'utilisateur manquant dans la définition de l'utilisateur.")
        return
    if not _valid_username(username):
        if logger:
            logger.error(f"deploy_user_config : username invalide refuse : {username!r}")
        return

    # --- Gestion de la cle SSH ---
    import base64 as _b64
    authorized_keys_path = f"/home/{username}/.ssh/authorized_keys"
    ssh_key = (user.get('ssh_key') or '').strip()
    if user.get('active') and ssh_key:
        if logger:
            logger.info(f"[{username}] Deploiement de la cle SSH.")
        mkdir_command = (
            f"mkdir -p /home/{username}/.ssh && "
            f"chown {username}:{username} /home/{username}/.ssh && "
            f"chmod 700 /home/{username}/.ssh"
        )
        execute_command_as_root(channel, mkdir_command, logger=logger)

        # Ecriture via base64 - aucune interpolation shell possible
        b64_key = _b64.b64encode(ssh_key.encode()).decode()
        key_command = (
            f"printf '%s' '{b64_key}' | base64 -d > {authorized_keys_path} && "
            f"chown {username}:{username} {authorized_keys_path} && "
            f"chmod 600 {authorized_keys_path}"
        )
        execute_command_as_root(channel, key_command, logger=logger)
    else:
        # ══ C'EST ICI QU'UN COMPTE INACTIF PERD SA CLE ══════════════════════
        #
        # E-195, et cette phrase est le correctif — il n'y a pas de code a
        # changer. Cette branche est la COMPENSATION qui rend correct le fait
        # que `configure_users` laisse les comptes inactifs hors de sa boucle
        # de revocation : ils ne gardent pas leur acces pour autant, ils le
        # perdent ici.
        #
        # Trois fonctions maintiennent ensemble une propriete que personne
        # n'avait ecrite, et qui n'etait donc vraie que par accident :
        #   `configure_users`      met le compte inactif hors de la revocation
        #   `deploy_user_config`   (ICI) lui retire sa cle
        #   `configure_user`       (branche inactive) lui retire son sudo
        # Le preflight, lui, l'annonce comme REVOQUE — et il dit vrai.
        #
        # Retirer ce `rm -f` « parce que la branche inactive ne fait rien
        # d'utile » rendrait un acces a chaque compte desactive du parc, en
        # silence, et le preflight continuerait d'annoncer une revocation qui
        # n'aurait plus lieu.
        if logger:
            logger.info(f"[{username}] Suppression de la cle SSH.")
        execute_command_as_root(channel, f"rm -f {authorized_keys_path}", logger=logger)
    
def generate_random_password(length: int = 16) -> str:
    """
    Génère un mot de passe aléatoire cryptographiquement sûr.

    Utilise ``secrets.choice`` sur un alphabet composé de lettres, chiffres et
    ponctuation pour garantir une entropie suffisante.

    Args:
        length (int): Longueur du mot de passe généré (défaut : 16).

    Returns:
        Chaîne aléatoire de ``length`` caractères.
    """
    # Exclure les caracteres qui cassent les commandes shell (', ", \, $, `, !)
    safe_punctuation = ''.join(c for c in string.punctuation if c not in r"""'"\\$`!""")
    characters = string.ascii_letters + string.digits + safe_punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def validate_machine(machine):
    """
    Valide qu'une définition de machine contient tous les champs obligatoires.

    Champs requis : id, name, ip, user, password, root_password.

    Args:
        machine (dict): Dictionnaire représentant une machine chargée depuis la BDD.

    Raises:
        ValueError: Si un champ obligatoire est absent du dictionnaire.
    """
    required_fields = ['id', 'name', 'ip', 'user', 'password', 'root_password']
    for field in required_fields:
        if field not in machine:
            raise ValueError(f"Le champ '{field}' est manquant dans la machine {machine.get('name', 'Unknown')}")

# ===================================================
# Classe de Configuration des Serveurs
# ===================================================
class ServerConfigurator:
    """
    Orchestre la configuration complète d'un serveur Linux distant via SSH.

    Pour chaque machine, la classe se charge de :
      - Se connecter via SSH avec retry automatique.
      - Mettre à jour le .bashrc root.
      - Créer/configurer les utilisateurs autorisés (configure_users).

    ⚠ Cette liste annonçait aussi « nettoyer les utilisateurs non autorisés
    (clean_up_users) ». C'est FAUX depuis que l'appel a été retiré : `configure`
    n'appelle que `configure_users`. La méthode existe encore, plus bas, et
    personne ne l'appelle — voir l'avertissement qui la précède.

    Le dire compte, parce qu'une docstring qui annonce une étape absente
    n'informe pas : elle INVITE à rétablir l'appel.

    Attributs :
        machine       (dict): Métadonnées de la machine (id, name, ip, port, user, password, root_password).
        all_users     (list): Liste de tous les utilisateurs déclarés en base.
        logger        (MachineLoggerAdapter): Logger contextuel avec le nom de la machine.
        name          (str): Nom de la machine.
        ip            (str): Adresse IP de la machine.
        port          (int): Port SSH (défaut : 22).
        user_ssh      (str): Compte utilisateur SSH pour la connexion initiale.
        encryption    (Encryption): Instance du moteur de déchiffrement.
        decrypted_pass(str): Mot de passe SSH déchiffré.
        decrypted_root(str): Mot de passe root déchiffré.
    """

    def __init__(self, machine, all_users, logger=None):
        self.machine = machine
        self.all_users = all_users
        self.logger = MachineLoggerAdapter(logger or logging.getLogger(__name__), {'machine': self.machine['name']})
        self.name = machine['name']
        self.ip = machine['ip']
        self.port = machine.get('port', 22)
        self.user_ssh = machine['user']
        self.encryption = Encryption()
        self.decrypted_pass = self.encryption.decrypt_password(machine.get('password', '')) or ''
        self.decrypted_root = self.encryption.decrypt_password(machine.get('root_password', '')) or ''

    @retry(Exception, tries=4, delay=2, backoff=2)
    def connect(self):
        """
        Établit la connexion SSH vers le serveur.

        Décorée avec @retry (4 tentatives, délai exponentiel de 2 s).

        Returns:
            Client Paramiko connecté.

        Raises:
            Exception: Si toutes les tentatives de connexion échouent.
        """
        return connect_ssh(self.ip, self.user_ssh, self.decrypted_pass, port=self.port, logger=self.logger)

    def configure(self):
        """
        Exécute la séquence complète de configuration du serveur.

        Ouvre une session SSH root via le context manager ``ssh_connection``,
        puis appelle dans l'ordre :
          1. ensure_sudo_installed   : installe sudo si absent
          2. configure_users         : crée/met à jour les comptes autorisés

        Note : le deploiement du .bashrc est gere exclusivement par le module
        dedie /bashrc/ (blueprint backend/routes/bashrc.py).
        """
        self.logger.info(f"=== Configuration de la machine : {self.name} ({self.ip}:{self.port}) ===")
        use_sa = self.machine.get('service_account_deployed', False)
        with ssh_connection(
            self.ip,
            self.user_ssh,
            self.decrypted_pass,
            port=self.port,
            root_password=self.decrypted_root,
            logger=self.logger,
            service_account=use_sa
        ) as (root_channel, ssh_client):
            # Si service account, sudo est deja disponible - pas besoin de ensure_sudo
            if not use_sa:
                ensure_sudo_installed(ssh_client, self.decrypted_root, logger=self.logger)
            # Le deploiement du .bashrc est gere par le module dedie /bashrc/.
            # Le nettoyage automatique des utilisateurs est DESACTIVE.
            # La suppression de comptes se fait uniquement depuis
            # Administration > Utilisateurs distants (action explicite).
            # Le deploiement ne fait que deployer/retirer les cles SSH.
            self.configure_users(root_channel)
        self.logger.info(f"=== Configuration terminée pour la machine : {self.name} ===")

    # ══ ⚠ CODE MORT, ET LE RETABLIR DETRUIRAIT 69 COMPTES (E-213) ══════════
    #
    # `clean_up_users` n'a AUCUN appelant dans tout le depot — mesure du
    # 2026-08-28. `configure()` n'appelle que `configure_users`. Elle ne
    # detruit donc rien aujourd'hui.
    #
    # CE QU'ELLE FERAIT SI ON RETABLISSAIT L'APPEL — ET LE CHIFFRE D'ABORD
    # ECRIT ICI ETAIT FAUX D'UN FACTEUR ~35, DANS LE SENS QUI ALARME.
    #
    # Il annoncait « 69 comptes que le portail affiche comme exclus recevraient
    # un `userdel -r` ». C'est le compte des lignes `excluded` de l'inventaire,
    # et **l'inventaire n'est pas l'entree de cette methode** : la liste des
    # candidats vient de la MACHINE, filtree par
    #
    #     awk -F: '$3 >= 1001 {print $1}' /etc/passwd        (ligne 842)
    #
    # Les UID < 1001 n'y apparaissent jamais. Mesure du 2026-08-28 :
    #
    #     server_user_inventory, status = 'excluded' . 69 lignes
    #       -> dont UID >= 1001 ........................ 2
    #       -> et ces 2 sont `nobody` (65534), deja dans _PROTECTED_USERS
    #       -> donc reellement supprimes AUJOURD'HUI ... 0
    #
    # CE QUI RESTE VRAI, ET C'EST L'ESSENTIEL : `user_exclusions` est VIDE (0
    # ligne). Les deux magasins ont diverge — la migration 030 les a copies UNE
    # fois, rien ne les synchronise depuis — et c'est le PREMIER que cette
    # methode lit. La seule protection restante serait donc la liste des six
    # noms systeme, sur un parc dont l'inventaire peut lui-meme etre faux
    # (E-187). **Le danger reste entier ; il ne repose simplement pas sur le
    # nombre qu'on croyait.**
    #
    # Son retrait est recommande et releve d'un arbitrage en cours. En
    # attendant, cet avertissement remplace l'invitation que portait la
    # docstring de la classe.
    def clean_up_users(self, channel):
        """
        Nettoie les utilisateurs non autorisés sur la machine, en tenant compte des exclusions.
        
        Le fonctionnement est le suivant :
        1. On garde les utilisateurs autorisés (liste `allowed_usernames`) - Ces utilisateurs sont déclarés en BDD
        2. On protège les utilisateurs dans la liste d'exclusion (`excluded_usernames`) - Ces utilisateurs ne seront pas supprimés
        3. On supprime les autres utilisateurs
        
        Note : Les utilisateurs qui sont dans la liste autorisée ne sont pas supprimés, même s'ils ne sont pas dans la liste d'exclusions.
        Si un compte doit être gardé sans être autorisé, il faut l'ajouter à la liste d'exclusion.
        """
        try:
            machine_id = self.machine['id']
            allowed_usernames = [
                user['name'] for user in self.all_users 
                if machine_id in user.get('allowed_servers', []) and user['active']
            ]
            self.logger.info(f"Utilisateurs autorisés sur la machine {machine_id} : {allowed_usernames}")

            # Récupérer les utilisateurs exclus pour cette machine
            excluded_usernames = []
            try:
                with mysql.connector.connect(**Config.DB_CONFIG) as conn:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT username FROM user_exclusions WHERE machine_id = %s", (machine_id,))
                    excluded_usernames = [row['username'] for row in cursor.fetchall()]
                    
                if excluded_usernames:
                    self.logger.info(f"Utilisateurs exclus pour la machine {machine_id} : {excluded_usernames}")
            except Exception as e:
                self.logger.error(f"Erreur lors de la récupération des exclusions : {e}")

            raw_passwd = execute_command_as_root(channel, "awk -F: '$3 >= 1001 {print $1}' /etc/passwd", logger=self.logger)
            existing_users = [line.strip() for line in raw_passwd.splitlines() if line.strip()]
            valid_existing_users = [user for user in existing_users if all(c.isalnum() or c in '-_.@' for c in user)]
            self.logger.info(f"Utilisateurs existants : {valid_existing_users}")

            # Utilisateurs systeme proteges - ne JAMAIS les supprimer
            _PROTECTED_USERS = frozenset({
                'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
                'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
                'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve',
                'messagebus', 'sshd', '_apt', 'rootwarden',
                self.user_ssh,  # user SSH de connexion
            })

            for username in valid_existing_users:
                # DÉCISION DE MAINTIEN OU SUPPRESSION
                # 1. Ne jamais supprimer un utilisateur systeme protege ou autorise
                if username.lower() in _PROTECTED_USERS or username in allowed_usernames:
                    self.logger.info(f"[{username}] Utilisateur autorisé, conservé.")
                    continue
                
                # 2. Ne pas supprimer les utilisateurs dans la liste d'exclusion
                if username in excluded_usernames:
                    self.logger.info(f"[{username}] Utilisateur dans la liste d'exclusion, conservé même si non autorisé.")
                    continue
                
                # 3. Supprimer tous les autres utilisateurs
                self.logger.info(f"[{username}] Non autorisé et non exclu. Suppression en cours...")
                try:
                    execute_command_as_root(channel, f"userdel -r {username}", logger=self.logger)
                    self.logger.info(f"[{username}] Supprimé avec succès.")
                    remove_from_sudoers(channel, username, logger=self.logger)
                except Exception as e:
                    self.logger.error(f"[{username}] Échec de la suppression : {e}")
                    try:
                        import base64 as _b64
                        random_password = generate_random_password()
                        _payload = _b64.b64encode(f"{username}:{random_password}".encode()).decode()
                        execute_command_as_root(channel, f"printf '%s' '{_payload}' | base64 -d | chpasswd", logger=self.logger)
                        self.logger.info(f"[{username}] Mot de passe réinitialisé.")
                        remove_from_sudoers(channel, username, logger=self.logger)
                    except Exception as inner_e:
                        self.logger.error(f"[{username}] Échec de la réinitialisation du mot de passe : {inner_e}")
        except Exception as e:
            self.logger.error(f"Erreur lors du nettoyage des utilisateurs : {e}")

    def configure_users(self, channel):
        """
        Configure les utilisateurs sur la machine courante.

        - Users autorises (dans allowed_servers) : deploie cles + config
        - Users managed dans l'inventaire mais qui ont perdu l'acces :
          retire la cle SSH et le sudo SANS supprimer le compte
        """
        mid = self.machine['id']

        # ══ CE N'EST PAS « QUI GARDE L'ACCES » — C'EST « QUI A ETE TRAITE » ══
        #
        # E-195. Cet ensemble s'appelait `authorized_names`, et le preflight
        # (`routes/ssh.py`) appelle `authorized` un ensemble calcule autrement :
        # `… JOIN user_machine_access … WHERE u.active = 1`. Deux noms
        # identiques pour DEUX NOTIONS DIFFERENTES, dans deux fichiers.
        #
        # Celui-ci ne filtre PAS sur `active`, et c'est correct : son seul role
        # est de dire qui `configure_user` a deja pris en charge, donc qui n'a
        # pas besoin de la boucle de revocation ci-dessous. Un compte INACTIF y
        # figure — et il perd quand meme sa cle, par un autre chemin : voir la
        # branche `else` de `deploy_user_config`, ou la compensation est ecrite.
        #
        # Les fusionner serait une ERREUR : le preflight cesserait d'annoncer
        # les revocations de comptes inactifs, qui ont pourtant bien lieu. Il
        # SOUS-annoncerait ce qui va etre detruit.
        comptes_traites = set()

        # 1. Deployer les users autorises
        for user in self.all_users:
            if mid in user.get('allowed_servers', []):
                comptes_traites.add(user.get('name'))
                self.configure_user(channel, user)

        # 2. Retirer les cles des users managed qui ont perdu l'acces
        try:
            import mysql.connector
            with mysql.connector.connect(**Config.DB_CONFIG) as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT username FROM server_user_inventory "
                    "WHERE machine_id = %s AND status = 'managed' AND managed_by = 'rootwarden'",
                    (mid,)
                )
                managed_users = {r['username'] for r in cursor.fetchall()}
        except Exception as e:
            self.logger.warning(f"Impossible de charger l'inventaire : {e}")
            managed_users = set()

        revoked = managed_users - comptes_traites
        for uname in revoked:
            # ══ UNE REVOCATION ANNONCEE N'EST PAS UNE REVOCATION FAITE ═══════
            #
            # E-192. Cette boucle journalisait « Acces revoque » AVANT d'agir,
            # puis jetait le resultat des deux gestes. Elle pouvait donc
            # affirmer qu'un acces etait ferme alors qu'il restait OUVERT.
            #
            # C'est l'inverse d'E-183, et c'est pire : E-183 detruisait une
            # donnee vraie, qui se repare en rescannant. Celle-ci produit une
            # FAUSSE ATTESTATION — personne ne rouvre un dossier de conformite
            # clos.
            #
            # Le nom vient de `server_user_inventory`, donc de ce qui a ete lu
            # dans le `/etc/passwd` de la machine, et il n'etait PAS valide
            # avant d'etre interpole dans un `rm -f` root. Ce n'est pas une
            # elevation de privilege — seul le root de cette machine peut poser
            # un tel nom, et la commande s'execute sur cette meme machine —
            # mais un nom porteur d'un espace ou d'un `;` fait echouer le
            # retrait EN SILENCE, ce qui est exactement le defaut ci-dessus.
            if not _valid_username(uname):
                self.logger.error(
                    f"[{uname!r}] REVOCATION REFUSEE : nom de compte invalide en "
                    f"inventaire. Aucun geste emis, l'acces reste en l'etat.")
                continue

            self.logger.info(f"[{uname}] Revocation DEMANDEE - retrait cle SSH et sudo (compte conserve).")
            try:
                ak_path = f"/home/{uname}/.ssh/authorized_keys"
                execute_command_as_root(channel, f"rm -f {ak_path}", logger=self.logger)
                remove_from_sudoers(channel, uname, logger=self.logger)

                # Le VERDICT se lit sur l'etat de la machine, pas sur le fait
                # d'avoir envoye les commandes.
                chemins = [ak_path, _sudoers_target(uname)]
                if uname != _RESERVED_SA_USER:
                    chemins.append(f"/etc/sudoers.d/{uname}")

                if _absence_verifiee(channel, chemins, logger=self.logger):
                    self.logger.info(
                        f"[{uname}] Acces REVOQUE et verifie : cle SSH et regles sudo absentes.")
                else:
                    self.logger.error(
                        f"[{uname}] REVOCATION NON VERIFIEE : au moins un de "
                        f"{chemins} subsiste ou n'a pas pu etre lu. "
                        f"L'ACCES DOIT ETRE CONSIDERE COMME ENCORE OUVERT.")
            except Exception as e:
                self.logger.error(f"[{uname}] Erreur retrait acces : {e}")

    def configure_user(self, channel, user: dict):
        """
        Configure un utilisateur sur le serveur distant.

        Comportement selon le statut ``active`` de l'utilisateur :
          - Actif   : crée le compte s'il n'existe pas, déploie la config complète
                      (clé SSH + .bashrc via deploy_user_config), gère les droits sudo.
          - Inactif : déploie la config (supprime la clé SSH), réinitialise le mot de
                      passe avec une valeur aléatoire et retire les droits sudo.

        Args:
            channel: Channel SSH root.
            user   (dict): Dictionnaire utilisateur avec au minimum les clés
                           'name', 'active', 'sudo', 'ssh_key', 'allowed_servers'.
        """
        username = user.get('name')
        if not username:
            self.logger.error("Nom d'utilisateur manquant dans la définition de l'utilisateur.")
            return
        if not _valid_username(username):
            self.logger.error(f"configure_user : username invalide refuse : {username!r}")
            return

        active = user.get('active', False)
        sudo = user.get('sudo', False)

        try:
            if active:
                if not user_exists(channel, username, logger=self.logger):
                    self.logger.info(f"[{username}] Création de l'utilisateur.")
                    execute_command_as_root(channel, f"useradd -m -s /bin/bash {username}", logger=self.logger)
                else:
                    self.logger.info(f"[{username}] L'utilisateur existe déjà.")
            else:
                self.logger.info(f"[{username}] Utilisateur inactif, configuration limitée.")

            # Deploiement de la cle SSH uniquement (le .bashrc est gere par /bashrc/)
            deploy_user_config(channel, user, logger=self.logger)

            # Gestion des droits sudo (v1.22.2 : desired state user_machine_access)
            #
            # Pattern desired/actual state :
            #   - desired = user_machine_access.sudo_preset (configure depuis admin)
            #   - actual  = /etc/sudoers.d/<user> sur le serveur cible (effet apres deploy)
            # Si l'user a un preset pour CETTE machine, on l'applique (visudo -cf).
            # Sinon fallback historique sur le bool users.sudo (compat retrocompat).
            if active:
                machine_id = self.machine.get('id')
                sudo_policies = user.get('sudo_policies') or {}
                policy_for_machine = sudo_policies.get(machine_id)
                # preset != 'none' -> deploy avec policy ; preset=='none' -> remove ;
                # policy=None -> fallback bool users.sudo
                if policy_for_machine and policy_for_machine.get('preset') and policy_for_machine.get('preset') != 'none':
                    add_to_sudoers(channel, username, logger=self.logger, policy=policy_for_machine)
                elif policy_for_machine and policy_for_machine.get('preset') == 'none':
                    remove_from_sudoers(channel, username, logger=self.logger)
                elif sudo:
                    # Legacy : bool users.sudo=1 -> NOPASSWD ALL (comportement v1.21.x)
                    add_to_sudoers(channel, username, logger=self.logger)
                else:
                    remove_from_sudoers(channel, username, logger=self.logger)
            else:
                # Pour les utilisateurs inactifs, on réinitialise le mot de passe et on retire le sudo
                import base64 as _b64
                random_password = generate_random_password()
                _payload = _b64.b64encode(f"{username}:{random_password}".encode()).decode()
                execute_command_as_root(channel, f"printf '%s' '{_payload}' | base64 -d | chpasswd", logger=self.logger)
                self.logger.info(f"[{username}] Mot de passe réinitialisé pour utilisateur inactif.")
                remove_from_sudoers(channel, username, logger=self.logger)
        except Exception as e:
            self.logger.error(f"[{username}] Erreur lors de la configuration : {e}")

    def run(self):
        """
        Point d'entrée appelé par ThreadPoolExecutor pour configurer la machine.

        Simple alias vers ``configure()``, compatible avec l'interface attendue
        par ``executor.submit(configurator.run)``.
        """
        self.configure()

# ===================================================
# Context Manager pour les Connexions SSH
# ===================================================
@contextmanager
def ssh_connection(ip, user, password, port=22, root_password=None, logger=None,
                   service_account=False):
    """
    Context manager pour une connexion SSH avec élévation de privilèges optionnelle.

    Ouvre une connexion Paramiko vers ``ip:port``, élève vers root si ``root_password``
    est fourni (via switch_to_root), puis ferme proprement la connexion à la sortie
    du bloc ``with``, même en cas d'exception.

    Si service_account=True, se connecte en tant que 'rootwarden' via keypair
    et utilise sudo NOPASSWD (pas besoin de root_password ni switch_to_root).

    Args:
        ip            (str): Adresse IP du serveur cible.
        user          (str): Compte utilisateur SSH pour la connexion initiale.
        password      (str): Mot de passe SSH en clair.
        port          (int): Port SSH (défaut : 22).
        root_password (str): Mot de passe root pour switch_to_root (optionnel).
        logger             : Logger pour tracer les erreurs de connexion.
        service_account (bool): Utiliser le compte rootwarden (NOPASSWD sudo).

    Yields:
        (channel_or_client, ssh_client) - Channel root ou client SSH selon le mode.

    Raises:
        Exception: Propage toute erreur de connexion après l'avoir loguée.
    """
    client = None
    try:
        client = connect_ssh(ip, user, password, port=port, logger=logger,
                             service_account=service_account)

        # Service account : pas besoin de switch_to_root, sudo NOPASSWD
        if getattr(client, '_rootwarden_auth_method', '') == 'service_account':
            yield client, client
        elif root_password:
            root_channel = switch_to_root(client, root_password, logger=logger)
            yield root_channel, client
        else:
            yield client, client
    except Exception as e:
        if logger:
            logger.error(f"Erreur de connexion SSH à {ip}:{port} - {e}")
        raise
    finally:
        if client:
            client.close()
            if logger:
                logger.info(f"Connexion SSH fermée pour {ip}:{port}")

# ===================================================
# Fonction Principale avec Concurrence et Argument Parsing
# ===================================================
def parse_arguments():
    """
    Analyse les arguments de la ligne de commande.

    Arguments positionnels :
        machines (str+): Identifiants (ids) des machines à configurer.

    Arguments optionnels :
        --log     (str): Chemin du fichier de log (défaut : /app/logs/deployment.log).
        --workers (int): Nombre de threads parallèles (défaut : 5).

    Returns:
        argparse.Namespace avec les attributs machines, log, workers.
    """
    parser = argparse.ArgumentParser(description="Script de configuration des serveurs.")
    parser.add_argument(
        'machines',
        metavar='M',
        type=str,
        nargs='+',
        help='Identifiants des machines à configurer'
    )
    parser.add_argument(
        '--log',
        type=str,
        default="/app/logs/deployment.log",
        help='Chemin du fichier de log'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=5,
        help='Nombre maximum de threads concurrentiels'
    )
    return parser.parse_args()

def main():
    """
    Point d'entrée principal du script de déploiement en masse.

    Séquence :
      1. Parse les arguments CLI.
      2. Configure le logging avec rotation.
      3. Charge toutes les machines et tous les utilisateurs depuis la BDD.
      4. Vérifie le déchiffrement des mots de passe (phase debug).
      5. Valide les définitions de machines.
      6. Filtre les machines demandées.
      7. Lance la configuration en parallèle via ThreadPoolExecutor.

    En cas d'erreur critique, quitte avec le code 1.
    """
    args = parse_arguments()
    setup_logging(args.log)
    main_logger = MachineLoggerAdapter(logging.getLogger(), {'machine': 'MAIN'})
    main_logger.info("===== Démarrage de la configuration des serveurs =====")

    try:
        machines_to_configure = args.machines
        main_logger.info(f"Machines transmises pour configuration : {machines_to_configure}")

        # Charge toutes les machines et utilisateurs depuis la base de données
        all_machines, all_users = load_data_from_db(logger=main_logger)

        # Phase de debugging - Test de déchiffrement des mots de passe
        main_logger.info("===== Phase de vérification des mots de passe =====")
        encryption = Encryption()
        for machine in all_machines:
            if str(machine['id']) in machines_to_configure:
                main_logger.info(f"Vérification des mots de passe pour la machine: {machine['name']} (ID: {machine['id']})")
                try:
                    # Test silencieux avec la méthode de debugging modifiée
                    user_pwd = encryption.test_decryption(machine['password'])
                    root_pwd = encryption.test_decryption(machine['root_password'])
                    
                    if user_pwd is None or root_pwd is None:
                        main_logger.error(f"Problème de déchiffrement pour {machine['name']}: Un ou plusieurs mots de passe n'ont pas pu être déchiffrés")
                    
                except Exception as e:
                    main_logger.error(f"Erreur lors de la vérification pour {machine['name']}: {e}")

        # Valide les données des machines
        for machine in all_machines:
            validate_machine(machine)

        # Filtre uniquement les machines transmises
        selected_machines = [m for m in all_machines if str(m['id']) in machines_to_configure]

        if not selected_machines:
            main_logger.warning("Aucune machine valide sélectionnée.")
            sys.exit(1)

        # Lance la configuration sur les machines sélectionnées en parallèle
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(ServerConfigurator(machine, all_users, logger=main_logger).run): machine 
                for machine in selected_machines
            }
            for future in as_completed(futures):
                machine = futures[future]
                try:
                    future.result()
                except Exception as e:
                    # Utiliser le logger adapté avec le nom de la machine
                    error_logger = MachineLoggerAdapter(logging.getLogger(), {'machine': machine['name']})
                    error_logger.error(f"Erreur lors de la configuration : {e}")

        main_logger.info("===== Déploiement terminé =====")
    except Exception as e:
        main_logger.error(f"Erreur critique : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
