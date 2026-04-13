#!/usr/bin/env python3
"""
configure_servers.py — Déploiement de la configuration SSH en masse pour RootWarden.

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

from ssh_utils import (
    connect_ssh,
    switch_to_root,
    execute_command_as_root,
    clean_output,
    load_data_from_db,
    ensure_sudo_installed
)

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

    Utilisé sur le logger racine pour s'assurer que tous les messages — y compris
    ceux générés par des bibliothèques non instrumentées — passent le formatage
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
def add_to_sudoers(channel, username: str, logger=None):
    """
    Ajoute un utilisateur aux sudoers en créant un fichier dans /etc/sudoers.d/.

    Le fichier créé (/etc/sudoers.d/<username>) accorde les droits NOPASSWD: ALL
    à l'utilisateur et est protégé avec les permissions 440 (lecture root uniquement).

    Args:
        channel  : Channel SSH root (retourné par switch_to_root).
        username : Nom de l'utilisateur Linux à ajouter aux sudoers.
        logger   : Logger optionnel pour tracer l'opération.
    """
    try:
        sudoers_file = f"/etc/sudoers.d/{username}"
        sudoers_entry = f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n"
        execute_command_as_root(channel, f"echo '{sudoers_entry}' > {sudoers_file}", logger=logger)
        execute_command_as_root(channel, f"chmod 440 {sudoers_file}", logger=logger)
        if logger:
            logger.info(f"[{username}] Ajouté aux sudoers avec configuration NOPASSWD.")
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
    try:
        sudoers_file = f"/etc/sudoers.d/{username}"
        execute_command_as_root(channel, f"rm -f {sudoers_file}", logger=logger)
        if logger:
            logger.info(f"[{username}] Retiré des sudoers.")
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
    try:
        output = execute_command_as_root(channel, f"id -u {username}", logger=logger)
        exists = output.strip().isdigit()
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

            # Ecriture via base64 — aucune interpolation shell possible
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

def deploy_user_config(channel, user: dict, logger=None, deploy_bashrc=True):
    """
    Met a jour la configuration de l'utilisateur en une seule operation.

    - Deploie la cle SSH (ou la supprime si inactif).
    - Deploie le .bashrc ameliore si deploy_bashrc=True.
    """
    username = user.get('name')
    if not username:
        if logger:
            logger.error("Nom d'utilisateur manquant dans la définition de l'utilisateur.")
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

        # Ecriture via base64 — aucune interpolation shell possible
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
    
    # --- Mise a jour du fichier .bashrc (configurable) ---
    if not deploy_bashrc:
        if logger:
            logger.info(f"[{username}] Deploiement .bashrc desactive pour cette machine.")
        return

    new_bashrc = """# ~/.bashrc - version améliorée avec couleurs

# Si non interactif, ne rien faire
[[ $- != *i* ]] && return

# Couleurs pour le prompt (root = orange, user = vert)
if [ "$(id -u)" -eq 0 ]; then
    PS1='\\[\\e[38;5;208m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
else
    PS1='\\[\\e[38;5;82m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
fi

# Historique avec horodatage
export HISTTIMEFORMAT="%F %T "

# Activer les couleurs pour ls
export LS_OPTIONS='--color=auto'
eval "$(dircolors -b)"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -lh'
alias la='ls $LS_OPTIONS -lah'
alias l='ls $LS_OPTIONS -lhA'

# Alias courants sécurisés
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Grep avec couleurs
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Utilitaires utiles
alias cls='clear'
alias ..='cd ..'
alias ...='cd ../..'

# Git dans le prompt si dispo
if [ -f /etc/bash_completion.d/git-prompt ]; then
    source /etc/bash_completion.d/git-prompt
    PS1='${debian_chroot:+($debian_chroot)}\\[\\e[38;5;82m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0;33m\\]$(__git_ps1 " (%s)")\\[\\e[0m\\]\\$ '
fi

# Autocomplétion bash si dispo
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
elif [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
fi

# Affichage du terminal en UTF-8
export LANG="fr_FR.UTF-8"
export LC_ALL="fr_FR.UTF-8"

# Correction orthographique dans cd
shopt -s cdspell

# Ajout du PATH perso si nécessaire
export PATH="$HOME/bin:$PATH" """
    
    bashrc_path = f"/home/{username}/.bashrc"
    try:
        if logger:
            logger.info(f"[{username}] Suppression de l'ancien .bashrc.")
        # Supprimer l'ancien fichier .bashrc s'il existe
        execute_command_as_root(channel, f"rm -f {bashrc_path}", logger=logger)
        
        # Déployer le nouveau .bashrc via here-document pour gérer proprement les caractères spéciaux
        bashrc_command = f"cat << 'EOF' > {bashrc_path}\n{new_bashrc}\nEOF"
        if logger:
            logger.info(f"[{username}] Déploiement du nouveau .bashrc.")
        execute_command_as_root(channel, bashrc_command, logger=logger)
        
        # Correction des permissions et propriété
        execute_command_as_root(channel, f"chown {username}:{username} {bashrc_path} && chmod 644 {bashrc_path}", logger=logger)
        
        # Charger le nouveau .bashrc (l'effet immédiat dépendra de la session, mais il sera appliqué pour les futures connexions)
        execute_command_as_root(channel, f". {bashrc_path}", logger=logger)
        
        if logger:
            logger.info(f"[{username}] .bashrc mis à jour et chargé avec succès.")
    except Exception as e:
        if logger:
            logger.error(f"[{username}] Erreur lors de la mise à jour de .bashrc : {e}")

def update_root_bashrc(channel, logger=None):
    """
    Met à jour le .bashrc pour le compte root (/root/.bashrc) avec le contenu défini.
    Cette opération est exécutée une seule fois pour toute la machine.
    """
    new_bashrc = """# /root/.bashrc - version améliorée avec couleurs

# Si non interactif, ne rien faire
[[ $- != *i* ]] && return

# Couleurs pour le prompt (root = orange, user = vert)
if [ "$(id -u)" -eq 0 ]; then
    PS1='\\[\\e[38;5;208m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
else
    PS1='\\[\\e[38;5;82m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
fi

# Historique avec horodatage
export HISTTIMEFORMAT="%F %T "

# Activer les couleurs pour ls
export LS_OPTIONS='--color=auto'
eval "$(dircolors -b)"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -lh'
alias la='ls $LS_OPTIONS -lah'
alias l='ls $LS_OPTIONS -lhA'

# Alias courants sécurisés
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Grep avec couleurs
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Utilitaires utiles
alias cls='clear'
alias ..='cd ..'
alias ...='cd ../..'

# Git dans le prompt si dispo
if [ -f /etc/bash_completion.d/git-prompt ]; then
    source /etc/bash_completion.d/git-prompt
    PS1='${debian_chroot:+($debian_chroot)}\\[\\e[38;5;82m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0;33m\\]$(__git_ps1 " (%s)")\\[\\e[0m\\]\\$ '
fi

# Autocomplétion bash si dispo
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
elif [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
fi

# Affichage du terminal en UTF-8
export LANG="fr_FR.UTF-8"
export LC_ALL="fr_FR.UTF-8"

# Correction orthographique dans cd
shopt -s cdspell

# Ajout du PATH perso si nécessaire
export PATH="/root/bin:$PATH" """
    
    bashrc_path = "/root/.bashrc"
    try:
        if logger:
            logger.info("[root] Mise à jour de .bashrc.")
        execute_command_as_root(channel, f"rm -f {bashrc_path}", logger=logger)
        bashrc_command = f"cat << 'EOF' > {bashrc_path}\n{new_bashrc}\nEOF"
        execute_command_as_root(channel, bashrc_command, logger=logger)
        execute_command_as_root(channel, f"chown root:root {bashrc_path} && chmod 644 {bashrc_path}", logger=logger)
        execute_command_as_root(channel, f". {bashrc_path}", logger=logger)
        if logger:
            logger.info("[root] .bashrc mis à jour et chargé avec succès.")
    except Exception as e:
        if logger:
            logger.error(f"[root] Erreur lors de la mise à jour de .bashrc : {e}")

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
      - Nettoyer les utilisateurs non autorisés (clean_up_users).
      - Créer/configurer les utilisateurs autorisés (configure_users).

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
          2. update_root_bashrc      : déploie le .bashrc amélioré pour root
          3. clean_up_users          : supprime les comptes non autorisés
          4. configure_users         : crée/met à jour les comptes autorisés
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
            # Si service account, sudo est deja disponible — pas besoin de ensure_sudo
            if not use_sa:
                ensure_sudo_installed(ssh_client, self.decrypted_root, logger=self.logger)
            # Mise a jour du .bashrc pour root (configurable par machine)
            if self.machine.get('deploy_bashrc', True):
                update_root_bashrc(root_channel, logger=self.logger)
            else:
                self.logger.info("[bashrc] Deploiement .bashrc desactive pour cette machine.")
            # Nettoyage des utilisateurs non autorises (configurable par machine)
            if self.machine.get('cleanup_users', True):
                self.clean_up_users(root_channel)
            else:
                self.logger.info("[cleanup] Nettoyage utilisateurs desactive pour cette machine.")
            self.configure_users(root_channel)
        self.logger.info(f"=== Configuration terminée pour la machine : {self.name} ===")

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

            # Utilisateurs systeme proteges — ne JAMAIS les supprimer
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
                        random_password = generate_random_password()
                        execute_command_as_root(channel, f"echo '{username}:{random_password}' | chpasswd", logger=self.logger)
                        self.logger.info(f"[{username}] Mot de passe réinitialisé.")
                        remove_from_sudoers(channel, username, logger=self.logger)
                    except Exception as inner_e:
                        self.logger.error(f"[{username}] Échec de la réinitialisation du mot de passe : {inner_e}")
        except Exception as e:
            self.logger.error(f"Erreur lors du nettoyage des utilisateurs : {e}")

    def configure_users(self, channel):
        """
        Configure l'ensemble des utilisateurs autorisés sur la machine courante.

        Itère sur ``all_users`` et délègue à ``configure_user`` pour chaque
        utilisateur dont l'id de machine figure dans ``allowed_servers``.

        Args:
            channel: Channel SSH root.
        """
        for user in self.all_users:
            if self.machine['id'] in user.get('allowed_servers', []):
                self.configure_user(channel, user)

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

            # Deploiement complet de la configuration (cle SSH + bashrc si active)
            deploy_user_config(channel, user, logger=self.logger,
                               deploy_bashrc=self.machine.get('deploy_bashrc', True))

            # Gestion des droits sudo
            if active:
                if sudo:
                    add_to_sudoers(channel, username, logger=self.logger)
                else:
                    remove_from_sudoers(channel, username, logger=self.logger)
            else:
                # Pour les utilisateurs inactifs, on réinitialise le mot de passe et on retire le sudo
                random_password = generate_random_password()
                execute_command_as_root(channel, f"echo '{username}:{random_password}' | chpasswd", logger=self.logger)
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
        (channel_or_client, ssh_client) — Channel root ou client SSH selon le mode.

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
