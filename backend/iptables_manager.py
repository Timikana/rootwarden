"""
iptables_manager.py — Gestion des règles iptables/ip6tables pour RootWarden.

Rôle :
    Lecture et application des règles iptables (IPv4 et IPv6) sur des serveurs
    distants via SSH. Toute écriture de règles passe par un encodage base64 afin
    d'éliminer le risque d'injection de commandes shell.

Dépendances clés :
    - ssh_utils.execute_as_root  : exécution de commandes en tant que root via SSH
    - encryption.Encryption      : déchiffrement des mots de passe stockés en BDD
    - config.Config              : paramètres globaux de l'application

Note de sécurité :
    L'écriture des règles dans les fichiers distants utilise exclusivement base64
    (fonction _write_rules_safe) pour éviter tout risque d'injection via les
    caractères spéciaux présents dans les règles iptables.
"""

import base64
import logging
import re

from config import Config
from encryption import Encryption
from ssh_utils import (
    connect_ssh,
    ssh_session,
    execute_as_root,
    clean_output,
)

_log = logging.getLogger(__name__)

# Instance partagée du moteur de chiffrement/déchiffrement
encryptor = Encryption()


def decrypt_password(encrypted_password: str) -> str:
    """
    Déchiffre un mot de passe chiffré via la classe Encryption.

    Args:
        encrypted_password: Mot de passe chiffré tel que stocké en base de données.

    Returns:
        Le mot de passe en clair, ou une chaîne vide en cas d'erreur ou de valeur nulle.
    """
    if not encrypted_password:
        return ""
    try:
        return encryptor.decrypt_password(encrypted_password)
    except Exception as e:
        _log.error("Erreur déchiffrement iptables_manager : %s", e)
        return ""


# ---------------------------------------------------------------------------
# Lecture des règles
# ---------------------------------------------------------------------------

def get_iptables_rules(client, root_password: str) -> dict:
    """
    Récupère les règles iptables actives (IPv4 + IPv6) et les fichiers rules.v4/v6.

    Exécute quatre commandes en root via SSH :
      - ``iptables -L -v -n``           → règles IPv4 en mémoire
      - ``ip6tables -L -v -n``          → règles IPv6 en mémoire (ou message si absent)
      - ``cat /etc/iptables/rules.v4``  → règles IPv4 persistées sur disque
      - ``cat /etc/iptables/rules.v6``  → règles IPv6 persistées sur disque

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.

    Returns:
        dict avec les clés :
            - current_rules_v4 (str) : règles IPv4 actives
            - current_rules_v6 (str) : règles IPv6 actives
            - file_rules_v4    (str) : contenu de /etc/iptables/rules.v4
            - file_rules_v6    (str) : contenu de /etc/iptables/rules.v6

    Raises:
        Exception: Re-lève toute exception SSH ou d'exécution après l'avoir loguée.
    """
    try:
        _log.info("Récupération des règles iptables.")
        rules_v4, _, _   = execute_as_root(client, "iptables -L -v -n", root_password)
        rules_v6, _, _   = execute_as_root(client,
            "ip6tables -L -v -n 2>/dev/null || echo 'No IPv6 rules'", root_password)
        file_v4, _, _    = execute_as_root(client,
            "cat /etc/iptables/rules.v4 2>/dev/null || echo ''", root_password)
        file_v6, _, _    = execute_as_root(client,
            "cat /etc/iptables/rules.v6 2>/dev/null || echo 'No IPv6 rules'", root_password)
        return {
            "current_rules_v4": rules_v4,
            "current_rules_v6": rules_v6,
            "file_rules_v4":    file_v4,
            "file_rules_v6":    file_v6,
        }
    except Exception as e:
        _log.error("get_iptables_rules : %s", e)
        raise


# ---------------------------------------------------------------------------
# Application des règles
# ---------------------------------------------------------------------------

def _write_rules_safe(client, root_password: str, rules: str, dest_path: str) -> None:
    """
    Écrit des règles iptables dans un fichier distant via encodage base64.

    L'encodage base64 garantit qu'aucun caractère spécial contenu dans les règles
    ne peut être interprété comme une commande shell (anti-injection).
    La commande distante décode le base64 puis redirige vers le fichier cible.

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.
        rules:         Contenu des règles iptables à écrire (texte brut).
        dest_path:     Chemin absolu du fichier de destination sur le serveur distant.
    """
    encoded = base64.b64encode(rules.encode('utf-8')).decode('ascii')
    execute_as_root(client,
        f"printf '%s' '{encoded}' | base64 -d > {dest_path}",
        root_password)


def apply_iptables_rules(client, root_password: str,
                         rules_v4: str, rules_v6: str = None) -> None:
    """
    Applique des règles iptables sur un serveur distant.

    Séquence d'opérations :
      1. Crée les fichiers rules.v4 et rules.v6 si absents (touch + chmod 640).
      2. Écrit les règles IPv4 via _write_rules_safe (encodage base64).
      3. Recharge les règles IPv4 en mémoire via ``iptables-restore``.
      4. Si rules_v6 est fourni, même traitement pour IPv6.

    Args:
        client:        Client SSH Paramiko connecté au serveur cible.
        root_password: Mot de passe root en clair pour l'élévation de privilèges.
        rules_v4:      Règles IPv4 au format iptables-save (texte brut).
        rules_v6:      Règles IPv6 au format ip6tables-save (optionnel).

    Raises:
        Exception: Re-lève toute exception SSH ou d'exécution après l'avoir loguée.
    """
    try:
        _log.info("Application des règles iptables.")

        for path in ("/etc/iptables/rules.v4", "/etc/iptables/rules.v6"):
            execute_as_root(client, f"touch {path} && chmod 640 {path}", root_password)

        _write_rules_safe(client, root_password, rules_v4, "/etc/iptables/rules.v4")
        execute_as_root(client, "iptables-restore < /etc/iptables/rules.v4", root_password)

        if rules_v6:
            _write_rules_safe(client, root_password, rules_v6, "/etc/iptables/rules.v6")
            execute_as_root(client, "ip6tables-restore < /etc/iptables/rules.v6", root_password)

        _log.info("Règles iptables appliquées avec succès.")
    except Exception as e:
        _log.error("apply_iptables_rules : %s", e)
        raise
