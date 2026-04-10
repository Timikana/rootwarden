#!/usr/bin/env python3
"""
server_checks.py — Utilitaires de surveillance et d'interrogation des serveurs pour RootWarden.

Rôle :
    Fournit des fonctions de bas niveau pour vérifier la disponibilité réseau d'un
    serveur (check_server_status), récupérer la version de l'OS Linux via SSH
    (get_linux_version), déchiffrer un mot de passe stocké en base (decrypt_password)
    et analyser la sortie de /etc/os-release (parse_os_release).

Dépendances clés :
    - encryption.Encryption : déchiffrement AES/libsodium des mots de passe
    - ssh_utils             : fallback de déchiffrement via decrypt_password
    - config.Config         : paramètres globaux

Note :
    check_server_status utilise uniquement socket.create_connection ; aucune
    bibliothèque SSH n'est requise pour le simple test de connectivité.
    get_linux_version nécessite un channel Paramiko déjà ouvert (non géré ici).
"""

import time
import logging
import socket
from encryption import Encryption
from config import Config

# Initialiser le logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialiser l'objet de chiffrement/déchiffrement
encryptor = Encryption()

def decrypt_password(encrypted_password, logger=None):
    """
    Déchiffre un mot de passe chiffré stocké en base de données.

    Tente d'abord de déchiffrer via l'instance globale ``encryptor`` (Encryption).
    En cas d'échec, effectue un second essai via la fonction ``decrypt_password``
    de ``ssh_utils`` (importée dynamiquement pour éviter les imports circulaires).

    Args:
        encrypted_password: Mot de passe chiffré (chaîne ou None).
        logger            : Logger optionnel pour enregistrer les erreurs.

    Returns:
        Le mot de passe en clair (str), une chaîne vide si ``encrypted_password``
        est falsy, ou None si les deux tentatives de déchiffrement échouent.
    """
    if not encrypted_password:
        return ""
    try:
        # Utiliser la méthode decrypt_password de la classe Encryption qui gère tous les formats
        return encryptor.decrypt_password(encrypted_password)
    except Exception as e:
        if logger:
            logger.error(f"Erreur de déchiffrement dans update_server: {e}")
        # Si on a une erreur avec l'encrypteur, tenter avec la méthode du ssh_utils
        try:
            from ssh_utils import decrypt_password as ssh_decrypt
            return ssh_decrypt(encrypted_password, logger)
        except Exception as e2:
            if logger:
                logger.error(f"Seconde tentative de déchiffrement échouée dans update_server: {e2}")
            return None

def get_linux_version(channel):
    """
    Récupère la version de l'OS Linux via un channel SSH Paramiko déjà ouvert.

    Envoie la commande ``cat /etc/os-release`` sur le channel, attend 1 s,
    puis lit tous les fragments disponibles dans le buffer de réception.

    Args:
        channel: Channel SSH Paramiko interactif (invoke_shell), déjà connecté.

    Returns:
        Sortie brute de /etc/os-release (str), ou None en cas d'erreur.
        Utiliser ``parse_os_release()`` pour extraire la version lisible.
    """
    try:
        channel.send("cat /etc/os-release\n")
        time.sleep(1)
        output = ""
        while channel.recv_ready():
            output_part = channel.recv(1024).decode('utf-8')
            output += output_part

        # Extraction simplifiée du nom et de la version (à affiner si besoin)
        # Exemple: NAME="Ubuntu" VERSION="20.04.6 LTS (Focal Fossa)"
        return output.strip()
    except Exception as e:
        logging.error(f"Erreur lors de la récupération de la version Linux : {e}")
        return None


def check_server_status(ip, port=22, timeout=5):
    """
    Vérifie la disponibilité réseau d'un serveur via une connexion TCP.

    Utilise ``socket.create_connection`` sans établir de session SSH.
    Permet un test rapide avant d'engager une connexion Paramiko complète.

    Args:
        ip      (str): Adresse IP ou nom d'hôte du serveur.
        port    (int): Port TCP à tester (défaut : 22 pour SSH).
        timeout (int): Délai maximal d'attente en secondes (défaut : 5).

    Returns:
        True si la connexion TCP aboutit, False si timeout ou toute autre erreur.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            logging.info(f"Le serveur {ip}:{port} est accessible.")
            return True
    except socket.timeout:
        logging.warning(f"Le serveur {ip}:{port} est injoignable (timeout).")
    except Exception as e:
        logging.error(f"Erreur lors de la vérification du serveur {ip}:{port} : {e}")
    return False


def check_for_cve(version_str):
    """
    Vérifie naïvement si une version d'OS est vulnérable à des CVE.

    Implémentation simplifiée à titre d'exemple — Ubuntu 20.04 est considéré
    non vulnérable ; toute autre version retourne True. Cette fonction est
    destinée à être remplacée par une intégration avec cve_scanner.py.

    Args:
        version_str (str): Chaîne de version OS (ex: sortie de get_linux_version).

    Returns:
        False si la chaîne contient "Ubuntu 20.04", True dans tous les autres cas.
    """
    if "Ubuntu 20.04" in version_str:
        return False
    return True

def parse_os_release(output):
    """
    Extrait la version lisible depuis la sortie brute de /etc/os-release.

    Cherche en priorité la clé ``PRETTY_NAME``, puis ``VERSION`` comme fallback.
    Si aucune des deux n'est trouvée, retourne "Inconnue".

    Args:
        output (str): Contenu brut de /etc/os-release (typiquement retourné
                      par get_linux_version).

    Returns:
        Chaîne de version lisible (ex: "Ubuntu 22.04.4 LTS"), ou "Inconnue".
    """
    lines = output.splitlines()
    pretty = "Inconnue"
    for line in lines:
        if line.startswith('PRETTY_NAME='):
            pretty = line.split('=', 1)[1].strip().strip('"')
            break
        elif line.startswith('VERSION='):
            pretty = line.split('=', 1)[1].strip().strip('"')
    return pretty

