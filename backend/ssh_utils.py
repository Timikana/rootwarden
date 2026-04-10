#!/usr/bin/env python3
"""
ssh_utils.py — Utilitaires SSH et base de données pour le projet RootWarden.

Rôle :
    Centralise toutes les primitives SSH (connexion, élévation de privilèges,
    exécution de commandes) et les fonctions d'accès à la base de données MySQL
    utilisées par server.py, configure_servers.py et iptables_manager.py.

Fonctions principales :
    connect_ssh()              — Ouvre une connexion SSH Paramiko (authentification par mot de passe).
    ssh_session()              — Context manager : connexion SSH avec fermeture garantie.
    execute_as_root()          — Exécute une commande en root via sudo -S (fallback : su -c).
    execute_as_root_stream()   — Idem, en streaming (générateur de chunks pour réponses SSE/plain).
    decrypt_password()         — Déchiffre un mot de passe AES/libsodium stocké en BDD.
    load_data_from_db()        — Charge machines + utilisateurs depuis MySQL.
    load_selected_machines()   — Charge un sous-ensemble de machines par IDs.
    ensure_sudo_installed()    — Installe sudo via su- si absent (bootstrap Debian minimal).
    validate_machine_id()      — Valide et convertit un machine_id reçu en requête.
    clean_output()             — Supprime les séquences ANSI d'une sortie shell.

Élévation de privilèges :
    1. Méthode recommandée : ``sudo -S -p ''`` — le mot de passe est envoyé via stdin,
       jamais dans la commande. Retourne un exit code réel.
    2. Fallback : ``su root -c`` — utilisé sur les systèmes sans sudo (Debian minimal).
    3. Bootstrap uniquement : ``_switch_to_root_shell()`` — ouvre un shell interactif
       via ``su -`` pour installer sudo si absent.

Sécurité :
    - Le mot de passe root est transmis exclusivement via stdin (jamais en argument).
    - Les clés de chiffrement sont lues depuis Config — jamais codées en dur.
    - ``decrypt_password()`` tente plusieurs méthodes pour maximiser la compatibilité
      avec les valeurs chiffrées par PHP, sans exposer la clé dans les logs.

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
#     'user': 'ssh_user',
#     'password': 'ssh_password',
#     'database': 'ssh_key_management'
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
# Déchiffrement du mot de passe
# ===================================================
def decrypt_password(encrypted_password: str, logger=None) -> str:
    """
    Déchiffre un mot de passe AES-256-CBC stocké en BDD (chiffré côté PHP ou Python).

    Implémente une stratégie exhaustive pour maximiser la compatibilité avec les données
    existantes chiffrées par différentes versions du code PHP (openssl_encrypt) :

    Étapes :
        0. Vérification préliminaire du format base64 / complétion de padding si nécessaire.
        1. Décodage base64 → extraction IV (16 octets) + ciphertext.
        2. Préparation de toutes les clés à essayer :
           - SECRET_KEY (hex ou brut) + OLD_SECRET_KEY si définie.
        3. Déchiffrement via deux bibliothèques (cryptography, PyCryptodome) avec 4 stratégies
           de dépadding chacune (PKCS7, null-trim, décodage brut, printable-only).
        4. Simulation exacte du comportement PHP (pack('H*')).
        5. Évaluation des résultats par priorité → retourne le meilleur.
        6. Dernier recours : extraction des segments ASCII imprimables.

    Args:
        encrypted_password (str): Valeur base64 chiffrée (sans préfixe "sodium:" ou "aes:").
        logger               : Logger Python optionnel pour les messages de debug/info.

    Returns:
        str: Mot de passe déchiffré, ou chaîne vide si toutes les méthodes échouent.
    """
    if not encrypted_password:
        return ""
        
    try:
        # Modules nécessaires pour toutes les approches
        from base64 import b64decode
        import binascii
        import subprocess
        import tempfile
        import os
        import re
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from Crypto.Cipher import AES as CryptoAES
        from Crypto.Util.Padding import unpad as crypto_unpad
        from config import Config
        
        # Fonction pour valider si un résultat est probablement un mot de passe valide
        def is_valid_password(password):
            if not password:
                return False
            # Un mot de passe valide devrait contenir principalement des caractères imprimables
            # et avoir une longueur raisonnable
            if len(password) < 4 or len(password) > 100:
                return False
            # Compter les caractères imprimables
            printable_chars = sum(1 for c in password if c.isprintable())
            return printable_chars / len(password) > 0.8  # Au moins 80% de caractères imprimables
        
        # 0. VÉRIFICATION PRÉLIMINAIRE DU FORMAT
        # Certaines chaînes peuvent avoir besoin d'être complétées avec un IV ou du padding
        try:
            # Si la chaîne ne commence pas par un caractère base64, essayer d'ajouter IV factice
            if not re.match(r'^[A-Za-z0-9+/]', encrypted_password):
                # Préparer un IV factice (16 octets de zéros)
                fake_iv = b'\x00' * 16
                # Essayer de décoder comme données brutes
                try:
                    # Convertir hexadécimal en binaire si c'est le format
                    if all(c in '0123456789abcdefABCDEF' for c in encrypted_password):
                        encrypted_data = bytes.fromhex(encrypted_password)
                        # Ajouter IV factice et recoder en base64
                        encrypted_password = b64encode(fake_iv + encrypted_data).decode('ascii')
                except:
                    pass
            
            # Si la longueur décodée n'est pas un multiple de 16, compléter avec du padding
            try:
                decoded = b64decode(encrypted_password)
                if (len(decoded) - 16) % 16 != 0:
                    # Extraire l'IV et les données
                    iv = decoded[:16]
                    data = decoded[16:]
                    # Calculer le padding nécessaire
                    padding_needed = 16 - (len(data) % 16)
                    # Ajouter le padding PKCS7
                    padded_data = data + bytes([padding_needed] * padding_needed)
                    # Reconstruire la chaîne base64
                    encrypted_password = b64encode(iv + padded_data).decode('ascii')
            except:
                pass
        except Exception as e:
            if logger:
                logger.debug(f"Erreur lors de la vérification préliminaire: {e}")
        
        # 1. PRÉPARATION DES DONNÉES
        try:
            data = b64decode(encrypted_password)
        except Exception as e:
            if logger:
                logger.error(f"Erreur de décodage base64: {e}")
            
            # Essayer de traiter comme hexadécimal si base64 échoue
            try:
                if all(c in '0123456789abcdefABCDEF' for c in encrypted_password):
                    data = bytes.fromhex(encrypted_password)
                    # Données hex sans IV: ajouter un IV factice
                    if len(data) % 16 == 0:
                        data = b'\x00' * 16 + data
            except:
                return ""
                
        if len(data) < 16:
            if logger:
                logger.error("Les données sont trop courtes pour inclure un IV valide")
            return ""
            
        # Extraire l'IV et les données chiffrées
        iv = data[:16]
        encrypted = data[16:]
        
        # S'assurer que les données sont un multiple de la taille de bloc
        # Si ce n'est pas le cas, essayer de les compléter avec du padding
        if len(encrypted) % 16 != 0:
            padding_needed = 16 - (len(encrypted) % 16)
            encrypted = encrypted + bytes([padding_needed] * padding_needed)
            if logger:
                logger.debug(f"Données complétées avec {padding_needed} octets de padding")
        
        # 2. PRÉPARATION DES CLÉS DANS DIFFÉRENTS FORMATS
        keys_to_try = []
        
        # Clé principale (SECRET_KEY)
        if len(Config.SECRET_KEY) in (32, 64) and all(c in '0123456789abcdefABCDEF' for c in Config.SECRET_KEY):
            # Clé hexadécimale
            keys_to_try.append(("SECRET_KEY hex", bytes.fromhex(Config.SECRET_KEY)))
        else:
            # Clé brute
            keys_to_try.append(("SECRET_KEY brut", Config.SECRET_KEY[:32].encode('utf-8')))
            
        # Ancienne clé (OLD_SECRET_KEY)
        if Config.OLD_SECRET_KEY:
            # Format brut limité à 32 caractères (façon PHP)
            keys_to_try.append(("OLD_SECRET_KEY brut", Config.OLD_SECRET_KEY[:32].encode('utf-8')))
            try:
                # Essayer comme hex au cas où
                keys_to_try.append(("OLD_SECRET_KEY hex", bytes.fromhex(Config.OLD_SECRET_KEY)))
            except:
                pass
        
        # Stocker tous les résultats potentiels pour les évaluer à la fin
        potential_results = []
        
        # 3. MÉTHODES DE DÉCHIFFREMENT ET DE UNPAD
        for key_name, key in keys_to_try:
            if logger:
                logger.debug(f"Essai avec {key_name}")
            
            # Rembourrer la clé si nécessaire (pour éviter des erreurs de longueur de clé)
            if len(key) < 32:
                key = key.ljust(32, b'\0')
            
            # MÉTHODE 1: cryptography
            try:
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted) + decryptor.finalize()
                
                # UNPAD MÉTHODE 1: PKCS7 standard
                try:
                    padding_length = decrypted[-1]
                    if 1 <= padding_length <= 16:  # Vérification basique
                        unpadded = decrypted[:-padding_length]
                        result = unpadded.decode('utf-8', errors='ignore')
                        if result and is_valid_password(result):
                            if logger:
                                logger.info(f"Déchiffrement réussi: cryptography + PKCS7 basic avec {key_name}")
                            potential_results.append((result, 10))  # Priorité 10 (élevée)
                except Exception:
                    pass
                    
                # UNPAD MÉTHODE 2: Recherche du premier caractère null
                try:
                    null_pos = decrypted.find(b'\x00')
                    if null_pos > 0:
                        result = decrypted[:null_pos].decode('utf-8', errors='ignore')
                        if result and is_valid_password(result):
                            if logger:
                                logger.info(f"Déchiffrement réussi: cryptography + null trim avec {key_name}")
                            potential_results.append((result, 8))  # Priorité 8
                except Exception:
                    pass
                    
                # UNPAD MÉTHODE 3: Tout décoder avec gestion des erreurs
                try:
                    result = decrypted.decode('utf-8', errors='ignore').rstrip('\0')
                    # Nettoyer les caractères non imprimables à la fin
                    result = re.sub(r'[\x00-\x1F\x7F-\xFF]+$', '', result)
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: cryptography + decode complet avec {key_name}")
                        potential_results.append((result, 6))  # Priorité 6
                except Exception:
                    pass
                    
                # UNPAD MÉTHODE 4: Recherche de caractères imprimables uniquement
                try:
                    # Garder uniquement les caractères imprimables
                    printable_bytes = bytes(b for b in decrypted if 32 <= b < 127)
                    result = printable_bytes.decode('utf-8', errors='ignore')
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: cryptography + printable only avec {key_name}")
                        potential_results.append((result, 4))  # Priorité 4
                except Exception:
                    pass
            except Exception as e:
                if logger:
                    logger.debug(f"Échec méthode cryptography avec {key_name}: {e}")
                    
            # MÉTHODE 2: PyCrypto/PyCryptodome
            try:
                cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                
                # Mêmes stratégies de unpad
                try:
                    padding_length = decrypted[-1]
                    if 1 <= padding_length <= 16:
                        unpadded = decrypted[:-padding_length]
                        result = unpadded.decode('utf-8', errors='ignore')
                        if result and is_valid_password(result):
                            if logger:
                                logger.info(f"Déchiffrement réussi: PyCrypto + PKCS7 basic avec {key_name}")
                            potential_results.append((result, 9))  # Priorité 9
                except Exception:
                    pass
                    
                try:
                    # Essayer PKCS7 de PyCryptodome
                    unpadded = crypto_unpad(decrypted, 16)
                    result = unpadded.decode('utf-8', errors='ignore')
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: PyCrypto + PKCS7 officiel avec {key_name}")
                        potential_results.append((result, 9))  # Priorité 9
                except Exception:
                    pass
                    
                # Null character trim
                try:
                    null_pos = decrypted.find(b'\x00')
                    if null_pos > 0:
                        result = decrypted[:null_pos].decode('utf-8', errors='ignore')
                        if result and is_valid_password(result):
                            if logger:
                                logger.info(f"Déchiffrement réussi: PyCrypto + null trim avec {key_name}")
                            potential_results.append((result, 7))  # Priorité 7
                except Exception:
                    pass
                    
                # Tout décoder
                try:
                    result = decrypted.decode('utf-8', errors='ignore').rstrip('\0')
                    # Nettoyer les caractères non imprimables à la fin
                    result = re.sub(r'[\x00-\x1F\x7F-\xFF]+$', '', result)
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: PyCrypto + decode complet avec {key_name}")
                        potential_results.append((result, 5))  # Priorité 5
                except Exception:
                    pass
                    
                # Garder uniquement les caractères imprimables
                try:
                    printable_bytes = bytes(b for b in decrypted if 32 <= b < 127)
                    result = printable_bytes.decode('utf-8', errors='ignore')
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: PyCrypto + printable only avec {key_name}")
                        potential_results.append((result, 3))  # Priorité 3
                except Exception:
                    pass
            except Exception as e:
                if logger:
                    logger.debug(f"Échec méthode PyCrypto avec {key_name}: {e}")

        # 4. MÉTHODE ULTIME: Simuler exactement le PHP en Python
        for key_name, key in keys_to_try:
            try:
                # Méthode de "reconstruction PHP" : reproduire exactement ce que fait PHP
                
                # 1. Si la clé est en hex, la convertir selon la logique de PHP
                if key_name.endswith("hex"):
                    # PHP utilise pack('H*', hex) ce qui donne une chaîne binaire
                    effective_key = key
                else:
                    # PHP utilise directement la chaîne limitée à 32 caractères
                    effective_key = key[:32] if len(key) > 32 else key
                
                # 2. Utiliser la même méthode de déchiffrement que PHP
                cipher = Cipher(algorithms.AES(effective_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted) + decryptor.finalize()
                
                # Recréer pkcs7_unpad de PHP en Python
                try:
                    padding_value = decrypted[-1]
                    if 1 <= padding_value <= 16:
                        unpadded = decrypted[:-padding_value]
                        
                        # Vérifier si le résultat décodé est valide
                        result = unpadded.decode('utf-8', errors='ignore')
                        if result and is_valid_password(result):
                            if logger:
                                logger.info(f"Déchiffrement réussi: Méthode PHP avec {key_name}")
                            potential_results.append((result, 10))  # Priorité 10 (élevée)
                except Exception:
                    pass
                    
                # Nettoyer et ne garder que les caractères imprimables
                try:
                    printable_bytes = bytes(b for b in decrypted if 32 <= b < 127)
                    result = printable_bytes.decode('utf-8', errors='ignore')
                    if result and is_valid_password(result):
                        if logger:
                            logger.info(f"Déchiffrement réussi: Méthode PHP + printable only avec {key_name}")
                        potential_results.append((result, 8))  # Priorité 8
                except Exception:
                    pass
            except Exception as e:
                if logger:
                    logger.debug(f"Échec simulation PHP avec {key_name}: {e}")
                
        # 5. ÉVALUATION DES RÉSULTATS
        if potential_results:
            # Trier par priorité (descendante)
            potential_results.sort(key=lambda x: x[1], reverse=True)
            
            # Retourner le résultat avec la plus haute priorité
            if logger:
                logger.info(f"Meilleur résultat trouvé avec priorité {potential_results[0][1]}")
            return potential_results[0][0]
        
        # 6. SI TOUT ÉCHOUE, TENTATIVE DÉSESPÉRÉE
        # Tentative directe sur les données brutes
        try:
            # Essayer de trouver une chaîne de caractères ASCII dans les données brutes
            raw_data = b64decode(encrypted_password)
            # Chercher tous les segments de caractères imprimables d'au moins 4 caractères
            printable_segments = re.findall(b'[ -~]{4,}', raw_data)
            if printable_segments:
                # Prendre le segment le plus long
                best_segment = max(printable_segments, key=len)
                result = best_segment.decode('ascii', errors='ignore')
                if result and is_valid_password(result):
                    if logger:
                        logger.info("Déchiffrement réussi: extraction directe de caractères imprimables")
                    return result
        except Exception as e:
            if logger:
                logger.debug(f"Échec de l'extraction directe: {e}")
                
        # Si toutes les méthodes échouent, retourner une chaîne vide
        if logger:
            logger.error("Toutes les méthodes de déchiffrement ont échoué")
        return ""
    except Exception as e:
        if logger:
            logger.error(f"Erreur générale dans decrypt_password: {e}")
        return ""

# ===================================================
# Gestion SSH (connexion, root)
# ===================================================
def connect_ssh(host: str, username: str, password: str, port: int = 22,
                logger=None, force_password: bool = False,
                service_account: bool = False) -> paramiko.SSHClient:
    """
    Etablit une connexion SSH — essaie d'abord la keypair plateforme,
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
            _logger.debug("SSH service account auth echouee pour %s:%d — fallback", host, port)
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as e:
            _logger.debug("SSH service account non disponible (%s) — fallback", e)
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
            _logger.debug("SSH keypair auth echouee pour %s:%d — fallback password", host, port)
            # Fermer et recreer le client pour le fallback
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except Exception as e:
            _logger.debug("SSH keypair non disponible (%s) — fallback password", e)
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
    Exécute une commande en root via ``su root -c`` (fallback si sudo absent).
    Attend le prompt "Password:" avant d'envoyer le mot de passe via le PTY.
    """
    _log = logger or logging.getLogger(__name__)
    su_cmd = f"su root -c {shlex.quote(command)}"
    try:
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
                break  # Données reçues mais pas de prompt → peut-être pas de mdp requis

        stdin.write(root_password + '\n')
        stdin.flush()

        # Lire la sortie jusqu'à la fin de la commande
        out = ""
        last_data = time.time()
        deadline_cmd = time.time() + timeout
        while time.time() < deadline_cmd:
            r, _, _ = select.select([stdout.channel], [], [], 0.5)
            if r:
                chunk = stdout.channel.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    break
                out += chunk
                last_data = time.time()
            elif stdout.channel.exit_status_ready():
                while stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096).decode('utf-8', errors='replace')
                    if chunk:
                        out += chunk
                break
            elif out and (time.time() - last_data) >= 3.0:
                break

        code = stdout.channel.recv_exit_status()
        _log.info("_su_exec code=%d cmd='%s...'", code, command[:60])
        return clean_output(out), "", code

    except Exception as e:
        _log.error("_su_exec '%s': %s", command[:60], e)
        raise


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
       retombe sur ``su root -c`` — compatible avec Debian sans sudo configuré.

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

    # Détecte si sudo est disponible sur le serveur
    _, check_out, _ = client.exec_command("which sudo 2>/dev/null", timeout=5)
    has_sudo = bool(check_out.read().decode().strip())

    if has_sudo:
        root_cmd = f"sudo -S -p '' sh -c {shlex.quote(command)}"
    else:
        # Fallback su -c pour les serveurs sans sudo
        escaped = command.replace("'", "'\\''")
        root_cmd = f"su - root -c '{escaped}'"
    _log.info("execute_as_root_stream: %s (mode=%s)", command[:60], 'sudo' if has_sudo else 'su')

    try:
        stdin, stdout, stderr = client.exec_command(root_cmd, get_pty=True)
        if not has_sudo:
            # su affiche "Mot de passe :" — attendre l'invite avant d'envoyer
            import time as _time
            _time.sleep(1)
        stdin.write(root_password + '\n')
        stdin.flush()

        yield "Début de l'exécution...\n"

        # Ignore les premiers octets (écho du mot de passe renvoyé par le PTY)
        _skip_password = True

        while True:
            r, _, _ = select.select([stdout.channel], [], [], 0.5)
            if r:
                chunk = stdout.channel.recv(4096)
                if not chunk:
                    break
                text = chunk.decode('utf-8', errors='replace')
                # Filtre l'écho du mot de passe dans les premiers chunks
                if _skip_password:
                    text = text.replace(root_password, '')
                    text = text.replace('\r', '')
                    if text.strip():
                        _skip_password = False
                # Nettoie les séquences ANSI du terminal
                text = _ansi_re.sub('', text)
                if text.strip():
                    yield text
            elif stdout.channel.exit_status_ready():
                while stdout.channel.recv_ready():
                    chunk = stdout.channel.recv(4096)
                    if chunk:
                        text = _ansi_re.sub('', chunk.decode('utf-8', errors='replace'))
                        text = text.replace(root_password, '')
                        if text.strip():
                            yield text
                break

        code = stdout.channel.recv_exit_status()
        yield f"\nExécution terminée (code {code}).\n"

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
        1. ``SELECT … FROM machines`` — toutes les machines avec identifiants SSH.
        2. Jointure ``users LEFT JOIN user_machine_access`` — tous les utilisateurs
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

        # Jointure users -> user_machine_access
        cursor.execute("""
            SELECT 
                u.id AS user_id, 
                u.name AS user_name,
                u.active,
                u.sudo,
                u.ssh_key,
                uma.machine_id
            FROM users u
            LEFT JOIN user_machine_access uma ON u.id = uma.user_id
        """)
        user_machines = cursor.fetchall()

        cursor.close()
        db.close()

        # Regrouper par user_id
        users_dict = {}
        for record in user_machines:
            uid = record['user_id']
            if uid not in users_dict:
                users_dict[uid] = {
                    "name": record['user_name'],
                    "active": record['active'],
                    "sudo": record['sudo'],
                    "ssh_key": record['ssh_key'],
                    "allowed_servers": []
                }
            if record['machine_id']:
                users_dict[uid]['allowed_servers'].append(record['machine_id'])

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
                _log.info("'sudo' absent — installation en cours.")
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
