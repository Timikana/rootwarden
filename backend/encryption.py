# utils/encryption.py
"""
encryption.py - Chiffrement et déchiffrement des mots de passe (RootWarden).

Rôle :
    Fournit la classe ``Encryption`` qui implémente un double mécanisme de chiffrement
    compatible avec le code PHP du frontend (openssl_encrypt / openssl_decrypt).

Algorithmes supportés :
    1. libsodium / PyNaCl (préfixe "sodium:") - recommandé, AEAD (nonce inclus).
       Utilise ``nacl.secret.SecretBox`` (XSalsa20-Poly1305).
    2. AES-256-CBC (préfixe "aes:") - fallback si PyNaCl absent.
       Format : base64(IV[16] + ciphertext), padding PKCS7.

Compatibilité PHP :
    Le déchiffrement AES est conçu pour être interopérable avec ``openssl_decrypt``
    (AES-256-CBC, clé hexadécimale → binaire via ``pack('H*', ...)``).
    Plusieurs stratégies de dépadding et de décodage sont essayées successivement
    pour absorber les différences de comportement entre PHP et Python.

Sécurité :
    - Ne jamais logguer le mot de passe en clair ni la clé.
    - Passer le mot de passe uniquement via stdin ou mémoire - jamais en argument de commande.
    - L'ancienne clé (OLD_SECRET_KEY) est uniquement utilisée pour le déchiffrement
      (migration transparente) ; le re-chiffrement utilise toujours SECRET_KEY.

Dépendances :
    cryptography (hazmat AES-CBC), PyNaCl (optionnel), PyCryptodome (fallback),
    config.Config (clés de chiffrement).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import logging
import os
from config import Config

_log = logging.getLogger(__name__)

class Encryption:
    """
    Gestionnaire de chiffrement/déchiffrement à double couche pour RootWarden.

    Supporte libsodium (PyNaCl, recommandé) et AES-256-CBC (fallback).
    Gère la coexistence de deux clés (principale + ancienne) pour permettre
    une migration transparente des mots de passe sans interruption de service.

    Attributs d'instance :
        is_sodium_available (bool) : True si PyNaCl est installé et importable.
        secret_key (bytes)         : Clé principale de 32 octets (dérivée de Config.SECRET_KEY).
        old_secret_key (str)       : Ancienne clé brute (Config.OLD_SECRET_KEY), peut être vide.
        old_key_bytes (bytes|None) : Ancienne clé de 32 octets, None si non configurée.
    """

    def __init__(self):
        """
        Initialise le gestionnaire de chiffrement.

        Vérifie la disponibilité de PyNaCl, prépare la clé principale et,
        si définie, l'ancienne clé pour les opérations de déchiffrement legacy.

        Raises:
            ValueError: Si SECRET_KEY est vide ou invalide.
        """
        self.is_sodium_available = self._check_sodium_available()

        from config import Config
        self.secret_key_raw = self._prepare_key(Config.SECRET_KEY)
        # HKDF derivation - separe les usages (passwords vs TOTP)
        self.secret_key = self._derive_key(self.secret_key_raw, b'rootwarden-aes')
        self.old_secret_key = Config.OLD_SECRET_KEY

        if self.old_secret_key:
            self.old_key_bytes = self._prepare_key(self.old_secret_key, is_old_key=True)
        else:
            self.old_key_bytes = None

    def _check_sodium_available(self):
        """
        Vérifie si PyNaCl (implémentation Python de libsodium) est disponible.

        Tente d'importer ``nacl.secret`` et ``nacl.utils``. En cas d'échec,
        émet un avertissement et retourne False pour basculer sur AES.

        Returns:
            bool: True si PyNaCl est utilisable, False sinon.
        """
        try:
            import nacl.secret
            import nacl.utils
            return True
        except ImportError:
            _log.warning("PyNaCl n'est pas disponible, utilisation de AES uniquement.")
            return False
    
    def _prepare_key(self, key, is_old_key=False):
        """
        Convertit une clé brute ou hexadécimale en 32 octets utilisables par AES-256.

        Pour la clé principale (is_old_key=False), si la chaîne est hexadécimale
        de 32 ou 64 caractères, elle est décodée via ``bytes.fromhex()``.
        Pour l'ancienne clé ou toute autre forme, la chaîne est encodée UTF-8
        et tronquée à 32 octets.

        Args:
            key (str)         : Clé en texte clair (hex ou brut).
            is_old_key (bool) : True pour utiliser le chemin "ancienne clé" (pas de détection hex).

        Returns:
            bytes: Clé de 32 octets prête pour AES-256.

        Raises:
            ValueError: Si la clé est vide.
        """
        if not key:
            raise ValueError("La clé ne peut pas être vide")
        
        if not is_old_key and len(key) in (32, 64) and all(c in '0123456789abcdefABCDEF' for c in key):
            # Clé hexadécimale (nouvelle clé)
            return bytes.fromhex(key)
        else:
            # Clé brute (ancienne clé)
            if isinstance(key, str):
                key = key.encode('utf-8')
            return key[:32]  # Tronquer à 32 octets (256 bits)

    def _derive_key(self, key_material: bytes, info: bytes) -> bytes:
        """Derive une cle via HKDF-SHA256 pour separer les usages."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(key_material)

    def pad(self, data):
        """
        Applique le padding PKCS7 sur les données fournies.

        Le padding complète les données jusqu'à un multiple de 16 octets.
        Chaque octet de padding a pour valeur le nombre d'octets ajoutés.

        Args:
            data (bytes): Données à padder.

        Returns:
            bytes: Données paddées (longueur multiple de 16).
        """
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        """Remove and validate PKCS7 padding."""
        if not data:
            return b''
        padding_length = data[-1]
        if padding_length < 1 or padding_length > 16 or padding_length > len(data):
            raise ValueError(f"Padding PKCS7 invalide : {padding_length}")
        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Padding PKCS7 corrompu")
        return data[:-padding_length]

    def encrypt_password(self, password, use_sodium=True):
        """
        Chiffre un mot de passe en utilisant la méthode préférée (Sodium si disponible, sinon AES).
        
        Args:
            password (str): Le mot de passe à chiffrer
            use_sodium (bool): Si True, utilise Sodium si disponible, sinon AES
            
        Returns:
            str: Le mot de passe chiffré encodé en base64, préfixé par le type de méthode utilisée
        """
        if not password:
            return ""
        
        # Vérifier si Sodium peut être utilisé
        if use_sodium and self.is_sodium_available:
            try:
                import nacl.secret
                import nacl.utils
                from base64 import b64encode
                
                # Créer une boîte de chiffrement avec la clé
                box = nacl.secret.SecretBox(self.secret_key)
                
                # Générer un nonce aléatoire
                nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                
                # Chiffrer avec libsodium
                encrypted = box.encrypt(password.encode('utf-8'), nonce)
                
                # Retourner le résultat préfixé et encodé en base64
                return f"sodium:{b64encode(encrypted).decode('ascii')}"
            except Exception as e:
                _log.warning("Erreur lors du chiffrement avec Sodium: %s", e)
                # Continuer avec AES comme méthode de secours
        
        # Méthode de secours: AES
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from base64 import b64encode
            import os
            
            # Générer un IV aléatoire
            iv = os.urandom(16)  # 16 octets pour AES
            
            # Appliquer le padding PKCS7
            password_bytes = password.encode('utf-8')
            padding_length = 16 - (len(password_bytes) % 16)
            padded_password = password_bytes + bytes([padding_length] * padding_length)
            
            # Créer le chiffreur AES
            cipher = Cipher(
                algorithms.AES(self.secret_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Chiffrer
            encrypted = encryptor.update(padded_password) + encryptor.finalize()
            
            # Combiner IV et données chiffrées, puis encoder en base64
            return f"aes:{b64encode(iv + encrypted).decode('ascii')}"
        except Exception as e:
            _log.error("Erreur lors du chiffrement AES: %s", e)
            raise

    def decrypt_password(self, encrypted_password: str) -> str:
        """
        Point d'entrée principal du déchiffrement - détecte automatiquement le format.

        Stratégie :
            1. Préfixe "sodium:" → déchiffrement libsodium (SecretBox.decrypt).
            2. Préfixe "aes:"    → retire le préfixe puis suit le chemin AES.
            3. Appelle ``decrypt_php_compatible`` (AES-CBC, clé principale puis ancienne).
            4. Fallback vers ``decrypt_simple`` (PyCrypto / cryptography, stratégies multiples).

        Args:
            encrypted_password (str): Texte chiffré préfixé ("sodium:…" ou "aes:…") ou
                                      base64 brut (chiffré PHP sans préfixe).

        Returns:
            str: Mot de passe déchiffré.

        Raises:
            ValueError: Si aucune méthode ne parvient à déchiffrer.
        """
        if not encrypted_password:
            return ""
        
        # Détecter la méthode de chiffrement utilisée
        if encrypted_password.startswith("sodium:") and self.is_sodium_available:
            # Déchiffrement avec Sodium - essaie cle HKDF puis cle brute (fallback legacy)
            import nacl.secret
            from base64 import b64decode

            encoded_data = encrypted_password[7:]
            encrypted_data = b64decode(encoded_data)

            for label, key in [("HKDF", self.secret_key), ("raw", self.secret_key_raw)]:
                try:
                    box = nacl.secret.SecretBox(key)
                    decrypted = box.decrypt(encrypted_data)
                    return decrypted.decode('utf-8')
                except Exception:
                    continue
            _log.debug("Echec dechiffrement Sodium (HKDF + raw)")
        elif encrypted_password.startswith("aes:"):
            # Déchiffrement AES avec préfixe explicite
            encrypted_password = encrypted_password[4:]  # Enlever 'aes:'
        
        # Méthode principale optimisée pour la compatibilité PHP
        try:
            result = self.decrypt_php_compatible(encrypted_password)
            if result:
                return result
        except Exception as e:
            _log.debug("Échec méthode PHP compatible: %s", e)

        # Méthode de secours
        methods = [
            (self.decrypt_simple, "méthode simplifiée"),
        ]

        for method, name in methods:
            try:
                result = method(encrypted_password)
                if result:
                    return result
            except Exception as e:
                _log.debug("Échec avec %s: %s", name, e)
        
        # Si toutes les méthodes échouent, lever une exception
        raise ValueError("Échec du déchiffrement: Aucune méthode n'a fonctionné")

    def decrypt_php_compatible(self, encrypted_password: str) -> str:
        """
        Déchiffre un mot de passe chiffré par ``openssl_encrypt`` PHP (AES-256-CBC).

        Format attendu : base64(IV[16 octets] + ciphertext).
        Tente successivement la clé principale (SECRET_KEY) puis l'ancienne clé (OLD_SECRET_KEY).
        Pour chaque clé, plusieurs stratégies de dépadding sont essayées :
          - PKCS7 standard (dernier octet = longueur du padding)
          - Troncature au premier octet nul (null terminator PHP)
          - Décodage brut UTF-8 avec suppression des nuls de fin

        Args:
            encrypted_password (str): Données base64 sans préfixe (IV+ciphertext).

        Returns:
            str: Mot de passe déchiffré.

        Raises:
            ValueError: Si les données sont invalides ou si le déchiffrement échoue
                        pour toutes les clés essayées.
        """
        if not encrypted_password:
            return ""
        
        # Décoder le base64 pour obtenir les données
        try:
            decoded_data = b64decode(encrypted_password)
        except Exception:
            raise ValueError("Données base64 invalides")
            
        if len(decoded_data) < 16:
            raise ValueError("Données trop courtes pour contenir un IV")
            
        # Extraire l'IV et les données chiffrées
        iv = decoded_data[:16]
        encrypted_data = decoded_data[16:]
        
        # Liste des clés à essayer : HKDF derivee, brute (legacy), ancienne cle
        keys_to_try = [
            (self.secret_key, "SECRET_KEY_HKDF"),
            (self.secret_key_raw, "SECRET_KEY_RAW"),
        ]
        if self.old_secret_key:
            keys_to_try.append((self.old_key_bytes, "OLD_SECRET_KEY"))

        for key, key_name in keys_to_try:
            # 1. Essayer avec la bibliothèque cryptography
            try:
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                raw_data = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Essayer plusieurs techniques de dépadding 
                # PKCS7 padding où le dernier octet indique le nombre d'octets à retirer
                try:
                    padding_length = raw_data[-1]
                    if 1 <= padding_length <= 16:
                        # Vérification simplifiée du padding sans validation stricte
                        unpadded = raw_data[:-padding_length]
                        try:
                            return unpadded.decode('utf-8')
                        except UnicodeDecodeError:
                            # Si ça ne marche pas, essayer différemment
                            pass
                except (IndexError, ValueError):
                    pass
                
                # PHP pourrait avoir des caractères nuls à la fin
                try:
                    null_pos = raw_data.find(b'\x00')
                    if null_pos > 0:
                        return raw_data[:null_pos].decode('utf-8')
                except Exception:
                    pass
                    
                # Dernier recours: essayer de décoder tel quel
                try:
                    return raw_data.decode('utf-8', errors='ignore').rstrip('\x00')
                except Exception:
                    pass
                    
            except Exception as e:
                _log.debug("Exception avec %s: %s", key_name, e)

        # Si aucune des méthodes n'a fonctionné, lever une exception
        raise ValueError("Échec de déchiffrement avec la méthode PHP compatible")

    def decrypt_simple(self, encrypted_password: str) -> str:
        """
        Fallback de déchiffrement AES-256-CBC, compatible PHP openssl_decrypt.

        Utilisé uniquement si ``decrypt_php_compatible`` échoue.
        Essaie d'abord PyCrypto/PyCryptodome (comportement le plus proche de PHP),
        puis la bibliothèque ``cryptography`` comme second recours.
        Pour chaque bibliothèque, tente trois stratégies de dépadding :
          1. PKCS7 basique (dernier octet).
          2. Décodage brut avec suppression des nuls.
          3. Troncature au premier octet nul.

        Args:
            encrypted_password (str): Données base64 (IV[16] + ciphertext), sans préfixe.

        Returns:
            str: Mot de passe déchiffré, ou chaîne vide si toutes les méthodes échouent.
        """
        # Gérer le cas où le mot de passe est vide
        if not encrypted_password or len(encrypted_password) < 10:
            return ""
        
        # Forcer une chaîne ASCII en cas d'entrée Unicode/UTF-8
        if isinstance(encrypted_password, bytes):
            encrypted_password = encrypted_password.decode('ascii')
        
        # Décoder le base64
        try:
            decoded_data = b64decode(encrypted_password)
        except Exception:
            _log.debug("Erreur de décodage base64")
            return ""
        
        if len(decoded_data) < 32:  # Au moins 16 octets pour l'IV et 16 pour les données
            _log.debug("Données décodées trop courtes")
            return ""
        
        # Extraire l'IV (les 16 premiers octets) et les données chiffrées
        iv = decoded_data[:16]
        encrypted_data = decoded_data[16:]
        
        # Mode sans vérification de padding pour compatibilité PHP
        def simple_unpad(data):
            if not data:
                return b''
            padding_length = data[-1]
            # Si le padding est valide, l'appliquer sinon retourner les données telles quelles
            if 1 <= padding_length <= 16:
                return data[:-padding_length]
            return data
        
        # Essayer avec la clé actuelle (HKDF derivee puis brute si echec)
        try:
            try:
                from Crypto.Cipher import AES as CryptoAES
                cipher = CryptoAES.new(self.secret_key, CryptoAES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_data)
                
                # Essayer de décoder avec diverses stratégies de unpad
                try:
                    # 1. Essayer le unpad standard
                    unpadded = simple_unpad(decrypted)
                    result = unpadded.decode('utf-8', errors='ignore')
                    if result:
                        return result
                except Exception:
                    pass
                
                # 2. Essayer sans unpad
                try:
                    result = decrypted.decode('utf-8', errors='ignore')
                    if result:
                        return result
                except Exception:
                    pass
                
                # 3. Essayer jusqu'au premier null byte
                try:
                    null_pos = decrypted.find(b'\0')
                    if null_pos > 0:
                        return decrypted[:null_pos].decode('utf-8', errors='ignore')
                except Exception:
                    pass
            except ImportError:
                pass
            
            # Si PyCrypto n'est pas disponible ou échoue, utiliser cryptography
            try:
                cipher = Cipher(
                    algorithms.AES(self.secret_key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Mêmes stratégies de unpad
                try:
                    unpadded = simple_unpad(decrypted)
                    result = unpadded.decode('utf-8', errors='ignore')
                    if result:
                        return result
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass
        
        # Essayer avec l'ancienne clé (non-hexadécimale)
        if self.old_secret_key:
            try:
                # Utiliser PyCrypto si disponible
                try:
                    from Crypto.Cipher import AES as CryptoAES
                    cipher = CryptoAES.new(self.old_key_bytes, CryptoAES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(encrypted_data)
                    
                    # Mêmes stratégies de unpad
                    try:
                        unpadded = simple_unpad(decrypted)
                        result = unpadded.decode('utf-8', errors='ignore')
                        if result:
                            return result
                    except Exception:
                        pass
                    
                    try:
                        result = decrypted.decode('utf-8', errors='ignore')
                        if result:
                            return result
                    except Exception:
                        pass
                    
                    try:
                        null_pos = decrypted.find(b'\0')
                        if null_pos > 0:
                            return decrypted[:null_pos].decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                except ImportError:
                    pass
                
                # Si PyCrypto n'est pas disponible ou échoue, utiliser cryptography
                try:
                    cipher = Cipher(
                        algorithms.AES(self.old_key_bytes),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                    
                    # Mêmes stratégies de unpad
                    try:
                        unpadded = simple_unpad(decrypted)
                        result = unpadded.decode('utf-8', errors='ignore')
                        if result:
                            return result
                    except Exception:
                        pass
                except Exception:
                    pass
            except Exception:
                pass
        
        # Si aucune méthode n'a fonctionné
        return ""

    def test_decryption(self, encrypted_password):
        """
        Utilitaire de diagnostic - tente de déchiffrer un mot de passe sans lever d'exception.

        Pratique pour les scripts de test (test_decrypt.py, test_crypto.php) ou pour
        vérifier rapidement si une valeur stockée en BDD est déchiffrable avec la clé actuelle.

        Args:
            encrypted_password (str): Valeur chiffrée à tester.

        Returns:
            str | None: Mot de passe déchiffré, ou None si le déchiffrement échoue.
        """
        try:
            # Ne pas afficher de logs directs
            decrypted = self.decrypt_password(encrypted_password)
            return decrypted
        except Exception as e:
            # Capture l'erreur sans l'afficher directement
            return None
