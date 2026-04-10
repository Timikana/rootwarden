<?php
// adm/incluces/crypto.php
require_once __DIR__ . '/../../auth/verify.php';
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// checkAuth(['2', '3']); // Admin (2) ou Superadmin (3)

// Validation de la clé de chiffrement
$secret_key = getenv('SECRET_KEY');
$old_secret_key = getenv('OLD_SECRET_KEY');

if (empty($secret_key)) {
    throw new Exception("SECRET_KEY n'est pas définie dans les variables d'environnement");
}

// Validation uniquement pour la nouvelle clé
if (strlen($secret_key) !== 32 && strlen($secret_key) !== 64) {
    throw new Exception("SECRET_KEY doit être une chaîne de 32 caractères (128 bits) ou 64 caractères (256 bits)");
}

define('SECRET_KEY', $secret_key);
define('OLD_SECRET_KEY', $old_secret_key);
define('MIN_PASSWORD_LENGTH', 15); // Longueur minimale du mot de passe
define('AES_BLOCK_SIZE', 16); // Taille du bloc AES
define('USE_SODIUM', true); // Utiliser Sodium (libsodium) pour le nouveau chiffrement

/**
 * Vérifie si libsodium est disponible sur le système
 */
function isSodiumAvailable() {
    return function_exists('sodium_crypto_secretbox') && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES');
}

/**
 * Prépare une clé pour les opérations AES-256-CBC (32 bytes).
 * Identique à prepareKeyForSodium() — même logique hex2bin — pour garantir
 * la compatibilité avec Python (encryption.py fait bytes.fromhex() si la clé est hex).
 *
 * @param  string $key  Clé brute ou hexadécimale (32 ou 64 chars).
 * @return string       Clé binaire de 32 bytes exactement.
 */
function prepareKeyForAES(string $key): string {
    if (ctype_xdigit($key)) {
        $bytes = hex2bin($key);
    } else {
        $bytes = $key;
    }
    // AES-256 requiert exactement 32 bytes
    if (strlen($bytes) < 32) {
        $bytes = str_pad($bytes, 32, "\0");
    } elseif (strlen($bytes) > 32) {
        $bytes = substr($bytes, 0, 32);
    }
    return $bytes;
}

/**
 * Convertit une clé hexadécimale en bytes pour sodium
 */
function prepareKeyForSodium($hex_key) {
    // Si la clé est au format hexadécimal, la convertir en bytes 
    // Sodium requiert une clé de 256 bits (32 bytes)
    if (ctype_xdigit($hex_key)) {
        $bytes = hex2bin($hex_key);
        // Ajuster la taille si nécessaire
        if (strlen($bytes) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            // Étendre la clé si elle est trop courte
            $bytes = str_pad($bytes, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, "\0");
        } elseif (strlen($bytes) > SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            // Tronquer si elle est trop longue
            $bytes = substr($bytes, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        }
        return $bytes;
    } else {
        // Si la clé n'est pas hexadécimale, utiliser les premiers caractères
        return substr($hex_key, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }
}

/**
 * Derive une cle via HKDF-SHA256 pour separer les usages (passwords, TOTP, etc.).
 * Compatible avec Python : HKDF(SHA256, length=32, salt=None, info=...).
 *
 * @param string $keyMaterial Cle brute binaire (32 bytes).
 * @param string $info        Label d'usage ('rootwarden-aes', 'rootwarden-totp').
 * @return string             Cle derivee de 32 bytes.
 */
function deriveKey(string $keyMaterial, string $info): string {
    return hash_hkdf('sha256', $keyMaterial, 32, $info);
}

/**
 * Ajoute un padding PKCS7.
 * Utilisé pour l'ancienne méthode AES.
 */
function pkcs7_pad($data, $block_size = AES_BLOCK_SIZE) {
    $padding = $block_size - (strlen($data) % $block_size);
    return $data . str_repeat(chr($padding), $padding);
}

/**
 * Supprime le padding PKCS7 avec validation stricte.
 * Utilisé pour l'ancienne méthode AES.
 */
function pkcs7_unpad(string $data): string {
    if ($data === '') return '';
    $len     = strlen($data);
    $padding = ord($data[$len - 1]);
    // Validation : padding entre 1 et 16, et tous les octets de padding identiques
    if ($padding < 1 || $padding > AES_BLOCK_SIZE || $padding > $len) {
        throw new Exception("Padding PKCS7 invalide");
    }
    for ($i = $len - $padding; $i < $len; $i++) {
        if (ord($data[$i]) !== $padding) {
            throw new Exception("Padding PKCS7 corrompu");
        }
    }
    return substr($data, 0, -$padding);
}

/**
 * Chiffre un mot de passe avec libsodium ou AES-256-CBC.
 * @param string $password Le mot de passe à chiffrer
 * @param bool $validate Si true, effectue la validation de complexité du mot de passe (par défaut pour les utilisateurs)
 */
function encryptPassword($password, $validate = true) {
    // Validation de la complexité du mot de passe uniquement si demandée
    if ($validate) {
        if (strlen($password) < MIN_PASSWORD_LENGTH) {
            throw new Exception("Le mot de passe doit contenir au moins " . MIN_PASSWORD_LENGTH . " caractères");
        }
        
        // Vérification des critères de complexité individuellement pour un message d'erreur plus précis
        if (!preg_match('/[a-z]/', $password)) {
            throw new Exception("Le mot de passe doit contenir au moins une lettre minuscule");
        }
        if (!preg_match('/[A-Z]/', $password)) {
            throw new Exception("Le mot de passe doit contenir au moins une lettre majuscule");
        }
        if (!preg_match('/[0-9]/', $password)) {
            throw new Exception("Le mot de passe doit contenir au moins un chiffre");
        }
        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            throw new Exception("Le mot de passe doit contenir au moins un caractère spécial");
        }
    }

    if (getenv('USE_BCRYPT') === 'true') {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    // Nouvelle méthode: utiliser libsodium si disponible (cle HKDF derivee)
    if (USE_SODIUM && isSodiumAvailable()) {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            // Cle HKDF derivee pour separer les usages
            $rawKey = prepareKeyForSodium(SECRET_KEY);
            $key = deriveKey($rawKey, 'rootwarden-aes');

            $encrypted = sodium_crypto_secretbox($password, $nonce, $key);

            return 'sodium:' . base64_encode($nonce . $encrypted);
        } catch (Exception $e) {
            error_log("Erreur avec sodium, utilisation d'AES comme fallback: " . $e->getMessage());
        }
    }
    
    // Méthode de secours: AES-256-CBC (cle HKDF derivee)
    $iv = random_bytes(AES_BLOCK_SIZE);
    $padded_password = pkcs7_pad($password);
    $aesKey = deriveKey(prepareKeyForAES(SECRET_KEY), 'rootwarden-aes');
    $encrypted = openssl_encrypt($padded_password, 'AES-256-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
    
    return 'aes:' . base64_encode($iv . $encrypted);
}

/**
 * Déchiffre un mot de passe avec libsodium ou AES-256-CBC.
 */
function decryptPassword($encryptedPassword) {
    // Vérifier si vide
    if (empty($encryptedPassword)) {
        return '';
    }
    
    // Détecter la méthode de chiffrement utilisée
    if (strpos($encryptedPassword, 'sodium:') === 0 && isSodiumAvailable()) {
        // Methode Sodium — essaie cle HKDF derivee puis cle brute (fallback legacy)
        $data = base64_decode(substr($encryptedPassword, 7));
        $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $rawKey = prepareKeyForSodium(SECRET_KEY);
        $hkdfKey = deriveKey($rawKey, 'rootwarden-aes');

        // 1. Essayer cle HKDF derivee
        $decrypted = @sodium_crypto_secretbox_open($ciphertext, $nonce, $hkdfKey);
        if ($decrypted !== false) return $decrypted;

        // 2. Fallback cle brute (donnees chiffrees avant HKDF)
        $decrypted = @sodium_crypto_secretbox_open($ciphertext, $nonce, $rawKey);
        if ($decrypted !== false) return $decrypted;

        throw new Exception("Echec dechiffrement Sodium (HKDF + raw)");
    } else if (strpos($encryptedPassword, 'aes:') === 0) {
        // Méthode AES (préfixée)
        $encryptedPassword = substr($encryptedPassword, 4);
    }
    
    // Méthode AES (ancienne ou préfixée 'aes:')
    try {
        $data = base64_decode($encryptedPassword);
        if (strlen($data) < AES_BLOCK_SIZE) {
            throw new Exception("Les données sont trop courtes pour inclure un IV valide");
        }

        $iv = substr($data, 0, AES_BLOCK_SIZE);
        $encrypted = substr($data, AES_BLOCK_SIZE);
        
        // Essayer : 1. cle HKDF derivee, 2. cle brute (legacy), 3. ancienne cle
        $rawKey = prepareKeyForAES(SECRET_KEY);
        $hkdfKey = deriveKey($rawKey, 'rootwarden-aes');
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $hkdfKey, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $rawKey, OPENSSL_RAW_DATA, $iv);
        }

        if ($decrypted === false && defined('OLD_SECRET_KEY') && !empty(OLD_SECRET_KEY)) {
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', prepareKeyForAES(OLD_SECRET_KEY), OPENSSL_RAW_DATA, $iv);
        }

        if ($decrypted === false) {
            throw new Exception("Échec du déchiffrement AES. Vérifiez la clé et les données chiffrées.");
        }

        return pkcs7_unpad($decrypted);
    } catch (Exception $e) {
        throw $e;
    }
}

/**
 * Génère un mot de passe sécurisé d'une longueur donnée.
 */
function generateSecurePassword($length = MIN_PASSWORD_LENGTH) {
    if ($length < MIN_PASSWORD_LENGTH) {
        throw new Exception("La longueur du mot de passe doit être d'au moins " . MIN_PASSWORD_LENGTH . " caractères.");
    }

    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+[]{}|;:,.<>?/\\';
    $charactersLength = strlen($characters);
    $password = '';

    for ($i = 0; $i < $length; $i++) {
        $password .= $characters[random_int(0, $charactersLength - 1)];
    }

    return $password;
}

/**
 * Valide un mot de passe utilisateur en fonction de son type de stockage.
 *
 * @param string $inputPassword Mot de passe fourni par l'utilisateur.
 * @param string $storedPassword Mot de passe stocké dans la base de données.
 * @param bool $isEncrypted Indique si le mot de passe est chiffré.
 * @return bool
 */
function validatePassword($inputPassword, $storedPassword, $isEncrypted = false) {
    if (password_get_info($storedPassword)['algo'] !== 0) { // Vérifie si c'est bcrypt
        return password_verify($inputPassword, $storedPassword);
    } elseif ($isEncrypted) {
        try {
            $decryptedPassword = decryptPassword($storedPassword);
            return $inputPassword === $decryptedPassword;
        } catch (Exception $e) {
            return false;
        }
    }
    return false;
}

/**
 * Hache un mot de passe avec l'algorithme par défaut de PHP (bcrypt/argon2).
 *
 * @param  string $password  Mot de passe en clair.
 * @return string            Hash calculé.
 */
function hash_password($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Vérifie qu'un mot de passe en clair correspond à un hash PHP.
 *
 * @param  string $password  Mot de passe en clair.
 * @param  string $hash      Hash stocké en BDD.
 * @return bool
 */
function verify_password($password, $hash) {
    return password_verify($password, $hash);
}
