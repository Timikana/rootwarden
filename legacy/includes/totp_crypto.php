<?php
/**
 * includes/totp_crypto.php - Chiffrement/dechiffrement des secrets TOTP.
 *
 * Approche retrocompatible :
 *   - encryptTotpSecret() retourne "totp:" + chiffre (sodium ou AES)
 *   - decryptTotpSecret() detecte le prefixe "totp:" et dechiffre,
 *     sinon retourne la valeur telle quelle (plaintext legacy)
 *
 * Utilise la meme SECRET_KEY que le chiffrement des mots de passe machines.
 */

/**
 * Chiffre un secret TOTP.
 * @param string $secret Le secret TOTP en clair (base32)
 * @return string Le secret chiffre avec prefixe "totp:"
 */
function encryptTotpSecret(string $secret): string
{
    if (empty($secret)) return '';

    $secretKey = getenv('SECRET_KEY');
    if (empty($secretKey)) {
        // Patch A02-04 (OWASP A02) : FAIL-CLOSED. Avant ce patch, si la
        // SECRET_KEY etait absente / vide, on retournait le secret TOTP en
        // CLAIR -> stockage silencieux d'un secret 2FA en clair en BDD,
        // utilisable directement par n'importe quel acces lecture DB.
        // Desormais on leve une exception : aucun secret TOTP ne peut
        // etre ecrit sans cle de chiffrement.
        error_log("[RootWarden] CRITIQUE: SECRET_KEY absente - encryptTotpSecret refuse fail-closed");
        throw new \RuntimeException(
            'SECRET_KEY indisponible : chiffrement TOTP impossible. '
            . 'Configurez SECRET_KEY dans srv-docker.env avant tout enrollment 2FA.'
        );
    }

    // Sodium (prioritaire) - cle HKDF derivee avec info label "rootwarden-totp"
    if (function_exists('sodium_crypto_secretbox')) {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $rawKey = substr(hex2bin($secretKey), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
            if (strlen($rawKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                $rawKey = str_pad($rawKey, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, "\0");
            }
            $key = hash_hkdf('sha256', $rawKey, 32, 'rootwarden-totp');
            $encrypted = sodium_crypto_secretbox($secret, $nonce, $key);
            return 'totp:sodium:' . base64_encode($nonce . $encrypted);
        } catch (Exception $e) {
            error_log("[RootWarden] TOTP sodium encrypt failed: " . $e->getMessage());
        }
    }

    // AES-256-GCM (fallback AEAD) - cle HKDF derivee.
    // Patch A02 : avant, le fallback etait AES-256-CBC SANS authentification
    // (pas d'HMAC/AEAD) -> aucune integrite sur le secret TOTP stocke,
    // incoherent avec l'AES-GCM utilise pour les mots de passe machines. GCM
    // fournit le tag d'authentification. (Le dechiffrement reste retrocompatible
    // avec les anciens blobs `totp:aes:` CBC, cf. decryptTotpSecret.)
    $rawKey = substr(hex2bin($secretKey), 0, 32);
    if (strlen($rawKey) < 32) $rawKey = str_pad($rawKey, 32, "\0");
    $key = hash_hkdf('sha256', $rawKey, 32, 'rootwarden-totp');
    $iv = random_bytes(12);
    $tag = '';
    $encrypted = openssl_encrypt($secret, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($encrypted === false || strlen($tag) !== 16) {
        // Patch A02-04 : FAIL-CLOSED, plus de fallback plaintext.
        error_log("[RootWarden] CRITIQUE: TOTP AES-GCM encrypt failed - refus fail-closed");
        throw new \RuntimeException(
            'Chiffrement TOTP echoue (openssl_encrypt AES-256-GCM). '
            . 'Verifiez la configuration cryptographique.'
        );
    }
    return 'totp:gcm:' . base64_encode($iv . $tag . $encrypted);
}

/**
 * Dechiffre un secret TOTP.
 * Retrocompatible : si pas de prefixe "totp:", retourne tel quel (plaintext legacy).
 * @param string $value La valeur depuis la BDD
 * @return string Le secret TOTP en clair (base32)
 */
function decryptTotpSecret(string $value): string
{
    if (empty($value)) return '';

    // Plaintext legacy - pas de prefixe "totp:"
    if (strpos($value, 'totp:') !== 0) {
        return $value;
    }

    $secretKey = getenv('SECRET_KEY');
    if (empty($secretKey)) {
        error_log("[RootWarden] SECRET_KEY absente - impossible de dechiffrer TOTP");
        return '';
    }

    // totp:sodium:base64(nonce + ciphertext)
    if (strpos($value, 'totp:sodium:') === 0) {
        $data = base64_decode(substr($value, strlen('totp:sodium:')));
        if ($data === false || strlen($data) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            error_log("[RootWarden] TOTP sodium decode failed");
            return '';
        }
        $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $rawKey = substr(hex2bin($secretKey), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        if (strlen($rawKey) < SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            $rawKey = str_pad($rawKey, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, "\0");
        }
        // Essaie cle HKDF derivee puis cle brute (fallback pre-HKDF)
        $hkdfKey = hash_hkdf('sha256', $rawKey, 32, 'rootwarden-totp');
        $decrypted = @sodium_crypto_secretbox_open($ciphertext, $nonce, $hkdfKey);
        if ($decrypted !== false) return $decrypted;
        $decrypted = @sodium_crypto_secretbox_open($ciphertext, $nonce, $rawKey);
        if ($decrypted !== false) return $decrypted;
        error_log("[RootWarden] TOTP sodium decrypt failed (HKDF + raw)");
        return '';
    }

    // totp:gcm:base64(iv[12] + tag[16] + ciphertext) - format AEAD courant
    if (strpos($value, 'totp:gcm:') === 0) {
        $data = base64_decode(substr($value, strlen('totp:gcm:')));
        if ($data === false || strlen($data) <= 28) {
            error_log("[RootWarden] TOTP GCM decode failed");
            return '';
        }
        $iv  = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ciphertext = substr($data, 28);
        $rawKey = substr(hex2bin($secretKey), 0, 32);
        if (strlen($rawKey) < 32) $rawKey = str_pad($rawKey, 32, "\0");
        $hkdfKey = hash_hkdf('sha256', $rawKey, 32, 'rootwarden-totp');
        $decrypted = openssl_decrypt($ciphertext, 'AES-256-GCM', $hkdfKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            error_log("[RootWarden] TOTP GCM decrypt failed (tag invalide)");
            return '';
        }
        return $decrypted;
    }

    // totp:aes:base64(iv + ciphertext) - LEGACY CBC non authentifie (lecture seule)
    if (strpos($value, 'totp:aes:') === 0) {
        $data = base64_decode(substr($value, strlen('totp:aes:')));
        if ($data === false || strlen($data) <= 16) {
            error_log("[RootWarden] TOTP AES decode failed");
            return '';
        }
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $rawKey = substr(hex2bin($secretKey), 0, 32);
        if (strlen($rawKey) < 32) $rawKey = str_pad($rawKey, 32, "\0");
        // Essaie cle HKDF derivee puis cle brute
        $hkdfKey = hash_hkdf('sha256', $rawKey, 32, 'rootwarden-totp');
        $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $hkdfKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $rawKey, OPENSSL_RAW_DATA, $iv);
        }
        if ($decrypted === false) {
            error_log("[RootWarden] TOTP AES decrypt failed (HKDF + raw)");
            return '';
        }
        return $decrypted;
    }

    // Prefixe inconnu - retourner vide par securite
    error_log("[RootWarden] TOTP unknown prefix: " . substr($value, 0, 20));
    return '';
}
