<?php

namespace App\Support;

/**
 * Chiffrement et dechiffrement des secrets TOTP stockes en base.
 *
 * Portage FIDELE de legacy/includes/totp_crypto.php : le meme secret doit
 * pouvoir etre lu par les deux frontends pendant toute la migration. Toute
 * divergence ici rend un compte inaccessible sur l'une des deux cibles.
 *
 * Formats reconnus, dans l'ordre :
 *   totp:sodium:base64(nonce + chiffre)   — courant
 *   totp:gcm:base64(iv[12] + tag[16] + chiffre)
 *   totp:aes:base64(iv[16] + chiffre)     — CBC non authentifie, LECTURE SEULE
 *   (sans prefixe)                        — clair, historique
 *
 * La cle vient de SECRET_KEY, partagee avec le backend Python. Elle est lue
 * dans config/rootwarden.php et non par un env() direct : hors de config/,
 * un env() rend null des le premier config:cache.
 */
class TotpCrypto
{
    /** Etiquette HKDF — doit rester identique au legacy, sinon la cle differe. */
    private const HKDF_INFO = 'rootwarden-totp';

    /**
     * Chiffre un secret TOTP pour la base.
     *
     * MIROIR EXACT de `encryptTotpSecret()` (`legacy/includes/totp_crypto.php:18`),
     * y compris l'ordre des moteurs : sodium d'abord, AES-256-GCM en repli. Un
     * blob ecrit ici doit rester lisible par l'ancien portail pendant toute la
     * migration — les deux frontends partagent la base, et un format divergent
     * d'un octet rendrait le compte inaccessible d'un cote **sans le moindre
     * message d'erreur**. C'est ce qui rend l'enrolement le sous-lot le plus
     * risque, et c'est pourquoi l'execution CROISEE est mesuree
     * (`tests/e2e/go-auth-totp-croise.mjs`).
     *
     * FAIL-CLOSED comme le legacy : sans cle, ou si le chiffrement echoue, on
     * leve. Avant son correctif A02-04, le legacy rendait le secret EN CLAIR
     * quand `SECRET_KEY` manquait — un secret 2FA lisible par tout acces en
     * lecture a la base. On ne reintroduit pas ce repli.
     *
     * @throws \RuntimeException  si la cle manque ou si le chiffrement echoue
     */
    public static function chiffre(string $secret): string
    {
        if ($secret === '') {
            return '';
        }

        $cleHex = (string) config('rootwarden.secret_key', '');
        if ($cleHex === '') {
            throw new \RuntimeException(
                'SECRET_KEY indisponible : chiffrement TOTP impossible.'
            );
        }

        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cle   = hash_hkdf(
                'sha256',
                self::cleBrute($cleHex, SODIUM_CRYPTO_SECRETBOX_KEYBYTES),
                32,
                self::HKDF_INFO,
            );

            return 'totp:sodium:' . base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, $cle));
        }

        $cle     = hash_hkdf('sha256', self::cleBrute($cleHex, 32), 32, self::HKDF_INFO);
        $iv      = random_bytes(12);
        $tag     = '';
        $chiffre = openssl_encrypt($secret, 'AES-256-GCM', $cle, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        if ($chiffre === false || strlen($tag) !== 16) {
            throw new \RuntimeException('Chiffrement TOTP echoue (AES-256-GCM).');
        }

        return 'totp:gcm:' . base64_encode($iv . $tag . $chiffre);
    }

    /**
     * Rend le secret TOTP en clair (base32), ou une chaine vide si le
     * dechiffrement echoue. Fail-closed : on ne rend jamais un blob chiffre
     * tel quel, ce qui ferait echouer toute verification en silence.
     */
    public static function dechiffre(?string $valeur): string
    {
        if ($valeur === null || $valeur === '') {
            return '';
        }

        // Historique : secret stocke en clair, sans prefixe.
        if (! str_starts_with($valeur, 'totp:')) {
            return $valeur;
        }

        $cle = (string) config('rootwarden.secret_key', '');
        if ($cle === '') {
            return '';
        }

        if (str_starts_with($valeur, 'totp:sodium:')) {
            return self::dechiffreSodium(substr($valeur, strlen('totp:sodium:')), $cle);
        }
        if (str_starts_with($valeur, 'totp:gcm:')) {
            return self::dechiffreGcm(substr($valeur, strlen('totp:gcm:')), $cle);
        }
        if (str_starts_with($valeur, 'totp:aes:')) {
            return self::dechiffreCbc(substr($valeur, strlen('totp:aes:')), $cle);
        }

        // Prefixe inconnu : vide par securite, jamais la valeur brute.
        return '';
    }

    /** Cle brute de n octets, derivee de SECRET_KEY hexadecimale. */
    private static function cleBrute(string $cleHex, int $octets): string
    {
        $brut = @hex2bin($cleHex);
        if ($brut === false) {
            $brut = '';
        }
        $brut = substr($brut, 0, $octets);

        return strlen($brut) < $octets ? str_pad($brut, $octets, "\0") : $brut;
    }

    private static function dechiffreSodium(string $b64, string $cleHex): string
    {
        $donnees = base64_decode($b64, true);
        if ($donnees === false || strlen($donnees) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return '';
        }

        $nonce   = substr($donnees, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $chiffre = substr($donnees, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $brute   = self::cleBrute($cleHex, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

        // Cle derivee HKDF d'abord, puis cle brute : des secrets anterieurs a
        // l'introduction du HKDF existent encore en base.
        foreach ([hash_hkdf('sha256', $brute, 32, self::HKDF_INFO), $brute] as $cle) {
            $clair = @sodium_crypto_secretbox_open($chiffre, $nonce, $cle);
            if ($clair !== false) {
                return $clair;
            }
        }

        return '';
    }

    private static function dechiffreGcm(string $b64, string $cleHex): string
    {
        $donnees = base64_decode($b64, true);
        if ($donnees === false || strlen($donnees) <= 28) {
            return '';
        }

        $iv      = substr($donnees, 0, 12);
        $tag     = substr($donnees, 12, 16);
        $chiffre = substr($donnees, 28);
        $cle     = hash_hkdf('sha256', self::cleBrute($cleHex, 32), 32, self::HKDF_INFO);

        $clair = openssl_decrypt($chiffre, 'AES-256-GCM', $cle, OPENSSL_RAW_DATA, $iv, $tag);

        return $clair === false ? '' : $clair;
    }

    /** CBC non authentifie : historique, lecture seule, jamais en ecriture. */
    private static function dechiffreCbc(string $b64, string $cleHex): string
    {
        $donnees = base64_decode($b64, true);
        if ($donnees === false || strlen($donnees) <= 16) {
            return '';
        }

        $iv      = substr($donnees, 0, 16);
        $chiffre = substr($donnees, 16);
        $brute   = self::cleBrute($cleHex, 32);

        foreach ([hash_hkdf('sha256', $brute, 32, self::HKDF_INFO), $brute] as $cle) {
            $clair = openssl_decrypt($chiffre, 'AES-256-CBC', $cle, OPENSSL_RAW_DATA, $iv);
            if ($clair !== false) {
                return $clair;
            }
        }

        return '';
    }
}
