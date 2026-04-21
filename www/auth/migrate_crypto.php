#!/usr/bin/env php
<?php
/**
 * migrate_crypto.php - Script de migration du chiffrement des mots de passe
 *
 * Rôle       : Script CLI one-shot à exécuter lors d'une rotation de clé de
 *              chiffrement ou lors d'une migration AES → Sodium. Re-chiffre
 *              tous les mots de passe de la table `users` qui ne sont pas déjà
 *              en format bcrypt ($2y$…).
 *
 * Usage CLI  : php migrate_crypto.php
 *              (depuis le conteneur PHP ou en local avec les variables d'env)
 *
 * Prérequis  :
 *   - db.php correctement configuré (connexion PDO $pdo disponible)
 *   - Variables d'environnement OLD_SECRET_KEY et SECRET_KEY définies
 *   - Sauvegarde de la base de données réalisée avant exécution
 *
 * Dépendances :
 *   - ../db.php : initialise la connexion PDO ($pdo)
 *   - Extension PHP openssl (AES-256-CBC)
 *   - Extension PHP sodium (détection du format sodium:)
 *
 * Variables d'environnement lues :
 *   OLD_SECRET_KEY - Ancienne clé de chiffrement (hex 32/64 chars ou texte 32 chars)
 *   SECRET_KEY     - Nouvelle clé de chiffrement (même format)
 *
 * Formats de chiffrement gérés :
 *   sodium:…  - Déjà migré, ignoré (retourne null)
 *   aes:…     - AES-256-CBC avec préfixe explicite, déchiffré puis re-chiffré
 *   …         - AES-256-CBC ancien format sans préfixe, déchiffré puis re-chiffré
 *   $2y$…     - bcrypt (exclu de la requête SQL, non traité ici)
 *
 * Sécurité   : S'exécute dans une transaction BDD - rollback automatique en cas
 *              d'erreur globale. Les erreurs par ligne sont loggées sans rollback
 *              partiel (la ligne est simplement ignorée).
 *
 * Note       : La migration des machines/serveurs est désactivée (commentée).
 *              Seule la table `users` est traitée.
 */

// Charge la connexion PDO depuis les variables d'environnement DB_*
require_once __DIR__ . '/../db.php';

// Taille d'un bloc AES en octets (16 = 128 bits), utilisée pour l'IV
define('AES_BLOCK_SIZE', 16);

/**
 * Ajoute un padding PKCS7 à un bloc de données.
 *
 * PKCS7 complète les données jusqu'au prochain multiple de $block_size
 * en ajoutant N octets de valeur N (N = nombre d'octets manquants).
 *
 * @param  string $data       Données à padder
 * @param  int    $block_size Taille du bloc (défaut : AES_BLOCK_SIZE = 16)
 * @return string             Données paddées
 */
function pkcs7_pad($data, $block_size = AES_BLOCK_SIZE) {
    $padding = $block_size - (strlen($data) % $block_size);
    return $data . str_repeat(chr($padding), $padding);
}

/**
 * Supprime le padding PKCS7 d'un bloc de données.
 *
 * Lit la valeur du dernier octet (= nombre d'octets de padding) et
 * les retire de la fin de la chaîne.
 *
 * @param  string $data Données paddées
 * @return string       Données sans padding (chaîne vide si $data est vide)
 */
function pkcs7_unpad($data) {
    if (empty($data)) return '';
    $padding = ord($data[strlen($data) - 1]);
    return substr($data, 0, -$padding);
}

/**
 * Prépare une clé brute pour AES-256-CBC (32 octets attendus).
 *
 * Détecte si la clé fournie est une chaîne hexadécimale (32 ou 64 chars hex
 * = 16 ou 32 octets binaires) et la convertit en binaire. Sinon, tronque
 * la clé à 32 caractères (utilisée telle quelle comme clé AES).
 *
 * @param  string $key Clé brute (hex ou texte)
 * @return string      Clé binaire de 16 ou 32 octets prête pour openssl_encrypt
 */
function prepareKey($key) {
    // Clé hexadécimale de 32 chars (= 16 octets AES-128) ou 64 chars (= 32 octets AES-256)
    if (ctype_xdigit($key) && (strlen($key) == 32 || strlen($key) == 64)) {
        return hex2bin($key);
    }

    // Clé texte : utilise les 32 premiers caractères (AES-256 attend 32 octets)
    return substr($key, 0, 32);
}

/**
 * Chiffre une donnée en clair avec AES-256-CBC et retourne le résultat en base64.
 *
 * Format de sortie : base64(IV_16bytes || ciphertext)
 * L'IV est généré aléatoirement à chaque appel (random_bytes = cryptographiquement sûr).
 *
 * @param  string $data Donnée en clair à chiffrer
 * @param  string $key  Clé de chiffrement brute (passée à prepareKey())
 * @return string       Donnée chiffrée encodée en base64
 * @throws Exception    Si openssl_encrypt échoue
 */
function encryptWithKey($data, $key) {
    $prepared_key = prepareKey($key);
    // IV aléatoire de 16 octets (une valeur unique par chiffrement)
    $iv = random_bytes(AES_BLOCK_SIZE);
    $padded    = pkcs7_pad($data);
    $encrypted = openssl_encrypt($padded, 'AES-256-CBC', $prepared_key, OPENSSL_RAW_DATA, $iv);
    if ($encrypted === false) {
        throw new Exception("Erreur d'encryption: " . openssl_error_string());
    }
    // Concatène IV + ciphertext puis encode en base64 pour le stockage BDD
    return base64_encode($iv . $encrypted);
}

/**
 * Déchiffre une donnée chiffrée AES-256-CBC (format base64 avec IV préfixé).
 *
 * Attendu en entrée : base64(IV_16bytes || ciphertext)
 * L'IV est extrait des 16 premiers octets après décodage base64.
 *
 * @param  string $encryptedData Donnée chiffrée en base64 (sans préfixe 'aes:')
 * @param  string $key           Clé de déchiffrement brute (passée à prepareKey())
 * @return string                Donnée déchiffrée en clair
 * @throws Exception             Si les données sont trop courtes ou si openssl_decrypt échoue
 */
function decryptWithKey($encryptedData, $key) {
    $prepared_key = prepareKey($key);
    $data = base64_decode($encryptedData);
    // Vérifie que les données contiennent au moins un IV complet (16 octets)
    if (strlen($data) < AES_BLOCK_SIZE) {
        throw new Exception("Les données sont trop courtes pour contenir un IV valide.");
    }
    // Extraction de l'IV (16 premiers octets) et du ciphertext (reste)
    $iv        = substr($data, 0, AES_BLOCK_SIZE);
    $encrypted = substr($data, AES_BLOCK_SIZE);
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $prepared_key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        throw new Exception("Erreur de déchiffrement: " . openssl_error_string());
    }
    return pkcs7_unpad($decrypted);
}

/**
 * Déchiffre intelligemment une donnée selon son format détecté automatiquement.
 *
 * Formats détectés :
 *   - 'sodium:…' → Données déjà au format Sodium, migration non nécessaire → retourne null
 *   - 'aes:…'    → AES-256-CBC avec préfixe explicite → retire le préfixe et déchiffre
 *   - (aucun)    → Ancien format AES sans préfixe → déchiffre directement
 *
 * @param  string      $encryptedData Donnée chiffrée (avec ou sans préfixe de format)
 * @param  string      $oldKey        Ancienne clé de déchiffrement
 * @return string|null                Donnée déchiffrée, ou null si déjà au format Sodium
 * @throws Exception                  Si le déchiffrement AES échoue
 */
function smartDecrypt($encryptedData, $oldKey) {
    // Détection du préfixe de format pour choisir la stratégie de déchiffrement
    if (strpos($encryptedData, 'sodium:') === 0) {
        echo "  Format détecté: Sodium (préfixé)\n";
        // Données déjà migrées vers Sodium : on les ignore (pas de re-chiffrement AES possible)
        return null;
    } elseif (strpos($encryptedData, 'aes:') === 0) {
        echo "  Format détecté: AES (préfixé)\n";
        // Retire le préfixe 'aes:' (4 chars) avant de décoder le base64
        $base64Data = substr($encryptedData, 4);
        return decryptWithKey($base64Data, $oldKey);
    } else {
        echo "  Format détecté: AES (ancien format sans préfixe)\n";
        // Ancien format : directement un base64 sans préfixe
        return decryptWithKey($encryptedData, $oldKey);
    }
}

// ── Chargement des clés de chiffrement depuis les variables d'environnement ───
// Les valeurs par défaut ne doivent être utilisées qu'en développement local.
$oldKey = getenv('OLD_SECRET_KEY') ?: '';
$newKey = getenv('SECRET_KEY')     ?: '';
if (!$newKey) { die("ERREUR : SECRET_KEY non definie dans les variables d'environnement.\n"); }

echo "Début de la migration des données chiffrées...\n";
// Affichage partiel des clés pour vérification sans exposer les valeurs complètes
echo "Clé actuelle (SECRET_KEY): "     . substr($newKey, 0, 6) . "..." . substr($newKey, -6) . " (" . strlen($newKey) . " caractères)\n";
echo "Ancienne clé (OLD_SECRET_KEY): " . substr($oldKey, 0, 6) . "..." . substr($oldKey, -6) . " (" . strlen($oldKey) . " caractères)\n\n";

try {
    // Toute la migration s'exécute dans une transaction - rollback si erreur globale
    $pdo->beginTransaction();

    // ── Section machines désactivée ───────────────────────────────────────────
    // La migration des machines/serveurs a été désactivée intentionnellement.
    // Le code est conservé commenté à titre de référence pour une future réactivation.
    /*
    // Migration des machines
    $stmt = $pdo->query("SELECT id, name, password, root_password FROM machines");
    $machines = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $machinesCount = 0;
    $skippedCount = 0;

    foreach ($machines as $machine) {
        echo "Traitement de la machine ID : " . $machine['id'] . " (" . $machine['name'] . ")\n";

        try {
            // Déchiffrement avec l'ancienne clé (détection automatique du format)
            echo "  Traitement du mot de passe utilisateur...\n";
            $decryptedPassword = smartDecrypt($machine['password'], $oldKey);
            
            echo "  Traitement du mot de passe root...\n";
            $decryptedRoot = smartDecrypt($machine['root_password'], $oldKey);
            
            // Si l'un des mots de passe est déjà au format Sodium, on saute cette machine
            if ($decryptedPassword === null || $decryptedRoot === null) {
                echo "  -> Un des mots de passe est déjà au format Sodium, on saute cette machine.\n";
                $skippedCount++;
                continue;
            }

            // Rechiffrement avec la nouvelle clé
            $newEncryptedPassword = encryptWithKey($decryptedPassword, $newKey);
            $newEncryptedRoot = encryptWithKey($decryptedRoot, $newKey);

            // Mise à jour de l'enregistrement dans la base
            $updateStmt = $pdo->prepare("UPDATE machines SET password = ?, root_password = ? WHERE id = ?");
            $updateStmt->execute([$newEncryptedPassword, $newEncryptedRoot, $machine['id']]);
            $machinesCount++;
            echo "  -> Mise à jour réussie.\n";
        } catch (Exception $e) {
            echo "  -> ⚠️ Erreur pour l'ID " . $machine['id'] . " : " . $e->getMessage() . "\n";
            echo "  -> Détails supplémentaires:\n";
            echo "     • Format du mot de passe: " . (strlen($machine['password']) > 30 ? substr($machine['password'], 0, 30) . "..." : $machine['password']) . "\n";
            echo "     • Format du mot de passe root: " . (strlen($machine['root_password']) > 30 ? substr($machine['root_password'], 0, 30) . "..." : $machine['root_password']) . "\n";
        }
    }
    */
    
    echo "Migration des mots de passe des utilisateurs uniquement.\n\n";

    // ── Migration de la table users ───────────────────────────────────────────
    // Sélectionne uniquement les utilisateurs dont le mot de passe n'est PAS
    // déjà un hash bcrypt (préfixe '$2y$') - les hash bcrypt n'ont pas besoin
    // d'être re-chiffrés (ils ne sont pas chiffrés AES, juste hachés).
    $stmt = $pdo->query("SELECT id, name, password FROM users WHERE password NOT LIKE '\$2y\$%'");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Compteurs pour le rapport final
    $usersCount        = 0; // Utilisateurs migrés avec succès
    $skippedUsersCount = 0; // Utilisateurs ignorés (déjà format Sodium)

    foreach ($users as $user) {
        echo "Traitement de l'utilisateur ID : " . $user['id'] . " (" . $user['name'] . ")\n";

        try {
            // Étape 1 : Déchiffrement avec l'ancienne clé (détection auto du format)
            $decryptedPassword = smartDecrypt($user['password'], $oldKey);

            // Si smartDecrypt retourne null → données déjà au format Sodium, ignorées
            if ($decryptedPassword === null) {
                echo "  -> Mot de passe déjà au format Sodium, on saute cet utilisateur.\n";
                $skippedUsersCount++;
                continue;
            }

            // Étape 2 : Re-chiffrement avec la nouvelle clé (AES-256-CBC + IV aléatoire)
            $newEncryptedPassword = encryptWithKey($decryptedPassword, $newKey);

            // Étape 3 : Mise à jour en BDD du mot de passe re-chiffré
            $updateStmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
            $updateStmt->execute([$newEncryptedPassword, $user['id']]);
            $usersCount++;
            echo "  -> Mise à jour réussie.\n";
        } catch (Exception $e) {
            // L'erreur est loggée mais n'interrompt pas les autres utilisateurs
            echo "  -> ⚠️ Erreur pour l'ID " . $user['id'] . " : " . $e->getMessage() . "\n";
            // Affichage partiel du mot de passe pour faciliter le diagnostic
            echo "  -> Format du mot de passe: " . (strlen($user['password']) > 30 ? substr($user['password'], 0, 30) . "..." : $user['password']) . "\n";
        }
    }

    // Validation de la transaction - persiste toutes les mises à jour
    $pdo->commit();

    echo "\n=== Migration terminée avec succès ! ===\n";
    echo "Utilisateurs mis à jour : "                          . $usersCount . "\n";
    echo "Utilisateurs ignorés (déjà au format Sodium) : "    . $skippedUsersCount . "\n";

} catch (Exception $e) {
    // En cas d'erreur globale (ex. : connexion BDD perdue), annule tout
    $pdo->rollBack();
    echo "Erreur lors de la migration : " . $e->getMessage() . "\n";
}
