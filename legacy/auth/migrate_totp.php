<?php
/**
 * auth/migrate_totp.php - Migration one-shot des secrets TOTP plaintext → chiffres.
 *
 * Parcourt tous les users avec un totp_secret non-null et sans prefixe "totp:".
 * Chiffre chaque secret et UPDATE en BDD.
 * Idempotent : ne re-chiffre pas les secrets deja chiffres.
 *
 * Acces : CLI STRICTEMENT. Toute requete HTTP est refusee (403).
 *         Pourquoi le refus pur plutot qu'un checkAuth + POST/CSRF :
 *           1. La version precedente declenchait une ecriture en masse sur la
 *              table users sur un simple GET. Aucun jeton CSRF n'etait verifie :
 *              une image ou un lien sur une page tierce suffisait a lancer la
 *              migration dans la session d'un superadmin connecte.
 *           2. Le script n'a aucune UI (sortie texte brut) : lui ajouter un
 *              ecran de confirmation POST + CSRF reviendrait a construire un
 *              formulaire pour une operation lancee une seule fois, a
 *              l'installation d'une version.
 *           3. auth/.htaccess refuse deja ce fichier en HTTP - le mode web
 *              documente ne fonctionnait donc plus. On aligne le code sur la
 *              realite operationnelle au lieu de maintenir un chemin mort.
 *         Cette garde PHP double le blocage Apache et tient meme si la conf
 *         Apache change ou si AllowOverride est retire.
 *
 * Usage : docker exec rootwarden_php php /var/www/html/auth/migrate_totp.php
 */

// ── Garde CLI ────────────────────────────────────────────────────────────────
// Placee AVANT tout require : une requete HTTP ne doit ouvrir ni connexion BDD
// ni charger les cles de chiffrement.
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

// En CLI il n'y a ni session ni utilisateur : le controle d'acces est celui du
// shell sur le conteneur. On ne charge donc pas auth/verify.php (checkAuth y
// redirigerait vers /auth/login.php et tuerait le script).
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/totp_crypto.php';

echo "=== Migration TOTP secrets (plaintext → chiffre) ===\n\n";

$stmt = $pdo->query("SELECT id, name, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ''");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$migrated = 0;
$skipped = 0;
$errors = 0;

foreach ($users as $u) {
    $secret = $u['totp_secret'];

    // Deja chiffre - skip
    if (strpos($secret, 'totp:') === 0) {
        echo "[SKIP] {$u['name']} (id={$u['id']}) - deja chiffre\n";
        $skipped++;
        continue;
    }

    // Chiffrer
    $encrypted = encryptTotpSecret($secret);
    if (strpos($encrypted, 'totp:') !== 0) {
        echo "[ERREUR] {$u['name']} (id={$u['id']}) - chiffrement echoue, secret conserve en clair\n";
        $errors++;
        continue;
    }

    // Verifier que le dechiffrement fonctionne AVANT d'ecrire
    $decrypted = decryptTotpSecret($encrypted);
    if ($decrypted !== $secret) {
        echo "[ERREUR] {$u['name']} (id={$u['id']}) - verification echec (decrypt != original), SKIP\n";
        $errors++;
        continue;
    }

    // UPDATE
    $stmtUpdate = $pdo->prepare("UPDATE users SET totp_secret = ? WHERE id = ?");
    $stmtUpdate->execute([$encrypted, $u['id']]);
    echo "[OK] {$u['name']} (id={$u['id']}) - secret chiffre\n";
    $migrated++;
}

echo "\n=== Resultat ===\n";
echo "Migres  : $migrated\n";
echo "Ignores : $skipped (deja chiffres)\n";
echo "Erreurs : $errors\n";
echo "\nTotal users avec TOTP : " . count($users) . "\n";
