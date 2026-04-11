<?php
/**
 * auth/migrate_totp.php — Migration one-shot des secrets TOTP plaintext → chiffres.
 *
 * Parcourt tous les users avec un totp_secret non-null et sans prefixe "totp:".
 * Chiffre chaque secret et UPDATE en BDD.
 * Acces : superadmin uniquement.
 *
 * Usage : https://localhost:8443/auth/migrate_totp.php
 * Idempotent : ne re-chiffre pas les secrets deja chiffres.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/totp_crypto.php';

checkAuth([ROLE_SUPERADMIN]); // Superadmin uniquement

header('Content-Type: text/plain; charset=utf-8');

echo "=== Migration TOTP secrets (plaintext → chiffre) ===\n\n";

$stmt = $pdo->query("SELECT id, name, totp_secret FROM users WHERE totp_secret IS NOT NULL AND totp_secret != ''");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

$migrated = 0;
$skipped = 0;
$errors = 0;

foreach ($users as $u) {
    $secret = $u['totp_secret'];

    // Deja chiffre — skip
    if (strpos($secret, 'totp:') === 0) {
        echo "[SKIP] {$u['name']} (id={$u['id']}) — deja chiffre\n";
        $skipped++;
        continue;
    }

    // Chiffrer
    $encrypted = encryptTotpSecret($secret);
    if (strpos($encrypted, 'totp:') !== 0) {
        echo "[ERREUR] {$u['name']} (id={$u['id']}) — chiffrement echoue, secret conserve en clair\n";
        $errors++;
        continue;
    }

    // Verifier que le dechiffrement fonctionne AVANT d'ecrire
    $decrypted = decryptTotpSecret($encrypted);
    if ($decrypted !== $secret) {
        echo "[ERREUR] {$u['name']} (id={$u['id']}) — verification echec (decrypt != original), SKIP\n";
        $errors++;
        continue;
    }

    // UPDATE
    $stmtUpdate = $pdo->prepare("UPDATE users SET totp_secret = ? WHERE id = ?");
    $stmtUpdate->execute([$encrypted, $u['id']]);
    echo "[OK] {$u['name']} (id={$u['id']}) — secret chiffre\n";
    $migrated++;
}

echo "\n=== Resultat ===\n";
echo "Migres  : $migrated\n";
echo "Ignores : $skipped (deja chiffres)\n";
echo "Erreurs : $errors\n";
echo "\nTotal users avec TOTP : " . count($users) . "\n";
