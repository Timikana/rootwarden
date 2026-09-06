<?php
/**
 * auth/confirm_2fa.php
 *
 * Endpoint de confirmation du code TOTP après activation initiale du 2FA.
 * Requiert un utilisateur connecté ($_SESSION['user_id']) et un code TOTP valide.
 * Ce fichier est utilisé en complément de enable_2fa.php pour valider
 * que l'utilisateur a bien enregistré son secret dans son application d'authentification.
 *
 * Flux :
 *   - Accepte uniquement les requêtes POST avec le champ '2fa_code'
 *   - Récupère le secret TOTP de l'utilisateur connecté en BDD
 *   - Applique les mêmes protections que verify_2fa.php (rate-limit session + IP,
 *     anti-rejeu du dernier code, tolérance d'une période)
 *   - Vérifie le code via OTPHP\TOTP::verify($code, null, 1)
 *   - Affiche un message de succès ou d'échec (pas de redirection automatique)
 *
 * @package RootWarden\Auth
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/functions.php';
require_once '../vendor/autoload.php';
require_once __DIR__ . '/../includes/totp_crypto.php';
// t() est utilise pour tous les messages de cette page : sans lang.php, le
// premier message d'erreur provoquait un fatal "undefined function".
require_once __DIR__ . '/../includes/lang.php';

use OTPHP\TOTP;

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['2fa_code'])) {
    checkCsrfToken();
    $code = $_POST['2fa_code'];

    // Récupérer le secret TOTP de l'utilisateur
    $stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || empty($user['totp_secret'])) {
        die(t('confirm_2fa.no_secret'));
    }

    // Dechiffrer le secret TOTP (retrocompatible plaintext legacy)
    $totpPlain = decryptTotpSecret($user['totp_secret']);
    $totp = TOTP::create($totpPlain);

    // Meme protection que verify_2fa.php : sans elle, cet endpoint offrait un
    // chemin de brute-force TOTP non limite (6 chiffres = 10^6 combinaisons).
    // Rate limiting : max 5 tentatives / minute par SESSION + max 10 / 10 min par IP.
    // Le compteur IP (table login_attempts, step = '2fa') resiste a la rotation
    // de session, contrairement au seul compteur en session.
    if (!isset($_SESSION['2fa_attempts'])) $_SESSION['2fa_attempts'] = [];
    $_SESSION['2fa_attempts'] = array_filter($_SESSION['2fa_attempts'], fn($t) => $t > time() - 60);
    $_SESSION['2fa_attempts'][] = time();

    $codeHash = hash('sha256', $code . floor(time() / 30));

    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ipBlocked = false;
    $attemptId = null; // id de la ligne login_attempts, repassee a success=1 si OK
    try {
        $stmtIp = $pdo->prepare(
            "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? "
            . "AND attempted_at > (NOW() - INTERVAL 10 MINUTE) AND step = '2fa' AND success = 0"
        );
        $stmtIp->execute([$clientIp]);
        $ipBlocked = ((int)$stmtIp->fetchColumn()) >= 10;
        // On enregistre la tentative en cours (success=0, on update si OK plus bas)
        $pdo->prepare(
            "INSERT INTO login_attempts (ip_address, username, success, step, attempted_at) "
            . "VALUES (?, ?, 0, '2fa', NOW())"
        )->execute([$clientIp, $_SESSION['username'] ?? 'unknown']);
        $attemptId = (int)$pdo->lastInsertId();
    } catch (\Throwable $_e) {
        // Colonne 'step' absente (migration 046 pas appliquee) : on continue avec
        // le rate-limit session uniquement. Pas bloquant pour l'enrolement.
    }

    if ($ipBlocked || count($_SESSION['2fa_attempts']) > 5) {
        error_log("Rate-limit 2FA (confirm) pour user " . $_SESSION['user_id']);
        echo "<h1>" . t('confirm_2fa.invalid_title') . "</h1>";
        echo "<p>" . t('2fa.error_rate_limit') . "</p>";
    } elseif (isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash) {
        // Anti-rejeu : un code deja consomme dans la meme fenetre de 30 s est refuse
        error_log("Rejeu de code TOTP (confirm) pour user " . $_SESSION['user_id']);
        echo "<h1>" . t('confirm_2fa.invalid_title') . "</h1>";
        echo "<p>" . t('2fa.error_reused') . "</p>";
    } elseif ($totp->verify($code, null, 1)) { // null = heure actuelle, 1 = tolerance d'une periode
        // Marquer le code comme consomme avant toute redirection (anti-rejeu)
        $_SESSION['last_totp_hash'] = $codeHash;
        unset($_SESSION['2fa_attempts']);

        // Repasser la tentative a success=1 : sinon une confirmation REUSSIE
        // compterait comme un echec dans le compteur IP et bloquerait des
        // utilisateurs legitimes derriere une meme IP/NAT.
        if ($attemptId) {
            try {
                $pdo->prepare("UPDATE login_attempts SET success = 1 WHERE id = ?")->execute([$attemptId]);
            } catch (\Throwable $_e) {}
        }

        // Charger les donnees user completes et initialiser la session
        $stmtUser = $pdo->prepare("SELECT id, name, role_id FROM users WHERE id = ?");
        $stmtUser->execute([$_SESSION['user_id']]);
        $fullUser = $stmtUser->fetch(PDO::FETCH_ASSOC);
        if ($fullUser) {
            initializeUserSession($fullUser);
        }
        // Rediriger vers le dashboard
        header("Location: /index.php");
        exit();
    } else {
        error_log("Code TOTP incorrect pour user " . $_SESSION['user_id']);
        echo "<h1>" . t('confirm_2fa.invalid_title') . "</h1>";
        echo "<p>" . t('confirm_2fa.invalid_msg') . "</p>";
    }
} else {
    header("Location: enable_2fa.php");
    exit();
}
