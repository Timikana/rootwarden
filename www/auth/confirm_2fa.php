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
 *   - Vérifie le code via OTPHP\TOTP::verify()
 *   - Affiche un message de succès ou d'échec (pas de redirection automatique)
 *
 * @package RootWarden\Auth
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';
require_once '../vendor/autoload.php';
require_once __DIR__ . '/../includes/totp_crypto.php';

use OTPHP\TOTP;

if (!isset($_SESSION['user_id'])) {
    header("Location: auth/login.php");
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

    if ($totp->verify($code)) {
        echo "<h1>" . t('confirm_2fa.success_title') . "</h1>";
        echo "<p>" . t('confirm_2fa.success_msg') . "</p>";
    } else {
        error_log("Code TOTP incorrect pour user " . $_SESSION['user_id']);
        echo "<h1>" . t('confirm_2fa.invalid_title') . "</h1>";
        echo "<p>" . t('confirm_2fa.invalid_msg') . "</p>";
    }
} else {
    header("Location: enable_2fa.php");
    exit();
}
