<?php
/**
 * auth/logout.php
 *
 * Deconnecte l'utilisateur courant :
 *   1. Supprime le token "Se souvenir de moi" de la table remember_tokens
 *   2. Supprime la session active de la table active_sessions
 *   3. Expire le cookie remember_token cote navigateur
 *   4. Detruit la session PHP (session_unset + session_destroy)
 *   5. Redirige vers login.php
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Supprimer le remember_token de la base si le cookie existe
if (isset($_COOKIE['remember_token'])) {
    $parts = explode(':', $_COOKIE['remember_token'], 2);
    if (count($parts) === 2 && ctype_digit((string) $parts[0])) {
        try {
            $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?");
            $stmt->execute([(int) $parts[0]]);
        } catch (\Exception $e) {
            error_log("logout.php: failed to delete remember_token: " . $e->getMessage());
        }
    }
    // Expirer le cookie
    setcookie('remember_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);
}

// Supprimer la session active de la base
if (isset($_SESSION['user_id'])) {
    try {
        $pdo->prepare("DELETE FROM active_sessions WHERE session_id = ?")
            ->execute([session_id()]);
    } catch (\Exception $e) {
        error_log("logout.php: failed to delete active_session: " . $e->getMessage());
    }
}

// Destruction de la session
session_unset();
session_destroy();

header("Location: login.php");
exit();
