<?php
// auth/functions.php

/**
 * Détruit la session courante et supprime le cookie remember_token.
 * Crée ensuite une nouvelle session vide. À appeler lors d'une déconnexion
 * ou d'une invalidation de session.
 */
function resetSession(): void {
    // Supprimer le cookie avant de détruire la session
    setcookie('remember_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    $_SESSION = [];
    session_destroy();
    session_start();
}

/**
 * Initialise les variables de session après une authentification réussie.
 * Régénère l'ID de session (protection contre la fixation de session),
 * génère un nouveau jeton CSRF et charge les permissions depuis la BDD.
 *
 * @param array $user  Ligne de la table `users` avec au moins : id, name, role_id.
 */
function initializeUserSession(array $user): void {
    global $pdo;

    $_SESSION['user_id']  = (int) ($user['id'] ?? 0);
    $_SESSION['username'] = $user['name'] ?? t('common.guest');
    $_SESSION['role_id']  = (int) ($user['role_id'] ?? 1);

    // Régénérer l'ID de session pour prévenir la fixation de session
    session_regenerate_id(true);

    // Nouveau jeton CSRF
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    $stmt = $pdo->prepare("SELECT * FROM permissions WHERE user_id = ?");
    $stmt->execute([$user['id']]);
    $permissions = $stmt->fetch(PDO::FETCH_ASSOC);

    $_SESSION['permissions'] = $permissions ?: [
        'can_deploy_keys'         => 0,
        'can_update_linux'        => 0,
        'can_manage_iptables'     => 0,
        'can_admin_portal'        => 0,
        'can_scan_cve'            => 0,
        'can_manage_remote_users' => 0,
        'can_manage_platform_key' => 0,
        'can_view_compliance'     => 0,
        'can_manage_backups'      => 0,
        'can_schedule_cve'        => 0,
        'can_manage_fail2ban'     => 0,
        'can_manage_services'    => 0,
    ];
}

/**
 * Tente de restaurer la session depuis le cookie "remember_token".
 * Format attendu : "user_id:token" (user_id doit être un entier positif).
 */
function restoreSessionFromToken(): bool {
    global $pdo;

    if (isset($_SESSION['user_id']) || !isset($_COOKIE['remember_token'])) {
        return false;
    }

    $parts = explode(':', $_COOKIE['remember_token'], 2);
    if (count($parts) !== 2) {
        setcookie('remember_token', '', time() - 3600, '/');
        return false;
    }

    [$uid, $token] = $parts;

    // Validation stricte : uid doit être un entier positif
    if (!ctype_digit((string) $uid) || (int) $uid <= 0) {
        setcookie('remember_token', '', time() - 3600, '/');
        return false;
    }

    $uid = (int) $uid;

    $stmt = $pdo->prepare("SELECT token_hash, expires_at FROM remember_tokens WHERE user_id = ?");
    $stmt->execute([$uid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($token, $row['token_hash']) || strtotime($row['expires_at']) <= time()) {
        setcookie('remember_token', '', time() - 3600, '/');
        return false;
    }

    $stmt = $pdo->prepare("SELECT id, name, role_id FROM users WHERE id = ?");
    $stmt->execute([$uid]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        resetSession();
        return false;
    }

    initializeUserSession($user);
    return true;
}

/**
 * Vérifie que le jeton CSRF du POST correspond à celui de la session.
 * Termine le script avec HTTP 403 si les jetons sont absents ou différents.
 * À appeler en tête de tout endpoint POST sensible.
 */
function checkCsrfToken(): void {
    if (empty($_SESSION['csrf_token'])) {
        http_response_code(403);
        die(t('common.csrf_no_session'));
    }
    if (empty($_POST['csrf_token'])) {
        http_response_code(403);
        die(t('common.csrf_no_request'));
    }
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die(t('common.csrf_invalid'));
    }
}

/**
 * Retourne le role_id d'un utilisateur à partir de son nom.
 *
 * @param  string $userName  Nom d'utilisateur (colonne `name` de la table `users`).
 * @return mixed             role_id (int) ou false si l'utilisateur n'existe pas.
 */
function getUserRole(string $userName): mixed {
    global $pdo;
    $stmt = $pdo->prepare("SELECT role_id FROM users WHERE name = ?");
    $stmt->execute([$userName]);
    return $stmt->fetchColumn();
}
