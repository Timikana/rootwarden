<?php
// auth/verify.php

// ── Mode Debug ───────────────────────────────────────────────────────────────
// DEBUG_MODE=true (variable d'environnement) active :
//   • error_reporting(E_ALL) + display_errors=On
//   • log_errors=On avec affichage dans la réponse HTTP
// ⚠️  NE JAMAIS activer en production : expose des traces et données sensibles.
if (getenv('DEBUG_MODE') === 'true') {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    ini_set('log_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Session timeout (défaut 30 min, configurable via SESSION_TIMEOUT en minutes)
$sessionTimeout = ((int)(getenv('SESSION_TIMEOUT') ?: 30)) * 60;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $sessionTimeout) {
    session_unset();
    session_destroy();
    header("Location: /auth/login.php?expired=1");
    exit();
}
$_SESSION['last_activity'] = time();

// Bloquer l'acces si le 2FA n'a pas ete verifie (empeche le bypass du redirect)
if (!empty($_SESSION['2fa_required'])) {
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if (!in_array($currentPage, ['verify_2fa.php', 'enable_2fa.php', 'login.php', 'logout.php'])) {
        header("Location: /auth/verify_2fa.php");
        exit();
    }
}

// Politique d'expiration des mots de passe (per-user override supporté)
// password_expiry_override : NULL = global, 0 = exempt, N = jours custom
$globalExpiryDays = (int)(getenv('PASSWORD_EXPIRY_DAYS') ?: 0);
$passwordWarnDays = (int)(getenv('PASSWORD_WARN_DAYS') ?: 14);
if (isset($_SESSION['user_id'])) {
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if (!in_array($currentPage, ['profile.php', 'login.php', 'verify_2fa.php', 'enable_2fa.php'])) {
        try {
            $pwStmt = $GLOBALS['pdo'] ?? null;
            if (!$pwStmt) { require_once __DIR__ . '/../db.php'; $pwStmt = $pdo; }
            $pwCheck = $pwStmt->prepare("SELECT password_updated_at, password_expiry_override FROM users WHERE id = ?");
            $pwCheck->execute([$_SESSION['user_id']]);
            $pwRow = $pwCheck->fetch(PDO::FETCH_ASSOC);

            if ($pwRow) {
                $override = $pwRow['password_expiry_override'];
                // Determiner le nombre de jours d'expiration effectif
                if ($override === 0 || $override === '0') {
                    // Exempt : cet utilisateur n'expire jamais
                    $effectiveExpiry = 0;
                } elseif ($override !== null && (int)$override > 0) {
                    // Override custom par user
                    $effectiveExpiry = (int)$override;
                } else {
                    // NULL = utiliser la valeur globale
                    $effectiveExpiry = $globalExpiryDays;
                }

                if ($effectiveExpiry > 0 && $pwRow['password_updated_at']) {
                    $daysSinceChange = (int)((time() - strtotime($pwRow['password_updated_at'])) / 86400);
                    if ($daysSinceChange >= $effectiveExpiry) {
                        $_SESSION['password_expired'] = true;
                        header("Location: /profile.php?password_expired=1");
                        exit();
                    } elseif ($daysSinceChange >= ($effectiveExpiry - $passwordWarnDays)) {
                        $_SESSION['password_warn_days'] = $effectiveExpiry - $daysSinceChange;
                    } else {
                        unset($_SESSION['password_warn_days']);
                    }
                } else {
                    unset($_SESSION['password_warn_days'], $_SESSION['password_expired']);
                }
            }
        } catch (\Exception $e) {}

        // Force password change : redirige vers profile.php si le flag est actif
        if (!empty($_SESSION['force_password_change']) && !in_array($currentPage, ['profile.php'])) {
            header("Location: /profile.php?force_change=1");
            exit();
        }
    }
}

// Headers de sécurité appliqués sur toutes les pages authentifiées
if (!headers_sent()) {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    // CSP : Tailwind CSS compile localement (plus de CDN ni unsafe-eval)
    // unsafe-inline reste necessaire pour les styles inline Tailwind et les scripts inline (toast, dark mode, htmx config)
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/functions.php';

// Constantes pour les rôles
if (!defined('ROLE_USER'))       define('ROLE_USER', 1);
if (!defined('ROLE_ADMIN'))      define('ROLE_ADMIN', 2);
if (!defined('ROLE_SUPERADMIN')) define('ROLE_SUPERADMIN', 3);

/**
 * Vérifie que l'utilisateur est connecté et possède un rôle autorisé.
 * Redirige vers /auth/login.php si non connecté.
 * Termine avec HTTP 403 si le rôle ne figure pas dans la liste autorisée.
 *
 * @param int|int[] $requiredRoles  Un rôle ou une liste de rôles acceptés.
 *                                  Par défaut : tous les rôles (1, 2, 3).
 */
function checkAuth($requiredRoles = [ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]): void {
    if (!isset($_SESSION['user_id'])) {
        header("Location: /auth/login.php");
        exit();
    }

    if (!is_array($requiredRoles)) {
        $requiredRoles = [$requiredRoles];
    }

    // Cast en int pour une comparaison stricte et cohérente
    $requiredRoles = array_map('intval', $requiredRoles);

    if (!in_array((int) $_SESSION['role_id'], $requiredRoles, true)) {
        http_response_code(403);
        die(t('common.access_denied'));
    }
}

// Tente de restaurer la session depuis le cookie "remember_token" (délégué à functions.php)
// Le remember-me restaure la session mais exige une re-verification 2FA
if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_token'])) {
    if (!restoreSessionFromToken()) {
        setcookie('remember_token', '', time() - 3600, '/', '', true, true);
        header("Location: /auth/login.php");
        exit();
    }
    // Forcer la re-verification 2FA apres restauration remember-me
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if (!in_array($currentPage, ['verify_2fa.php', 'login.php', 'logout.php'])) {
        require_once __DIR__ . '/../db.php';
        $stmtTotp = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
        $stmtTotp->execute([$_SESSION['user_id']]);
        $totpSecret = $stmtTotp->fetchColumn();
        if ($totpSecret) {
            // L'utilisateur a le 2FA actif — exiger re-verification
            $_SESSION['temp_user'] = [
                'id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'] ?? '',
                'role_id' => $_SESSION['role_id'] ?? 1,
            ];
            // Conserver user_id pour le remember-me flow mais marquer comme non-verifie
            $_SESSION['2fa_pending'] = true;
            header("Location: /auth/verify_2fa.php");
            exit();
        }
    }
}

// Permissions par défaut si absentes (cas edge : session partielle)
if (!isset($_SESSION['permissions'])) {
    $_SESSION['permissions'] = [
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
 * Vérifie qu'un utilisateur possède une permission spécifique OU est superadmin.
 * Usage : checkPermission('can_scan_cve') ou checkPermission('can_scan_cve', false) pour ne pas mourir.
 */
function checkPermission(string $permission, bool $die = true): bool {
    $isSuperAdmin = ((int) ($_SESSION['role_id'] ?? 0)) >= 3;
    $hasPerm      = (bool) ($_SESSION['permissions'][$permission] ?? 0);
    if ($isSuperAdmin || $hasPerm) return true;

    // Verifier les permissions temporaires (non expirees)
    if (isset($_SESSION['user_id'])) {
        try {
            global $pdo;
            if (!$pdo) require_once __DIR__ . '/../db.php';
            $tmpStmt = $pdo->prepare(
                "SELECT 1 FROM temporary_permissions WHERE user_id = ? AND permission = ? AND expires_at > NOW() LIMIT 1"
            );
            $tmpStmt->execute([$_SESSION['user_id'], $permission]);
            if ($tmpStmt->fetchColumn()) return true;
        } catch (\Exception $e) {}
    }
    if ($die) {
        http_response_code(403);
        $permLabel = htmlspecialchars($permission);
        require_once __DIR__ . '/../head.php';
        echo '<!DOCTYPE html><html lang="fr"><head><title>Acces refuse</title></head>';
        echo '<body class="bg-gray-100 dark:bg-gray-900 min-h-screen flex items-center justify-center">';
        echo '<div class="text-center p-8 max-w-md">';
        echo '<div class="text-6xl mb-4">&#128274;</div>';
        echo '<h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-2">' . t('common.access_denied') . '</h1>';
        echo '<p class="text-sm text-gray-500 dark:text-gray-400 mb-4">' . t('common.permission_required') . ' <code class="bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded text-xs">' . $permLabel . '</code></p>';
        echo '<p class="text-xs text-gray-400 mb-6">' . t('common.contact_admin') . '</p>';
        echo '<a href="/index.php" class="inline-block bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">' . t('common.back_dashboard') . '</a>';
        echo '</div></body></html>';
        exit();
    }
    return false;
}
?>
