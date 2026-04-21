<?php
/**
 * auth/verify.php — Garde central d'authentification et d'autorisation.
 *
 * DOIT etre inclus (require_once) en tete de CHAQUE page protegee.
 * Responsabilites :
 *   1. Debug mode
 *   2. session_start + timeout configurable (SESSION_TIMEOUT env)
 *   3. Blocage total si 2FA non verifie
 *   4. Password expiry enforcement (global + per-user override)
 *   5. Force password change redirect
 *   6. Security headers (CSP, X-Frame-Options, etc.)
 *   7. Auto-restore remember_token → mais FORCER re-2FA apres restore
 *   8. Initialisation permissions par defaut si absentes
 *   9. Definition constantes ROLE_USER/ROLE_ADMIN/ROLE_SUPERADMIN
 *  10. checkAuth() avec verification DB
 *  11. checkPermission() avec verification DB systematique
 *
 * @package RootWarden\Auth
 */

// ── Mode Debug ───────────────────────────────────────────────────────────────
if (getenv('DEBUG_MODE') === 'true') {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    ini_set('log_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}

// ── Session ──────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Dependances ──────────────────────────────────────────────────────────────
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/functions.php';

// ── Constantes pour les roles ────────────────────────────────────────────────
if (!defined('ROLE_USER'))       define('ROLE_USER', 1);
if (!defined('ROLE_ADMIN'))      define('ROLE_ADMIN', 2);
if (!defined('ROLE_SUPERADMIN')) define('ROLE_SUPERADMIN', 3);

// ── Session timeout (defaut 30 min, configurable via SESSION_TIMEOUT) ────────
$sessionTimeout = ((int)(getenv('SESSION_TIMEOUT') ?: 30)) * 60;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $sessionTimeout) {
    session_unset();
    session_destroy();
    header("Location: /auth/login.php?expired=1");
    exit();
}
$_SESSION['last_activity'] = time();

// ── Revocation server-side : verifie que la session est toujours dans active_sessions ──
// Sans ce check, un DELETE depuis /profile.php (bouton "Revoquer") n'a aucun effet —
// la session cookie continue de fonctionner tant que PHP n'a pas timeout.
// Refuse aussi les sessions pour lesquelles /logout.php aurait ete appele
// depuis un autre navigateur, ou que l'admin aurait force-revoke (future UI).
if (isset($_SESSION['user_id']) && !empty($_SESSION['2fa_required']) === false) {
    try {
        $_sessChk = $pdo->prepare(
            "SELECT 1 FROM active_sessions WHERE session_id = ? AND user_id = ? LIMIT 1"
        );
        $_sessChk->execute([session_id(), (int)$_SESSION['user_id']]);
        if (!$_sessChk->fetchColumn()) {
            // Session n'est plus enregistree → revoquee (UI profile) ou jamais
            // instanciee (edge case : restoration de cookie remember_me sans
            // active_sessions row). Dans les deux cas, on force un re-login.
            session_unset();
            session_destroy();
            header("Location: /auth/login.php?expired=1");
            exit();
        }
    } catch (\Exception $e) {
        // DB indisponible : on ne BLOQUE PAS l'utilisateur (fail-open pour la
        // dispo, fail-closed serait plus strict mais casserait le service en
        // cas de glitch DB). Log pour detection.
        error_log('verify.php active_sessions check failed: ' . $e->getMessage());
    }
}

// ── Remember-me : restauration de session depuis le cookie ───────────────────
// Si pas connecte mais cookie present → tenter la restauration
if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_token'])) {
    if (!restoreSessionFromToken()) {
        expireRememberCookie();
        header("Location: /auth/login.php");
        exit();
    }
    // Session restauree — forcer la re-verification 2FA
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if (!in_array($currentPage, ['verify_2fa.php', 'enable_2fa.php', 'login.php', 'logout.php'])) {
        $stmtTotp = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ? AND active = 1");
        $stmtTotp->execute([$_SESSION['user_id']]);
        $totpSecret = $stmtTotp->fetchColumn();
        if ($totpSecret) {
            // L'utilisateur a le 2FA actif — exiger re-verification
            $_SESSION['temp_user'] = [
                'id'       => $_SESSION['user_id'],
                'username' => $_SESSION['username'] ?? '',
                'role_id'  => $_SESSION['role_id'] ?? 1,
            ];
            $_SESSION['2fa_pending'] = true;
            $_SESSION['2fa_required'] = true;
            header("Location: /auth/verify_2fa.php");
            exit();
        }
    }
}

// ── Blocage 2FA : empecher tout acces si 2FA non verifie ─────────────────────
if (!empty($_SESSION['2fa_required']) || !empty($_SESSION['2fa_pending'])) {
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    $allowedPages = ['verify_2fa.php', 'enable_2fa.php', 'login.php', 'logout.php'];
    if (!in_array($currentPage, $allowedPages)) {
        header("Location: /auth/verify_2fa.php");
        exit();
    }
}

// ── Password expiry enforcement ──────────────────────────────────────────────
$globalExpiryDays = (int)(getenv('PASSWORD_EXPIRY_DAYS') ?: 0);
$passwordWarnDays = (int)(getenv('PASSWORD_WARN_DAYS') ?: 14);
if (isset($_SESSION['user_id'])) {
    $currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
    $expiryExemptPages = ['profile.php', 'login.php', 'verify_2fa.php', 'enable_2fa.php', 'logout.php'];
    if (!in_array($currentPage, $expiryExemptPages)) {
        try {
            $pwCheck = $pdo->prepare(
                "SELECT password_updated_at, password_expiry_override, force_password_change
                 FROM users WHERE id = ? AND active = 1"
            );
            $pwCheck->execute([$_SESSION['user_id']]);
            $pwRow = $pwCheck->fetch(PDO::FETCH_ASSOC);

            if ($pwRow) {
                // Force password change : prioritaire
                if ((int)($pwRow['force_password_change'] ?? 0) === 1) {
                    $_SESSION['force_password_change'] = true;
                    header("Location: /profile.php?force_change=1");
                    exit();
                }

                // Determiner le nombre de jours d'expiration effectif
                $override = $pwRow['password_expiry_override'];
                if ($override === 0 || $override === '0') {
                    $effectiveExpiry = 0; // Exempt
                } elseif ($override !== null && (int)$override > 0) {
                    $effectiveExpiry = (int)$override; // Override custom
                } else {
                    $effectiveExpiry = $globalExpiryDays; // Global
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
        } catch (\Exception $e) {
            // Fail secure : en cas d'erreur DB, ne pas bloquer mais logger
            error_log("verify.php password expiry check failed: " . $e->getMessage());
        }
    }
}

// ── Security headers ─────────────────────────────────────────────────────────
if (!headers_sent()) {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
}

// ── Permissions par defaut si absentes (session partielle) ───────────────────
if (!isset($_SESSION['permissions'])) {
    $_SESSION['permissions'] = DEFAULT_PERMISSIONS;
}

// ══════════════════════════════════════════════════════════════════════════════
// Fonctions de controle d'acces (definies ici car elles dependent de $pdo
// et des constantes ROLE_* qui viennent d'etre definies)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Verifie que l'utilisateur est connecte, existe encore en DB (active=1),
 * et possede un role autorise.
 *
 * - Si non connecte → redirect login
 * - Si utilisateur desactive en DB → session_destroy + redirect login
 * - Si role_id en DB differe de la session → mise a jour session
 * - Si role non autorise → HTTP 403
 *
 * @param int|int[] $requiredRoles  Un role ou une liste de roles acceptes.
 */
function checkAuth($requiredRoles = [ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]): void
{
    global $pdo;

    if (!isset($_SESSION['user_id'])) {
        header("Location: /auth/login.php");
        exit();
    }

    // ZERO TRUST : verifier que l'utilisateur existe et est actif en DB
    $stmt = $pdo->prepare("SELECT role_id, active FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $dbUser = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$dbUser || (int)$dbUser['active'] !== 1) {
        // Utilisateur supprime ou desactive → destruction totale
        resetSession();
        header("Location: /auth/login.php");
        exit();
    }

    $dbRoleId = (int) $dbUser['role_id'];

    // Synchroniser le role en session si different de la DB
    if ($dbRoleId !== (int) $_SESSION['role_id']) {
        $_SESSION['role_id'] = $dbRoleId;
        // Recharger les permissions car le role a change
        $_SESSION['permissions'] = getVerifiedPermissions($_SESSION['user_id']);
    }

    if (!is_array($requiredRoles)) {
        $requiredRoles = [$requiredRoles];
    }
    $requiredRoles = array_map('intval', $requiredRoles);

    if (!in_array($dbRoleId, $requiredRoles, true)) {
        http_response_code(403);
        die(t('common.access_denied'));
    }
}

/**
 * Verifie qu'un utilisateur possede une permission specifique.
 *
 * TOUJOURS verifie en DB (pas depuis $_SESSION['permissions']).
 * Superadmin (role_id=3 verifie en DB) bypass tout.
 * Combine permissions permanentes + temporaires non expirees.
 * Met a jour le cache $_SESSION['permissions'] apres chaque check.
 *
 * @param string $permission  Nom de la permission (ex: 'can_scan_cve').
 * @param bool   $die         Si true, affiche une page d'erreur et exit().
 * @return bool               true si autorise, false sinon.
 */
function checkPermission(string $permission, bool $die = true): bool
{
    global $pdo;

    $userId = (int) ($_SESSION['user_id'] ?? 0);
    if ($userId === 0) {
        if ($die) {
            http_response_code(403);
            die(t('common.access_denied'));
        }
        return false;
    }

    // Superadmin bypass (role_id deja verifie en DB par checkAuth)
    $roleId = (int) ($_SESSION['role_id'] ?? 0);
    if ($roleId === 3) {
        return true;
    }

    // Verifier la permission depuis la session (synchronisee par checkAuth)
    $hasPerm = (bool) ($_SESSION['permissions'][$permission] ?? 0);

    // Fallback : verifier les permissions temporaires en DB (seule query necessaire)
    if (!$hasPerm) {
        try {
            $tmpStmt = $pdo->prepare(
                "SELECT 1 FROM temporary_permissions
                 WHERE user_id = ? AND permission = ? AND expires_at > NOW() LIMIT 1"
            );
            $tmpStmt->execute([$userId, $permission]);
            $hasPerm = (bool) $tmpStmt->fetchColumn();
        } catch (\Exception $e) {}
    }

    if ($hasPerm) {
        return true;
    }

    // Permission refusee — logger le refus
    try {
        $logStmt = $pdo->prepare("INSERT INTO user_logs (user_id, action) VALUES (?, ?)");
        $logStmt->execute([$userId, "Permission refusee : $permission"]);
    } catch (\Exception $e) {
        error_log("Failed to log permission denial: " . $e->getMessage());
    }

    if ($die) {
        http_response_code(403);
        $permLabel = htmlspecialchars($permission);
        require_once __DIR__ . '/../head.php';
        echo '<!DOCTYPE html><html lang="fr"><head><title>' . t('common.access_denied') . '</title></head>';
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
