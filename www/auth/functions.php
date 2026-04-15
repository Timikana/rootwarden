<?php
/**
 * auth/functions.php — Utilitaires d'authentification et de controle d'acces.
 *
 * Toutes les fonctions liees a la gestion de session, CSRF, permissions
 * et verification utilisateur. Principe ZERO TRUST : ne jamais faire
 * confiance a $_SESSION pour les decisions de securite — toujours
 * verifier en base de donnees.
 *
 * @package RootWarden\Auth
 */

// ── Permissions par defaut (tout a 0) ───────────────────────────────────────
define('DEFAULT_PERMISSIONS', [
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
    'can_manage_services'     => 0,
    'can_audit_ssh'           => 0,
    'can_manage_supervision'  => 0,
]);

/**
 * Detruit la session courante et supprime le cookie remember_token.
 * Cree ensuite une nouvelle session vide.
 */
function resetSession(): void
{
    // Supprimer le cookie remember_token
    setcookie('remember_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    session_start();
}

/**
 * Initialise les variables de session apres une authentification reussie.
 * Regenere l'ID de session (protection contre la fixation de session),
 * genere un nouveau jeton CSRF et charge les permissions depuis la BDD.
 *
 * @param array $user  Ligne de la table `users` avec au moins : id, name, role_id.
 */
function initializeUserSession(array $user): void
{
    global $pdo;

    $_SESSION['user_id']  = (int) ($user['id'] ?? 0);
    $_SESSION['username'] = $user['name'] ?? t('common.guest');
    $_SESSION['role_id']  = (int) ($user['role_id'] ?? 1);

    // Regenerer l'ID de session pour prevenir la fixation de session
    session_regenerate_id(true);

    // Nouveau jeton CSRF
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    // Charger les permissions depuis la base de donnees (source de verite)
    $_SESSION['permissions'] = getVerifiedPermissions($_SESSION['user_id']);
}

/**
 * Tente de restaurer la session depuis le cookie "remember_token".
 * Format attendu : "user_id:token" (user_id doit etre un entier positif).
 *
 * IMPORTANT : apres restauration, l'utilisateur doit re-verifier le 2FA.
 * Cette fonction ne fait que restaurer la session basique (user_id, username, role_id).
 */
function restoreSessionFromToken(): bool
{
    global $pdo;

    if (isset($_SESSION['user_id']) || !isset($_COOKIE['remember_token'])) {
        return false;
    }

    $parts = explode(':', $_COOKIE['remember_token'], 2);
    if (count($parts) !== 2) {
        expireRememberCookie();
        return false;
    }

    [$uid, $token] = $parts;

    // Validation stricte : uid doit etre un entier positif
    if (!ctype_digit((string) $uid) || (int) $uid <= 0) {
        expireRememberCookie();
        return false;
    }

    $uid = (int) $uid;

    // Verifier le token en base
    $stmt = $pdo->prepare("SELECT token_hash, expires_at FROM remember_tokens WHERE user_id = ?");
    $stmt->execute([$uid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($token, $row['token_hash']) || strtotime($row['expires_at']) <= time()) {
        expireRememberCookie();
        return false;
    }

    // Verifier que l'utilisateur existe ET est actif en base
    $stmt = $pdo->prepare("SELECT id, name, role_id, active FROM users WHERE id = ? AND active = 1");
    $stmt->execute([$uid]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Utilisateur inexistant ou desactive — supprimer le token
        $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?")->execute([$uid]);
        resetSession();
        return false;
    }

    // Restaurer la session basique (les permissions seront chargees depuis la DB)
    initializeUserSession($user);
    return true;
}

/**
 * Verifie que le jeton CSRF du POST correspond a celui de la session.
 * Termine le script avec HTTP 403 si les jetons sont absents ou differents.
 *
 * Sources du token (ordre de priorite) :
 *   1. $_POST['csrf_token']           (form-urlencoded classique)
 *   2. Header X-CSRF-TOKEN            (htmx auto-inject / fetch custom)
 *   3. Body JSON php://input          (requetes application/json)
 *
 * Utilise hash_equals() pour une comparaison timing-safe.
 */
function checkCsrfToken(): void
{
    if (empty($_SESSION['csrf_token'])) {
        http_response_code(403);
        header('Content-Type: application/json');
        die(json_encode(['success' => false, 'message' => t('common.csrf_no_session')]));
    }

    // 1. POST form-urlencoded
    $token = $_POST['csrf_token'] ?? '';

    // 2. Header htmx / fetch
    if (empty($token)) {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    }

    // 3. Body JSON (php://input — rerereadable en PHP 8.2)
    if (empty($token)) {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        if (str_contains($contentType, 'application/json')) {
            $jsonBody = json_decode(file_get_contents('php://input'), true);
            $token = $jsonBody['csrf_token'] ?? '';
        }
    }

    if (empty($token)) {
        http_response_code(403);
        header('Content-Type: application/json');
        die(json_encode(['success' => false, 'message' => t('common.csrf_no_request')]));
    }

    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        header('Content-Type: application/json');
        die(json_encode(['success' => false, 'message' => t('common.csrf_invalid')]));
    }
}

/**
 * Retourne le role_id d'un utilisateur depuis la base de donnees.
 *
 * @param  int $userId  ID de l'utilisateur.
 * @return int          role_id (1, 2 ou 3), ou 0 si l'utilisateur n'existe pas.
 */
function getUserRole(int $userId): int
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ? AND active = 1");
    $stmt->execute([$userId]);
    $role = $stmt->fetchColumn();
    return $role !== false ? (int) $role : 0;
}

/**
 * Retourne les informations completes d'un utilisateur verifie en base.
 * Inclut role_id, active, permissions, totp_secret, force_password_change.
 *
 * @param  int        $userId  ID de l'utilisateur.
 * @return array|null          Donnees utilisateur ou null si inexistant/inactif.
 */
function getVerifiedUser(int $userId): ?array
{
    global $pdo;
    $stmt = $pdo->prepare(
        "SELECT u.id, u.name, u.role_id, u.active, u.totp_secret,
                u.force_password_change, u.password_updated_at, u.password_expiry_override
         FROM users u
         WHERE u.id = ? AND u.active = 1"
    );
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        return null;
    }

    $user['permissions'] = getVerifiedPermissions($userId);
    return $user;
}

/**
 * Retourne les permissions d'un utilisateur depuis la base de donnees.
 * C'est la SOURCE DE VERITE pour les permissions — ne jamais utiliser
 * $_SESSION['permissions'] pour une decision de securite.
 *
 * @param  int   $userId  ID de l'utilisateur.
 * @return array          Tableau associatif des permissions (default = tout a 0).
 */
function getVerifiedPermissions(int $userId): array
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM permissions WHERE user_id = ?");
    $stmt->execute([$userId]);
    $permissions = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$permissions) {
        return DEFAULT_PERMISSIONS;
    }

    // S'assurer que toutes les cles existent (protection contre schema partiel)
    return array_merge(DEFAULT_PERMISSIONS, $permissions);
}

/**
 * Verifie une permission specifique en base de donnees.
 * Combine les permissions permanentes (table permissions) ET temporaires
 * (table temporary_permissions avec expires_at > NOW()).
 *
 * Superadmin (role_id=3 verifie en DB) bypass tout.
 *
 * @param  int    $userId     ID de l'utilisateur.
 * @param  string $permission Nom de la permission (ex: 'can_scan_cve').
 * @return bool               true si autorise, false sinon.
 */
function checkPermissionFromDB(int $userId, string $permission): bool
{
    global $pdo;

    // Verifier le role en DB (pas depuis la session)
    $roleId = getUserRole($userId);

    // Superadmin bypass
    if ($roleId === 3) {
        return true;
    }

    // Verifier la permission permanente en DB
    $perms = getVerifiedPermissions($userId);
    if (!empty($perms[$permission])) {
        return true;
    }

    // Verifier les permissions temporaires (non expirees)
    $stmt = $pdo->prepare(
        "SELECT 1 FROM temporary_permissions
         WHERE user_id = ? AND permission = ? AND expires_at > NOW()
         LIMIT 1"
    );
    $stmt->execute([$userId, $permission]);
    return (bool) $stmt->fetchColumn();
}

/**
 * Expire le cookie remember_token cote navigateur.
 */
function expireRememberCookie(): void
{
    setcookie('remember_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly'  => true,
        'samesite' => 'Strict',
    ]);
}
