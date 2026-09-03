<?php
/**
 * auth/reset_totp.php
 *
 * Réinitialise le secret TOTP d'un utilisateur donné.
 * Accessible uniquement aux superadmins (role 3) via POST avec CSRF.
 *
 * @package RootWarden\Auth
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

// Superadmin uniquement
checkAuth([ROLE_SUPERADMIN]);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {
    checkCsrfToken();
    $userId = (int)$_POST['user_id'];

    // Empecher de reset son propre 2FA via cette route
    if ($userId === (int)$_SESSION['user_id']) {
        header("Location: /adm/admin_page.php?error=Impossible+de+reinitialiser+votre+propre+2FA+ici.");
        exit();
    }

    $stmt = $pdo->prepare("UPDATE users SET totp_secret = NULL WHERE id = ?");
    $stmt->execute([$userId]);

    require_once __DIR__ . '/../adm/includes/audit_log.php';
    audit_log($pdo, "Reset 2FA utilisateur #$userId");

    header("Location: /adm/admin_page.php?message=TOTP+reinitialise.");
    exit();
}

header("Location: /adm/admin_page.php");
exit();
