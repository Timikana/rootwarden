<?php
/**
 * anonymize_user.php - Anonymisation RGPD d'un utilisateur (soft-delete).
 *
 * A la difference d'un DELETE dur (cascade FK) :
 *   - Preserve l'integrite de l'audit log (user_logs) -> tracabilite legale
 *   - Remplace name par "deleted-{id}"
 *   - Efface email, company, ssh_key, totp_secret (PII)
 *   - Invalide password (set = NULL) et active = 0
 *   - Revoque toutes les sessions + remember_tokens + password_history
 *
 * Compatible RGPD art. 17 (droit a l'effacement) : les donnees personnelles
 * sont effacees, seuls l'ID et les lignes d'audit sont conserves (interet
 * legitime : tracabilite securite).
 *
 * Acces : superadmin uniquement.
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../includes/audit_log.php';

if (session_status() === PHP_SESSION_NONE) session_start();

checkAuth([ROLE_SUPERADMIN]);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Methode non autorisee']);
    exit;
}

checkCsrfToken();

$data = json_decode(file_get_contents('php://input'), true) ?: $_POST;
$userId = (int)($data['user_id'] ?? 0);

if ($userId <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'user_id invalide']);
    exit;
}

$actorId = (int)($_SESSION['user_id'] ?? 0);

// Protection : pas d'auto-anonymisation
if ($userId === $actorId) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Impossible d\'anonymiser votre propre compte']);
    exit;
}

// Protection : on ne peut pas anonymiser le dernier superadmin
$targetRoleStmt = $pdo->prepare("SELECT role_id, name FROM users WHERE id = ?");
$targetRoleStmt->execute([$userId]);
$target = $targetRoleStmt->fetch(PDO::FETCH_ASSOC);
if (!$target) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Utilisateur introuvable']);
    exit;
}
if ((int)$target['role_id'] === 3) {
    $saCount = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role_id = 3 AND active = 1")->fetchColumn();
    if ($saCount <= 1) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Impossible d\'anonymiser le dernier superadmin actif']);
        exit;
    }
}

try {
    $pdo->beginTransaction();

    $originalName = (string)$target['name'];

    // Anonymisation : remplace les PII par des valeurs neutres
    $pdo->prepare(
        "UPDATE users SET "
        . "name = CONCAT('deleted-', id), "
        . "email = NULL, "
        . "company = NULL, "
        . "ssh_key = NULL, "
        . "totp_secret = NULL, "
        . "password = NULL, "
        . "active = 0, "
        . "sudo = 0, "
        . "force_password_change = 0, "
        . "password_expiry_override = NULL, "
        . "locked_until = NULL, "
        . "failed_attempts = 0 "
        . "WHERE id = ?"
    )->execute([$userId]);

    // Revoque toutes les sessions actives + remember_tokens
    $pdo->prepare("DELETE FROM active_sessions WHERE user_id = ?")->execute([$userId]);
    $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?")->execute([$userId]);

    // Purge password_history (les hashes sont inutiles sur compte anonymise)
    $pdo->prepare("DELETE FROM password_history WHERE user_id = ?")->execute([$userId]);

    // Efface les preferences de notification (PII indirecte)
    $pdo->prepare("DELETE FROM notification_preferences WHERE user_id = ?")->execute([$userId]);

    // Retire les permissions
    $pdo->prepare("DELETE FROM permissions WHERE user_id = ?")->execute([$userId]);

    // Retire les acces machines (ACL per-user)
    $pdo->prepare("DELETE FROM user_machine_access WHERE user_id = ?")->execute([$userId]);

    // ← Les user_logs et login_history sont CONSERVES pour tracabilite legale
    //    (interet legitime de securite > droit a l'effacement dans ce cas precis,
    //    justifiable RGPD art. 17.3.b + 17.3.e). Le user_id pointe vers le
    //    compte anonymise "deleted-X" qui ne contient plus de PII.

    $pdo->commit();

    audit_log_raw($pdo, $actorId, sprintf(
        "[rgpd] Anonymisation du compte '%s' (id=%d) - PII effacees, audit conserve",
        $originalName, $userId
    ));

    echo json_encode([
        'success' => true,
        'user_id' => $userId,
        'original_name' => $originalName,
        'new_name' => "deleted-$userId",
        'message' => 'Compte anonymise. Audit log conserve avec user_id pointant vers ce compte vide.',
    ]);
} catch (\Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('anonymize_user.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
