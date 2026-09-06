<?php
/**
 * unlock_user.php - Deverrouille manuellement un compte verrouille apres N echecs consecutifs.
 *
 * Acces : superadmin uniquement (role_id = 3).
 *
 * Body JSON attendu :
 *   { "user_id": int }
 *
 * Effet :
 *   UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?
 *
 * Audit : ligne dans user_logs prefixee [security].
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../auth/functions.php';
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

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    $data = $_POST;
}

$user_id = isset($data['user_id']) ? (int)$data['user_id'] : 0;
if ($user_id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'user_id invalide']);
    exit;
}

try {
    $stmt = $pdo->prepare("SELECT id, name, failed_attempts, locked_until FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $u = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$u) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Utilisateur introuvable']);
        exit;
    }

    $pdo->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
        ->execute([$user_id]);

    // Bug 2026-05-26 : sans purge de login_attempts, l'user restait bloque
    // par le rate-limit IP-based (5 echecs / 10 min) meme apres unlock du
    // compte. On purge les tentatives echouees lui appartenant.
    $purgeStmt = $pdo->prepare(
        "DELETE FROM login_attempts WHERE username = ? AND success = 0"
    );
    $purgeStmt->execute([$u['name']]);
    $purged = $purgeStmt->rowCount();

    $actor_id = (int)($_SESSION['user_id'] ?? 0);
    audit_log_raw($pdo, $actor_id, sprintf(
        "[security] Deverrouillage manuel du compte %s (id=%d, %d echecs effaces, %d login_attempts purgees)",
        $u['name'], $user_id, (int)$u['failed_attempts'], $purged
    ));

    echo json_encode([
        'success' => true,
        'user_id' => $user_id,
        'user_name' => $u['name'],
        'was_locked' => !empty($u['locked_until']),
        'cleared_attempts' => (int)$u['failed_attempts'],
        'purged_login_attempts' => $purged,
    ]);
} catch (\Exception $e) {
    error_log('unlock_user.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
