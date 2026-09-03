<?php
/**
 * dismiss_onboarding.php - Masque le wizard d'onboarding pour l'user courant.
 *
 * Met users.onboarding_dismissed_at = NOW(). Reversible en UPDATE manuel
 * ou futur endpoint admin si besoin.
 */
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkCsrfToken();

header('Content-Type: application/json');

$uid = (int)($_SESSION['user_id'] ?? 0);
if ($uid === 0) {
    http_response_code(401);
    echo json_encode(['success' => false]);
    exit;
}

try {
    $pdo->prepare("UPDATE users SET onboarding_dismissed_at = NOW() WHERE id = ?")->execute([$uid]);
    echo json_encode(['success' => true]);
} catch (\PDOException $e) {
    error_log('dismiss_onboarding: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false]);
}
