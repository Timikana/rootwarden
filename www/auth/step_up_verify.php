<?php
/**
 * step_up_verify.php - Endpoint qui valide un code TOTP pour une action.
 *
 * Patch A04-INSEC-N4 - declenche par le modal frontend quand stepUpRequire
 * a renvoye 403 sur une action sensible.
 *
 * POST : {action: str, totp_code: str}
 * Reponse : {success: bool, message: str}
 *
 * Si OK, marque le step-up valide pour 15 minutes -> l'action sensible
 * peut etre re-tentee.
 */

require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/verify.php';
require_once __DIR__ . '/../includes/totp_crypto.php';
require_once __DIR__ . '/step_up.php';

use OTPHP\TOTP;

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'POST requis']);
    exit;
}

checkCsrfToken();

$data = json_decode(file_get_contents('php://input'), true) ?: $_POST;
$action = preg_replace('/[^a-z0-9_]/i', '_', (string)($data['action'] ?? ''));
$code   = trim((string)($data['totp_code'] ?? ''));

if (!$action || !$code || !preg_match('/^\d{6}$/', $code)) {
    echo json_encode(['success' => false, 'message' => 'action ou code invalide']);
    exit;
}

// Rate-limit basique : max 5 tentatives par minute en session
$_SESSION['_step_up_attempts'] = array_filter(
    $_SESSION['_step_up_attempts'] ?? [],
    fn($t) => $t > time() - 60
);
if (count($_SESSION['_step_up_attempts']) >= 5) {
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Trop de tentatives, patientez 1 min']);
    exit;
}
$_SESSION['_step_up_attempts'][] = time();

// Verifier le TOTP courant
$stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
$stmt->execute([(int)$_SESSION['user_id']]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$row || empty($row['totp_secret'])) {
    echo json_encode(['success' => false, 'message' => '2FA non configure pour ce compte']);
    exit;
}

$secret = decryptTotpSecret($row['totp_secret']);
$totp = TOTP::create($secret);
if (!$totp->verify($code, null, 1)) {
    echo json_encode(['success' => false, 'message' => 'Code 2FA invalide']);
    exit;
}

stepUpMark($action);
echo json_encode([
    'success' => true,
    'message' => 'Re-authentification valide',
    'action' => $action,
    'valid_until' => time() + 900,
]);
