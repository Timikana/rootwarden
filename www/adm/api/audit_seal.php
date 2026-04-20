<?php
/**
 * audit_seal.php — Seale les lignes user_logs orphelines (self_hash NULL).
 *
 * Scenario : un INSERT legacy (blueprint Python, code ancien) ecrit une ligne
 * sans passer par audit_log_raw() → self_hash reste NULL. Cet endpoint walks
 * les lignes non-scellees dans l'ordre d'ID et les scelle en continuant la
 * chaine existante.
 *
 * Acces : superadmin (GET = dry-run, POST = execute).
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../includes/audit_log.php';

if (session_status() === PHP_SESSION_NONE) session_start();

checkAuth([ROLE_SUPERADMIN]);

header('Content-Type: application/json');

$dryRun = ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST';
if (!$dryRun) {
    checkCsrfToken();
}

try {
    // Dernier hash connu (reference pour continuer la chaine)
    $lastHash = (string)($pdo->query(
        "SELECT self_hash FROM user_logs
         WHERE self_hash IS NOT NULL
         ORDER BY id DESC LIMIT 1"
    )->fetchColumn() ?: AUDIT_LOG_GENESIS);

    // Toutes les lignes non scellees, par ID croissant
    $stmt = $pdo->query(
        "SELECT id, user_id, action, UNIX_TIMESTAMP(created_at) AS ts
         FROM user_logs
         WHERE self_hash IS NULL
         ORDER BY id ASC"
    );
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $sealed = 0;
    if (!$dryRun && count($rows) > 0) {
        $pdo->beginTransaction();
        $upd = $pdo->prepare("UPDATE user_logs SET prev_hash = ?, self_hash = ? WHERE id = ?");
        foreach ($rows as $r) {
            $self = audit_log_compute_hash(
                $lastHash,
                (int)$r['user_id'],
                (string)$r['action'],
                (int)$r['ts']
            );
            $upd->execute([$lastHash, $self, (int)$r['id']]);
            $lastHash = $self;
            $sealed++;
        }
        $pdo->commit();
    }

    echo json_encode([
        'success' => true,
        'dry_run' => $dryRun,
        'unsealed_count' => count($rows),
        'sealed' => $sealed,
        'latest_hash' => substr($lastHash, 0, 16) . '…',
    ]);
} catch (\Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('audit_seal.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
