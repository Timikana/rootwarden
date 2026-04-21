<?php
/**
 * audit_seal.php - Seale les lignes user_logs orphelines (self_hash NULL).
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
    // Rebuild complet de la chaine a partir de la ligne ID 1 (GENESIS).
    // Cela garantit une chaine consistante meme quand des lignes orphelines
    // sont intercalees avec des lignes deja scellees (cas des INSERTs
    // legacy arrivant apres des lignes recentes scellees).
    //
    // Trade-off : les signatures deja calculees peuvent changer. La
    // tamper-evidence est preservee pour l'avenir (une modif post-seal
    // sera detectee), et la comparaison avec un export ou un backup
    // externe reste possible.
    $stmt = $pdo->query(
        "SELECT id, user_id, action, UNIX_TIMESTAMP(created_at) AS ts,
                self_hash AS current_self
         FROM user_logs ORDER BY id ASC"
    );
    $allRows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $lastHash = AUDIT_LOG_GENESIS;
    $orphanCount = 0;
    $rewrittenCount = 0;
    $pending = [];  // [id, prev, self] pour update batch

    foreach ($allRows as $r) {
        $self = audit_log_compute_hash(
            $lastHash,
            (int)$r['user_id'],
            (string)$r['action'],
            (int)$r['ts']
        );
        $prevSelf = $r['current_self'];
        if ($prevSelf === null) {
            $orphanCount++;
        } elseif ($prevSelf !== $self) {
            $rewrittenCount++;
        }
        if ($prevSelf !== $self) {
            $pending[] = [(int)$r['id'], $lastHash, $self];
        }
        $lastHash = $self;
    }

    $sealed = 0;
    if (!$dryRun && count($pending) > 0) {
        $pdo->beginTransaction();
        $upd = $pdo->prepare("UPDATE user_logs SET prev_hash = ?, self_hash = ? WHERE id = ?");
        foreach ($pending as [$id, $prev, $self]) {
            $upd->execute([$prev, $self, $id]);
            $sealed++;
        }
        $pdo->commit();
    }

    echo json_encode([
        'success' => true,
        'dry_run' => $dryRun,
        'total_rows' => count($allRows),
        'unsealed_count' => $orphanCount,
        'rewritten_sealed' => $rewrittenCount,
        'sealed' => $sealed,
        'latest_hash' => substr($lastHash, 0, 16) . '…',
    ]);
} catch (\Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('audit_seal.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
