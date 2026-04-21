<?php
/**
 * audit_verify.php — Verifie l'integrite de la chaine de hash user_logs.
 *
 * Walks chaque ligne dans l'ordre d'ID, recalcule le hash attendu et le
 * compare a self_hash stocke. Signale la PREMIERE incoherence si presente.
 *
 * Types de probleme detectables :
 *   - MISMATCH    : self_hash != hash recalcule (ligne modifiee apres scellement)
 *   - PREV_BROKEN : prev_hash != self_hash de la ligne precedente (ligne inseree/supprimee)
 *   - UNSEALED    : lignes sans self_hash (INSERTs legacy, non-bloquant)
 *
 * Acces : superadmin uniquement (en lecture, pas de mutation).
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/../includes/audit_log.php';

if (session_status() === PHP_SESSION_NONE) session_start();

checkAuth([ROLE_SUPERADMIN]);

header('Content-Type: application/json');

try {
    $stmt = $pdo->query(
        "SELECT id, user_id, action, UNIX_TIMESTAMP(created_at) AS ts,
                prev_hash, self_hash
         FROM user_logs ORDER BY id ASC"
    );

    $expectedPrev = AUDIT_LOG_GENESIS;
    $total = 0;
    $sealed = 0;
    $unsealed = 0;
    $firstError = null;

    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $total++;

        // Ligne sans scellement
        if ($r['self_hash'] === null) {
            $unsealed++;
            // On ne peut pas poursuivre la chaine tant qu'elle n'est pas scellee,
            // donc on arrete le scan coherent ici.
            if ($firstError === null && $unsealed === 1) {
                // Pas une erreur en soi, juste un signal — continue pour compter
            }
            continue;
        }

        $sealed++;

        // Check prev_hash continuity
        if ($r['prev_hash'] !== $expectedPrev) {
            if ($firstError === null) {
                $firstError = [
                    'id' => (int)$r['id'],
                    'type' => 'PREV_BROKEN',
                    'expected_prev' => substr($expectedPrev, 0, 16) . '…',
                    'actual_prev' => substr((string)$r['prev_hash'], 0, 16) . '…',
                    'message' => 'La ligne ' . $r['id'] . ' pointe vers un hash precedent inattendu',
                ];
            }
        }

        // Check self_hash recomputation
        $expectedSelf = audit_log_compute_hash(
            (string)$r['prev_hash'],
            (int)$r['user_id'],
            (string)$r['action'],
            (int)$r['ts']
        );
        if ($expectedSelf !== $r['self_hash']) {
            if ($firstError === null) {
                $firstError = [
                    'id' => (int)$r['id'],
                    'type' => 'MISMATCH',
                    'expected_self' => substr($expectedSelf, 0, 16) . '…',
                    'actual_self' => substr((string)$r['self_hash'], 0, 16) . '…',
                    'message' => 'La ligne ' . $r['id'] . ' a ete modifiee apres scellement',
                ];
            }
        }

        $expectedPrev = $r['self_hash'];
    }

    echo json_encode([
        'success' => $firstError === null,
        'total' => $total,
        'sealed' => $sealed,
        'unsealed' => $unsealed,
        'chain_head' => $sealed > 0 ? substr($expectedPrev, 0, 16) . '…' : null,
        'error' => $firstError,
        'integrity' => $firstError === null ? 'OK' : 'BROKEN',
    ]);
} catch (\Exception $e) {
    error_log('audit_verify.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
