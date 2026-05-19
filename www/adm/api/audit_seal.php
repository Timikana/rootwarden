<?php
/**
 * audit_seal.php - Seale les lignes user_logs orphelines (self_hash NULL).
 *
 * Scenario : un INSERT legacy (blueprint Python, code ancien) ecrit une ligne
 * sans passer par audit_log_raw() -> self_hash reste NULL. Cet endpoint
 * complete uniquement les self_hash manquants en s'appuyant sur le dernier
 * hash scelle valide en remontant la chaine.
 *
 * Acces : superadmin (GET = dry-run, POST = execute).
 *
 * Patch A08-01 (OWASP A08 Data Integrity Failures) :
 * ---------------------------------------------------
 * AVANT : si une ligne deja scellee ne matchait pas le hash recalcule, on
 *         REECRIVAIT prev_hash + self_hash. Resultat : un superadmin
 *         compromis (ou attaquant ayant un UPDATE direct sur user_logs)
 *         pouvait modifier le contenu d'une ligne, cliquer "Seal" et la
 *         chaine etait silencieusement remarquee comme valide. Toute la
 *         tamper-evidence etait annulee en 1 clic.
 *
 * APRES : on ne touche JAMAIS a une ligne deja scellee. Si on detecte une
 *         desynchro (self_hash recalcule != self_hash stocke), on remonte
 *         l'incident dans la reponse + on log dans error_log() hors-bande,
 *         et on stoppe le sealing (return). L'utilisateur doit investiguer
 *         (alteration BDD legitime ? compromission ?) avant de continuer.
 *
 * Le sealing reste utile uniquement pour les NOUVELLES lignes (self_hash IS
 * NULL) inserees par du code legacy : on les chaine apres la derniere
 * ligne scellee valide, sans rien reecrire.
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
    $stmt = $pdo->query(
        "SELECT id, user_id, action, UNIX_TIMESTAMP(created_at) AS ts,
                prev_hash AS current_prev, self_hash AS current_self
         FROM user_logs ORDER BY id ASC"
    );
    $allRows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $lastHash = AUDIT_LOG_GENESIS;
    $orphanCount = 0;
    $tamperedDetected = [];  // ids ou self_hash stocke != recalcul
    $pending = [];           // [id, prev, self] uniquement pour orphelins
    $stopAtTamper = false;

    foreach ($allRows as $r) {
        $computed = audit_log_compute_hash(
            $lastHash,
            (int)$r['user_id'],
            (string)$r['action'],
            (int)$r['ts']
        );
        $prevSelf = $r['current_self'];

        if ($prevSelf === null) {
            // Ligne orpheline : on la scelle en continuant la chaine valide
            $orphanCount++;
            $pending[] = [(int)$r['id'], $lastHash, $computed];
            $lastHash = $computed;
        } elseif ($prevSelf !== $computed) {
            // Ligne deja scellee mais ne matche pas. NE PAS REECRIRE.
            // Log hors-bande pour investigation + arrete le sealing.
            $tamperedDetected[] = (int)$r['id'];
            error_log(sprintf(
                'audit_seal.php SECURITY: user_logs id=%d self_hash desynchronise '
                . '(stored=%s computed=%s) - PAS de reecriture, investigation requise',
                (int)$r['id'],
                substr((string)$prevSelf, 0, 16) . '...',
                substr($computed, 0, 16) . '...'
            ));
            $stopAtTamper = true;
            // On ne met PAS a jour $lastHash avec $computed : on garde
            // $prevSelf comme reference de chaine "telle quelle" pour
            // que les lignes suivantes orphelines (si elles existent)
            // soient cohérentes avec ce qui est en BDD, pas avec notre
            // recalcul. Mais on n'auto-seal plus apres tamper.
            $lastHash = $prevSelf;
            break;
        } else {
            // Ligne scellee et coherente -> on continue la chaine
            $lastHash = $prevSelf;
        }
    }

    $sealed = 0;
    if (!$dryRun && !$stopAtTamper && count($pending) > 0) {
        $pdo->beginTransaction();
        // Garde-fou SQL : UPDATE seulement si self_hash EST NULL. Empeche
        // toute reecriture si une race ou un bug update une ligne entre
        // notre SELECT et le UPDATE.
        $upd = $pdo->prepare(
            "UPDATE user_logs SET prev_hash = ?, self_hash = ? "
            . "WHERE id = ? AND self_hash IS NULL"
        );
        foreach ($pending as [$id, $prev, $self]) {
            $upd->execute([$prev, $self, $id]);
            if ($upd->rowCount() > 0) $sealed++;
        }
        $pdo->commit();
    }

    $out = [
        'success' => true,
        'dry_run' => $dryRun,
        'total_rows' => count($allRows),
        'unsealed_count' => $orphanCount,
        'sealed' => $sealed,
        'tampered_detected' => $tamperedDetected,
        'stopped_at_tamper' => $stopAtTamper,
        'latest_hash' => substr($lastHash, 0, 16) . '...',
    ];
    if ($stopAtTamper) {
        $out['message'] = 'Desynchronisation detectee sur ' . count($tamperedDetected)
            . ' ligne(s). Aucune reecriture effectuee. Investigation requise '
            . '(voir error_log pour les IDs).';
    }
    echo json_encode($out);
} catch (\Exception $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('audit_seal.php: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
