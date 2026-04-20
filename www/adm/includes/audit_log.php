<?php
/**
 * audit_log.php — Fonction centralisée de logging des actions admin.
 *
 * Insère une entrée dans la table user_logs avec l'IP et les détails.
 * À appeler après chaque action sensible.
 *
 * Hash chain (migration 036) :
 *   Chaque ligne inclut prev_hash + self_hash = SHA2-256(prev_hash | user_id | action | unix_ts).
 *   audit_log() calcule et renseigne les deux colonnes atomiquement
 *   (SELECT derniere self_hash FOR UPDATE puis INSERT dans la meme transaction).
 *   Les INSERTs legacy qui n'utilisent pas ce helper laissent self_hash NULL —
 *   /adm/api/audit_seal.php les seale en arriere-plan.
 */

/** Valeur initiale de prev_hash quand user_logs est vide. */
if (!defined('AUDIT_LOG_GENESIS')) {
    define('AUDIT_LOG_GENESIS', 'GENESIS');
}

/**
 * Calcule le self_hash SHA2-256 d'une ligne user_logs.
 * IMPORTANT : la formule doit matcher /adm/api/audit_verify.php.
 */
function audit_log_compute_hash(string $prevHash, int $userId, string $action, int $unixTs): string {
    return hash('sha256', implode('|', [$prevHash, (string)$userId, $action, (string)$unixTs]));
}

/**
 * @param PDO    $pdo    Connexion PDO
 * @param string $action Description de l'action (ex: "Création utilisateur marie.test")
 * @param int|null $targetId ID de l'objet cible (user_id, machine_id, null)
 * @param string $details Détails supplémentaires (optionnel)
 */
function audit_log(PDO $pdo, string $action, ?int $targetId = null, string $details = ''): void {
    $userId = (int)($_SESSION['user_id'] ?? 0);
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Enrichir l'action avec le contexte (targetId, IP, details)
    $fullAction = $action;
    if ($targetId !== null) $fullAction .= " [cible=#$targetId]";
    if ($details) $fullAction .= " — $details";
    $fullAction .= " (IP: $ip)";
    $fullAction = substr($fullAction, 0, 255);

    audit_log_raw($pdo, $userId, $fullAction);
}

/**
 * Version bas-niveau : ecrit une ligne user_logs scellee avec hash chaine.
 * Utilisee par audit_log() + par les call sites qui precisent user_id manuellement
 * (login.php, unlock_user.php, etc.).
 */
function audit_log_raw(PDO $pdo, int $userId, string $action): void {
    $action = substr($action, 0, 255);
    try {
        $pdo->beginTransaction();
        $prevStmt = $pdo->query(
            "SELECT self_hash FROM user_logs
             WHERE self_hash IS NOT NULL
             ORDER BY id DESC LIMIT 1
             FOR UPDATE"
        );
        $prevHash = (string)($prevStmt->fetchColumn() ?: AUDIT_LOG_GENESIS);
        $unixTs = time();
        $selfHash = audit_log_compute_hash($prevHash, $userId, $action, $unixTs);
        $stmt = $pdo->prepare(
            "INSERT INTO user_logs (user_id, action, created_at, prev_hash, self_hash)
             VALUES (?, ?, FROM_UNIXTIME(?), ?, ?)"
        );
        $stmt->execute([$userId, $action, $unixTs, $prevHash, $selfHash]);
        $pdo->commit();
    } catch (\Exception $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log("audit_log_raw failed: " . $e->getMessage());
    }
}
