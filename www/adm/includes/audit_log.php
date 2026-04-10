<?php
/**
 * audit_log.php — Fonction centralisée de logging des actions admin.
 *
 * Insère une entrée dans la table user_logs avec l'IP et les détails.
 * À appeler après chaque action sensible.
 */

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

    try {
        $stmt = $pdo->prepare("INSERT INTO user_logs (user_id, action, created_at) VALUES (?, ?, NOW())");
        $stmt->execute([$userId, substr($fullAction, 0, 255)]);
    } catch (\Exception $e) {
        error_log("audit_log failed: " . $e->getMessage());
    }
}
