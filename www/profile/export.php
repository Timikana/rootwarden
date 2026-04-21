<?php
/**
 * profile/export.php — Export RGPD des donnees personnelles du user connecte.
 *
 * Fournit un fichier JSON telechargeable contenant toutes les donnees
 * personnelles identifiables par l'utilisateur (art. 15 RGPD : droit
 * d'acces, art. 20 : portabilite).
 *
 * Contenu exporte (filtre par user_id = session user) :
 *   - users : profil (name, email, company, role, dates, flags)
 *   - permissions : droits fonctionnels actuels
 *   - user_machine_access : machines auxquelles l'user a acces (role=1)
 *   - user_logs : historique des actions effectuees par le user
 *   - login_history : tentatives de connexion (success + echecs)
 *   - active_sessions : sessions actives
 *   - notification_preferences : preferences notif
 *   - password_history : metas uniquement (changed_at, pas le hash)
 *
 * Format : JSON UTF-8, Content-Disposition attachment.
 */

require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

$userId = (int)($_SESSION['user_id'] ?? 0);
if ($userId <= 0) {
    http_response_code(403);
    exit('Non autorise');
}

// Audit log de la demande d'export (RGPD art. 30 : registre des activites)
require_once __DIR__ . '/../adm/includes/audit_log.php';
audit_log_raw($pdo, $userId, '[rgpd] Export des donnees personnelles demande');

// Helper : fetch all rows as array
function fetchAllSafe(PDO $pdo, string $sql, array $params = []): array {
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (\Exception $e) {
        error_log("profile/export.php fetch failed: " . $e->getMessage());
        return ['_error' => 'fetch failed'];
    }
}

$export = [
    '_metadata' => [
        'generated_at' => date('c'),
        'rootwarden_version' => trim(@file_get_contents(__DIR__ . '/../version.txt') ?: 'unknown'),
        'user_id' => $userId,
        'format_version' => '1.0',
        'rgpd_articles' => ['art_15_access', 'art_20_portability'],
    ],
    'user' => fetchAllSafe($pdo,
        "SELECT id, name, email, company, role_id, active, sudo, created_at, "
        . "password_updated_at, ssh_key, ssh_key_updated_at, password_expiry_override, "
        . "force_password_change, failed_attempts, locked_until, last_failed_login_at "
        . "FROM users WHERE id = ?",
        [$userId]
    ),
    'permissions' => fetchAllSafe($pdo,
        "SELECT * FROM permissions WHERE user_id = ?", [$userId]
    ),
    'user_machine_access' => fetchAllSafe($pdo,
        "SELECT uma.machine_id, m.name AS machine_name, m.ip "
        . "FROM user_machine_access uma "
        . "LEFT JOIN machines m ON m.id = uma.machine_id "
        . "WHERE uma.user_id = ?",
        [$userId]
    ),
    'user_logs' => fetchAllSafe($pdo,
        "SELECT id, action, created_at, LEFT(self_hash, 16) AS hash_chain "
        . "FROM user_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10000",
        [$userId]
    ),
    'login_history' => fetchAllSafe($pdo,
        "SELECT id, ip_address, user_agent, status, created_at "
        . "FROM login_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 1000",
        [$userId]
    ),
    'active_sessions' => array_map(function($s) {
        // Masquer session_id pour ne pas exposer le token en clair dans le dump
        $s['session_id'] = substr($s['session_id'] ?? '', 0, 8) . '...';
        return $s;
    }, fetchAllSafe($pdo,
        "SELECT session_id, ip_address, user_agent, last_activity, created_at "
        . "FROM active_sessions WHERE user_id = ?", [$userId]
    )),
    'notification_preferences' => fetchAllSafe($pdo,
        "SELECT event_type, email, in_app FROM notification_preferences WHERE user_id = ?",
        [$userId]
    ),
    'password_history' => fetchAllSafe($pdo,
        // Meta seulement : dates de changement, PAS les hashes (pas reversibles mais inutile a exporter)
        "SELECT changed_at FROM password_history WHERE user_id = ? ORDER BY changed_at DESC",
        [$userId]
    ),
];

// Liste des cles API creees PAR le user (si superadmin)
if ((int)($_SESSION['role_id'] ?? 0) === 3) {
    $export['api_keys_created'] = fetchAllSafe($pdo,
        "SELECT name, key_prefix, scope_json, created_at, revoked_at, last_used_at "
        . "FROM api_keys WHERE created_by = ?",
        [$userId]
    );
}

$filename = sprintf('rootwarden-export-user-%d-%s.json', $userId, date('Ymd-His'));

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

echo json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
