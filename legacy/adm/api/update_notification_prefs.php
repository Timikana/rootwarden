<?php
/**
 * update_notification_prefs.php - Toggle une preference de notification (endpoint htmx)
 *
 * Pattern identique a update_permissions.php : retourne le label HTML mis a jour.
 * Acces requis : superadmin (role_id = 3).
 */

require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

checkAuth([ROLE_SUPERADMIN]);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Methode non autorisee']);
    exit();
}

checkCsrfToken();

$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (str_contains($contentType, 'application/json')) {
    $data = json_decode(file_get_contents('php://input'), true);
} else {
    $data = $_POST;
}

if (!isset($data['user_id'], $data['event_type'], $data['value'])) {
    echo json_encode(['success' => false, 'message' => 'Donnees manquantes']);
    exit();
}

$user_id    = intval($data['user_id']);
$event_type = $data['event_type'];
$value      = intval($data['value']);

$allowedTypes = [
    'cve_scan', 'ssh_audit', 'compliance_report',
    'security_alert', 'backup_status', 'update_status',
];

if (!in_array($event_type, $allowedTypes, true)) {
    echo json_encode(['success' => false, 'message' => 'Type evenement non valide']);
    exit();
}

$stmt = $pdo->prepare("
    INSERT INTO notification_preferences (user_id, event_type, enabled)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE enabled = ?, updated_at = NOW()
");
$success = $stmt->execute([$user_id, $event_type, $value, $value]);

if ($success) {
    require_once __DIR__ . '/../includes/audit_log.php';
    audit_log($pdo, ($value ? 'Activation' : 'Desactivation') . " notification $event_type pour user #$user_id");

    if (!empty($_SERVER['HTTP_HX_REQUEST'])) {
        $checked = (bool)$value;
        $checkCls = $checked
            ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
            : 'bg-gray-50 dark:bg-gray-700/30 border-gray-200 dark:border-gray-700';

        $evLabels = [
            'cve_scan'          => [t('notif_pref.cve_scan'),          t('notif_pref.cve_scan_desc')],
            'ssh_audit'         => [t('notif_pref.ssh_audit'),         t('notif_pref.ssh_audit_desc')],
            'compliance_report' => [t('notif_pref.compliance_report'), t('notif_pref.compliance_report_desc')],
            'security_alert'    => [t('notif_pref.security_alert'),    t('notif_pref.security_alert_desc')],
            'backup_status'     => [t('notif_pref.backup_status'),     t('notif_pref.backup_status_desc')],
            'update_status'     => [t('notif_pref.update_status'),     t('notif_pref.update_status_desc')],
        ];
        $info = $evLabels[$event_type] ?? [$event_type, ''];
        $checkedAttr = $checked ? 'checked' : '';

        header('HX-Trigger: ' . json_encode(['showToast' => ['message' => t('notif_pref.updated'), 'type' => 'success']]));
        echo <<<HTML
<label class="flex items-center gap-2 px-3 py-2 rounded-lg border {$checkCls} cursor-pointer hover:border-green-300 dark:hover:border-green-600 transition-colors">
    <input type="checkbox" data-user-id="{$user_id}" data-event-type="{$event_type}"
           hx-post="/adm/api/update_notification_prefs.php" hx-trigger="change" hx-target="closest label" hx-swap="outerHTML"
           hx-vals='{"user_id": "{$user_id}", "event_type": "{$event_type}"}'
           {$checkedAttr}
           class="form-checkbox h-3.5 w-3.5 text-green-600 rounded border-gray-300 focus:ring-green-500 flex-shrink-0">
    <div class="min-w-0">
        <div class="text-xs font-medium text-gray-700 dark:text-gray-300">{$info[0]}</div>
        <div class="text-[10px] text-gray-400 truncate">{$info[1]}</div>
    </div>
</label>
HTML;
        exit;
    }
    echo json_encode(['success' => true, 'message' => 'Preference mise a jour']);
} else {
    echo json_encode(['success' => false, 'message' => 'Erreur interne']);
}
