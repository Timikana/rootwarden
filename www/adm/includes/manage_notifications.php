<?php
/**
 * manage_notifications.php - Preferences de notification email/in-app.
 *
 * Inclus dans admin_page.php (onglet Acces & Permissions).
 * Pattern identique a manage_permissions.php : cards details/summary par user,
 * grille de checkboxes htmx par type d'evenement.
 */

$notifGroups = [
    'Securite' => [
        'cve_scan'       => ['label' => t('notif_pref.cve_scan'),       'desc' => t('notif_pref.cve_scan_desc')],
        'ssh_audit'      => ['label' => t('notif_pref.ssh_audit'),      'desc' => t('notif_pref.ssh_audit_desc')],
        'security_alert' => ['label' => t('notif_pref.security_alert'), 'desc' => t('notif_pref.security_alert_desc')],
    ],
    'Rapports' => [
        'compliance_report' => ['label' => t('notif_pref.compliance_report'), 'desc' => t('notif_pref.compliance_report_desc')],
        'backup_status'     => ['label' => t('notif_pref.backup_status'),     'desc' => t('notif_pref.backup_status_desc')],
        'update_status'     => ['label' => t('notif_pref.update_status'),     'desc' => t('notif_pref.update_status_desc')],
    ],
];

$notifStmt = $pdo->query("
    SELECT np.user_id, np.event_type, np.enabled
    FROM notification_preferences np
    JOIN users u ON np.user_id = u.id
    WHERE u.active = 1
");
$notifPrefs = [];
while ($row = $notifStmt->fetch(PDO::FETCH_ASSOC)) {
    $notifPrefs[$row['user_id']][$row['event_type']] = (bool)$row['enabled'];
}

$_nRoleStmt = $pdo->prepare("SELECT role_id FROM users WHERE id = ?");
$_nRoleStmt->execute([$_SESSION['user_id']]);
$_nRoleRow = $_nRoleStmt->fetch(PDO::FETCH_ASSOC);
$canEditNotifs = $_nRoleRow && (int)$_nRoleRow['role_id'] >= 3;

$totalNotifTypes = array_sum(array_map('count', $notifGroups));
?>

<div class="flex items-center justify-between mb-2">
    <div>
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('notif_pref.title') ?></h2>
        <p class="text-xs text-gray-400 mt-0.5"><?= t('notif_pref.desc') ?></p>
    </div>
    <input type="text" id="notif-filter" placeholder="<?= t('common.filter') ?>"
           class="w-44 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 flex-shrink-0"
           oninput="document.querySelectorAll('.notif-card').forEach(c => { c.style.display = c.dataset.name.includes(this.value.toLowerCase()) ? '' : 'none'; })">
</div>

<div class="space-y-3">
<?php
$nUsersStmt = $pdo->query("SELECT u.id, u.name, u.email, u.role_id, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.active = 1 ORDER BY u.role_id DESC, u.name");
while ($user = $nUsersStmt->fetch(PDO::FETCH_ASSOC)):
    $hasEmail = !empty($user['email']) && $user['email'] !== 'admin@example.com';
    $roleCls = match((int)$user['role_id']) {
        3 => 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
        2 => 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
    };
    $activeNotifs = 0;
    foreach ($notifGroups as $perms) {
        foreach ($perms as $key => $info) {
            if ($notifPrefs[$user['id']][$key] ?? false) $activeNotifs++;
        }
    }
?>
<details class="notif-card bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden"
         data-name="<?= htmlspecialchars(strtolower($user['name'])) ?>">
    <summary class="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 select-none">
        <div class="w-8 h-8 rounded-full bg-green-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            <?= strtoupper(substr($user['name'], 0, 1)) ?>
        </div>
        <span class="font-medium text-sm text-gray-800 dark:text-gray-200"><?= htmlspecialchars($user['name']) ?></span>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $roleCls ?>"><?= htmlspecialchars($user['role']) ?></span>
        <span class="text-xs px-2 py-0.5 rounded-full <?= $activeNotifs === $totalNotifTypes ? 'bg-green-50 dark:bg-green-900/30 text-green-600 dark:text-green-300 font-medium' : ($activeNotifs > 0 ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 font-medium' : 'bg-gray-100 dark:bg-gray-700 text-gray-400') ?>"><?= $activeNotifs ?>/<?= $totalNotifTypes ?> <?= t('notif_pref.active') ?></span>
        <?php if (!$hasEmail): ?>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300" title="<?= t('notif_pref.no_email_tip') ?>"><?= t('notif_pref.no_email') ?></span>
        <?php endif; ?>
    </summary>

    <div class="px-4 pb-4 pt-2 border-t border-gray-100 dark:border-gray-700">
        <?php foreach ($notifGroups as $groupName => $events): ?>
        <div class="mb-3">
            <div class="text-[10px] text-gray-400 uppercase tracking-wider mb-1.5"><?= $groupName ?></div>
            <div class="grid grid-cols-2 md:grid-cols-3 gap-2">
                <?php foreach ($events as $evKey => $evInfo):
                    $checked = $notifPrefs[$user['id']][$evKey] ?? false;
                    $checkCls = $checked ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800' : 'bg-gray-50 dark:bg-gray-700/30 border-gray-200 dark:border-gray-700';
                ?>
                <label class="flex items-center gap-2 px-3 py-2 rounded-lg border <?= $checkCls ?> <?= $canEditNotifs ? 'cursor-pointer hover:border-green-300 dark:hover:border-green-600' : '' ?> transition-colors">
                    <?php if ($canEditNotifs): ?>
                    <input type="checkbox" data-user-id="<?= $user['id'] ?>" data-event-type="<?= $evKey ?>"
                           hx-post="/adm/api/update_notification_prefs.php" hx-trigger="change" hx-target="closest label" hx-swap="outerHTML"
                           hx-vals='{"user_id": "<?= $user['id'] ?>", "event_type": "<?= $evKey ?>"}'
                           <?= $checked ? 'checked' : '' ?>
                           class="form-checkbox h-3.5 w-3.5 text-green-600 rounded border-gray-300 focus:ring-green-500 flex-shrink-0">
                    <?php else: ?>
                    <span class="w-3.5 h-3.5 flex-shrink-0 <?= $checked ? 'text-green-500' : 'text-gray-400' ?>"><?= $checked ? '&#10003;' : '&#10007;' ?></span>
                    <?php endif; ?>
                    <div class="min-w-0">
                        <div class="text-xs font-medium text-gray-700 dark:text-gray-300"><?= $evInfo['label'] ?></div>
                        <div class="text-[10px] text-gray-400 truncate"><?= $evInfo['desc'] ?></div>
                    </div>
                </label>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endforeach; ?>

        <?php if ($canEditNotifs): ?>
        <div class="flex items-center gap-2 mt-2 pt-2 border-t border-gray-100 dark:border-gray-700">
            <button onclick="setAllNotifs(<?= $user['id'] ?>, true)" class="text-[10px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-green-50 hover:text-green-700 hover:border-green-300"><?= t('notif_pref.enable_all') ?></button>
            <button onclick="setAllNotifs(<?= $user['id'] ?>, false)" class="text-[10px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-red-50 hover:text-red-700 hover:border-red-300"><?= t('notif_pref.disable_all') ?></button>
        </div>
        <?php endif; ?>
    </div>
</details>
<?php endwhile; ?>
</div>

<script>
document.addEventListener('htmx:configRequest', function(evt) {
    const elt = evt.detail.elt;
    if (elt && elt.type === 'checkbox' && elt.dataset.eventType) {
        evt.detail.parameters['value'] = elt.checked ? 1 : 0;
    }
});

function setAllNotifs(userId, enable) {
    const card = document.querySelector(`.notif-card [data-user-id="${userId}"]`)?.closest('.notif-card');
    if (!card) return;
    card.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        if (cb.checked !== enable) {
            cb.checked = enable;
            htmx.trigger(cb, 'change');
        }
    });
}
</script>
