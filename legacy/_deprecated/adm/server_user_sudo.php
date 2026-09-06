<?php
/**
 * server_user_sudo.php - Droits sudo par utilisateur distant (page dediee).
 * Separe de la gestion SFTP (cf server_user_sftp.php) pour la clarte.
 * Acces : superadmin uniquement (backend @require_role(3)).
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([ROLE_SUPERADMIN]);

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$servers = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$selectedId = isset($_GET['server']) ? (int)$_GET['server'] : ($servers[0]['id'] ?? 0);

$users = [];
if ($selectedId) {
    $stmt = $pdo->prepare("SELECT id, username FROM server_user_inventory WHERE machine_id = ? AND status IN ('managed','pending_review') ORDER BY username");
    $stmt->execute([$selectedId]);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
$selectedUserId = isset($_GET['user']) ? (int)$_GET['user'] : ($users[0]['id'] ?? 0);

$existingSudo = null;
if ($selectedId && $selectedUserId) {
    $stmt = $pdo->prepare("SELECT * FROM server_user_sudo_policies WHERE machine_id=? AND server_user_id=?");
    $stmt->execute([$selectedId, $selectedUserId]);
    $existingSudo = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
$cur = $existingSudo['preset'] ?? 'apt_only';
$presets = ['all_nopasswd','restart_services','apt_only','read_logs','systemctl_specific','custom'];
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('sudopol.title') ?> - <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<div class="px-6 py-6 max-w-screen-xl mx-auto">
    <div class="flex items-center justify-between mb-4">
        <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('sudopol.title') ?></h1>
        <span class="text-xs text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30 px-2 py-1 rounded"><?= t('policies.superadmin_badge') ?></span>
    </div>

    <!-- Encadre explicatif -->
    <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl p-4 mb-6">
        <p class="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-1">💡 <?= t('sudopol.intro_title') ?></p>
        <p class="text-sm text-blue-900/80 dark:text-blue-200/80"><?= t('sudopol.intro') ?></p>
    </div>

    <!-- Selecteurs serveur + user -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
        <div class="flex flex-wrap items-center gap-3">
            <label class="text-sm font-medium"><?= t('policies.server_label') ?></label>
            <select onchange="location.href='?server='+this.value" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 min-w-[260px]">
                <?php foreach ($servers as $s): ?>
                <option value="<?= $s['id'] ?>" <?= $s['id'] == $selectedId ? 'selected' : '' ?>><?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>)</option>
                <?php endforeach; ?>
            </select>
            <label class="text-sm font-medium ml-4"><?= t('policies.user_label') ?></label>
            <select onchange="location.href='?server=<?= $selectedId ?>&user='+this.value" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 min-w-[200px]">
                <?php if (empty($users)): ?><option><?= t('policies.no_users') ?></option>
                <?php else: foreach ($users as $u): ?><option value="<?= $u['id'] ?>" <?= $u['id'] == $selectedUserId ? 'selected' : '' ?>><?= htmlspecialchars($u['username']) ?></option>
                <?php endforeach; endif; ?>
            </select>
        </div>
    </div>

<?php if ($selectedId && $selectedUserId): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
        <h2 class="text-base font-semibold mb-4"><?= t('sudopol.choose') ?></h2>
        <form id="sudo-form" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1"><?= t('policies.sudo_preset') ?></label>
                <select name="preset" id="sudo-preset" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    <?php foreach ($presets as $p): ?>
                    <option value="<?= $p ?>" <?= $cur === $p ? 'selected' : '' ?>><?= t('policies.preset_' . $p) ?></option>
                    <?php endforeach; ?>
                </select>
                <!-- Explication EN CLAIR du modele choisi -->
                <p class="text-sm text-gray-600 dark:text-gray-300 mt-2 p-2 bg-gray-50 dark:bg-gray-900/40 rounded" id="preset-help"><?= t('policies.preset_help_' . $cur) ?></p>
            </div>

            <div id="custom-rules-block" class="<?= $cur === 'custom' ? '' : 'hidden' ?>">
                <label class="block text-sm font-medium mb-1"><?= t('policies.custom_rules') ?></label>
                <textarea name="custom_rules" id="sudo-custom-rules" rows="5" placeholder="ALL=(root) NOPASSWD: /usr/bin/docker ps" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono text-xs"><?= htmlspecialchars($existingSudo['custom_rules'] ?? '') ?></textarea>
                <p class="text-xs text-amber-600 mt-1"><?= t('policies.custom_warning') ?></p>
            </div>

            <div id="services-block" class="<?= $cur === 'systemctl_specific' ? '' : 'hidden' ?>">
                <label class="block text-sm font-medium mb-1"><?= t('policies.services_list') ?></label>
                <input type="text" name="services" id="sudo-services" placeholder="nginx, php8.2-fpm, redis-server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                <p class="text-xs text-gray-500 mt-1"><?= t('policies.services_hint') ?></p>
            </div>

            <div class="flex items-center gap-6 pt-2 border-t border-gray-100 dark:border-gray-700">
                <label class="flex items-center gap-2 text-sm pt-2">
                    <input type="checkbox" name="nopasswd" id="sudo-nopasswd" <?= ($existingSudo['nopasswd'] ?? false) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.nopasswd') ?></span>
                </label>
                <label class="flex items-center gap-2 text-sm pt-2">
                    <span><?= t('policies.runas') ?></span>
                    <input type="text" name="runas" id="sudo-runas" value="<?= htmlspecialchars($existingSudo['runas'] ?? 'root') ?>" class="w-32 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-sm">
                </label>
            </div>

            <div class="flex flex-wrap gap-2 pt-2">
                <button type="button" id="btn-deploy" title="<?= t('policies.help_deploy') ?>" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg font-medium"><?= t('policies.btn_deploy') ?></button>
                <button type="button" id="btn-audit" title="<?= t('policies.help_audit') ?>" class="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-2 rounded-lg font-medium"><?= t('policies.btn_audit') ?></button>
                <button type="button" id="btn-remove" title="<?= t('policies.help_remove') ?>" class="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-2 rounded-lg font-medium"><?= t('policies.btn_remove') ?></button>
            </div>
            <p class="text-[11px] text-gray-400"><?= t('policies.help_deploy') ?> · <?= t('policies.help_audit') ?> · <?= t('policies.help_remove') ?></p>
        </form>

        <?php if ($existingSudo): ?>
        <p class="text-xs text-gray-400 mt-4"><?= t('policies.last_deployed') ?>: <?= $existingSudo['last_deployed_at'] ?? 'jamais' ?>
            (<?= $existingSudo['enabled'] ? '<span class="text-green-600">'.t('policies.status_enabled').'</span>' : '<span class="text-gray-500">'.t('policies.status_disabled').'</span>' ?>)</p>
        <?php endif; ?>

        <pre id="pol-output" class="hidden mt-4 bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs font-mono whitespace-pre-wrap"></pre>

        <!-- Historique (repliable) -->
        <div class="mt-6 border-t border-gray-100 dark:border-gray-700 pt-3">
            <button type="button" id="history-toggle" class="text-sm text-blue-600 hover:underline">▸ <?= t('policies.history_toggle') ?></button>
            <div id="history-box" class="hidden mt-3"><div id="history-list" class="space-y-2"></div></div>
        </div>
    </div>
<?php endif; ?>
</div>

<script>
window.POL = {
    type: 'sudo',
    machineId: <?= (int)$selectedId ?>,
    serverUserId: <?= (int)$selectedUserId ?>,
    presetHelp: {
        all_nopasswd: <?= json_encode(t('policies.preset_help_all_nopasswd')) ?>,
        restart_services: <?= json_encode(t('policies.preset_help_restart_services')) ?>,
        apt_only: <?= json_encode(t('policies.preset_help_apt_only')) ?>,
        read_logs: <?= json_encode(t('policies.preset_help_read_logs')) ?>,
        systemctl_specific: <?= json_encode(t('policies.preset_help_systemctl_specific')) ?>,
        custom: <?= json_encode(t('policies.preset_help_custom')) ?>,
    },
    t: {
        confirmRemove: <?= json_encode(t('policies.confirm_remove')) ?>,
        confirmRollback: <?= json_encode(t('policies.confirm_rollback')) ?>,
        deploySuccess: <?= json_encode(t('policies.deploy_success')) ?>,
        deployFail: <?= json_encode(t('policies.deploy_fail')) ?>,
        netError: <?= json_encode(t('policies.net_error')) ?>,
        auditFound: <?= json_encode(t('policies.audit_found')) ?>,
        auditNotFound: <?= json_encode(t('policies.audit_not_found')) ?>,
        removeSuccess: <?= json_encode(t('policies.remove_success')) ?>,
        historyEmpty: <?= json_encode(t('policies.history_empty')) ?>,
        btnRollback: <?= json_encode(t('policies.btn_rollback')) ?>,
        rollbackReason: <?= json_encode(t('policies.rollback_reason')) ?>,
    },
};
</script>
<script src="/adm/js/server_user_policy.js?v=<?= @filemtime(__DIR__ . '/js/server_user_policy.js') ?>"></script>
</body>
</html>
