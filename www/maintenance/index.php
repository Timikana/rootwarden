<?php
/**
 * maintenance/index.php - Fenetres de maintenance / calendrier de changements.
 *
 * Definit les plages horaires hebdomadaires pendant lesquelles les actions
 * mutantes (mises a jour, reboot) sont autorisees. Hors de ces plages, ces
 * actions sont bloquees par le backend (sauf superadmin).
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

$machines = [];
try {
    $machines = $pdo->query("SELECT id, name FROM machines ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {}
$dayLabels = [t('maint.mon'), t('maint.tue'), t('maint.wed'), t('maint.thu'), t('maint.fri'), t('maint.sat'), t('maint.sun')];
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('maint.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('maint.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('maint.desc') ?></p>
            </div>
            <button id="new-win-btn" title="<?= t('maint.tip_new') ?>" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                <span><?= t('maint.btn_new') ?></span>
            </button>
        </div>

        <!-- Formulaire -->
        <div id="win-form" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6 space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_name') ?></label>
                    <input id="w-name" type="text" maxlength="100" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_scope') ?></label>
                    <select id="w-scope" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value="global"><?= t('maint.scope_global') ?></option>
                        <option value="machine"><?= t('maint.scope_machine') ?></option>
                    </select>
                </div>
                <div id="w-machine-wrap" class="hidden">
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_machine') ?></label>
                    <select id="w-machine" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <?php foreach ($machines as $m): ?>
                        <option value="<?= (int)$m['id'] ?>"><?= htmlspecialchars($m['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_days') ?></label>
                <div class="flex flex-wrap gap-3 text-sm">
                    <?php foreach ($dayLabels as $i => $lbl): ?>
                    <label class="inline-flex items-center gap-1"><input type="checkbox" class="wd" value="<?= $i ?>" <?= $i < 5 ? 'checked' : '' ?>> <?= htmlspecialchars($lbl) ?></label>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="flex gap-4">
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_start') ?></label>
                    <input id="w-start" type="time" value="22:00" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('maint.f_end') ?></label>
                    <input id="w-end" type="time" value="06:00" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div class="flex items-end">
                    <label class="inline-flex items-center gap-2 text-sm"><input id="w-enabled" type="checkbox" checked> <?= t('maint.f_enabled') ?></label>
                </div>
            </div>
            <p class="text-[11px] text-gray-400"><?= t('maint.overnight_hint') ?></p>
            <div class="flex gap-2">
                <button id="w-save" class="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-2 rounded-lg"><?= t('maint.btn_save') ?></button>
                <button id="w-cancel" class="bg-gray-200 dark:bg-gray-700 text-sm px-4 py-2 rounded-lg"><?= t('maint.btn_cancel') ?></button>
            </div>
        </div>

        <!-- Liste -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('maint.col_name') ?></th>
                        <th class="text-left px-4 py-3"><?= t('maint.col_scope') ?></th>
                        <th class="text-left px-4 py-3"><?= t('maint.col_days') ?></th>
                        <th class="text-left px-4 py-3"><?= t('maint.col_hours') ?></th>
                        <th class="text-left px-4 py-3"><?= t('maint.col_status') ?></th>
                        <th class="px-4 py-3"></th>
                    </tr>
                </thead>
                <tbody id="win-tbody">
                    <tr><td colspan="6" class="px-4 py-6 text-center text-gray-400"><?= t('maint.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>window._dayLabels = <?= json_encode($dayLabels, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP|JSON_UNESCAPED_UNICODE) ?>;</script>
    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/maintenance/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
