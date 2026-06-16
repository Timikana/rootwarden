<?php
/**
 * tasks/index.php - Centre de taches : historique de l'activite de fond.
 *
 * Vue operationnelle admin (lecture seule) : scans CVE/SSH/drift, backups, etc.
 * enregistres via task_tracker cote backend.
 *
 * Permissions : admin (2) / superadmin (3).
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('tasks.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('tasks.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('tasks.desc') ?></p>
            </div>
            <div class="flex items-center gap-2">
                <select id="task-filter" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-800">
                    <option value=""><?= t('tasks.filter_all') ?></option>
                    <option value="running"><?= t('tasks.st_running') ?></option>
                    <option value="success"><?= t('tasks.st_success') ?></option>
                    <option value="error"><?= t('tasks.st_error') ?></option>
                </select>
                <label class="text-xs text-gray-500 flex items-center gap-1">
                    <input type="checkbox" id="task-autorefresh" checked> <?= t('tasks.autorefresh') ?>
                </label>
            </div>
        </div>

        <div id="task-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"></div>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('tasks.col_status') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tasks.col_type') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tasks.col_label') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tasks.col_started') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tasks.col_duration') ?></th>
                    </tr>
                </thead>
                <tbody id="task-tbody">
                    <tr><td colspan="5" class="px-4 py-6 text-center text-gray-400"><?= t('tasks.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/tasks/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
