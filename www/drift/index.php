<?php
/**
 * drift/index.php - Detection de derive de configuration (config drift).
 *
 * Compare l'etat desire (gere par RootWarden) a l'etat reel des serveurs pour
 * les categories sudo / sshd / fail2ban. Lecture seule cote page ; le scan est
 * declenche via le backend (/drift/scan_all).
 *
 * Permissions : admin (2) / superadmin (3) + can_view_compliance.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_view_compliance');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('drift.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('drift.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('drift.desc') ?></p>
            </div>
            <button id="scan-all-btn"
                    class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                <span><?= t('drift.btn_scan_all') ?></span>
            </button>
        </div>

        <!-- Resume -->
        <div id="drift-summary" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"></div>

        <!-- Tableau -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('drift.col_server') ?></th>
                        <th class="text-left px-4 py-3">sudo</th>
                        <th class="text-left px-4 py-3">sshd</th>
                        <th class="text-left px-4 py-3">fail2ban</th>
                        <th class="text-left px-4 py-3"><?= t('drift.col_checked') ?></th>
                        <th class="px-4 py-3"></th>
                    </tr>
                </thead>
                <tbody id="drift-tbody">
                    <tr><td colspan="6" class="px-4 py-6 text-center text-gray-400"><?= t('drift.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/drift/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
