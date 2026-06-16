<?php
/**
 * backups/index.php - Sauvegardes BDD : liste, creation, verification, restauration.
 *
 * La restauration est DESTRUCTIVE et reservee au superadmin (verifie aussi cote
 * backend). Un backup de securite est cree automatiquement avant restauration.
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');
$isSuperadmin = ((int)($_SESSION['role_id'] ?? 0)) >= ROLE_SUPERADMIN;
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('backup.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('backup.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('backup.desc') ?></p>
            </div>
            <button id="create-btn" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                <span><?= t('backup.btn_create') ?></span>
            </button>
        </div>

        <?php if ($isSuperadmin): ?>
        <div class="mb-4 p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300 text-sm">
            ⚠️ <?= t('backup.restore_warning') ?>
        </div>
        <?php endif; ?>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('backup.col_file') ?></th>
                        <th class="text-left px-4 py-3"><?= t('backup.col_size') ?></th>
                        <th class="text-left px-4 py-3"><?= t('backup.col_date') ?></th>
                        <th class="px-4 py-3"></th>
                    </tr>
                </thead>
                <tbody id="backup-tbody">
                    <tr><td colspan="4" class="px-4 py-6 text-center text-gray-400"><?= t('backup.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>window._isSuperadmin = <?= $isSuperadmin ? 'true' : 'false' ?>;</script>
    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/backups/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
