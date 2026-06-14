<?php
/**
 * approvals/index.php - Workflow d'approbation 4-eyes.
 *
 * Liste les demandes d'approbation des actions destructives et permet a un
 * SECOND admin de les approuver/rejeter (un admin ne peut pas approuver sa
 * propre demande). L'execution se fait quand le demandeur rejoue l'action.
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('appr.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('appr.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('appr.desc') ?></p>
        </div>

        <div class="mb-4 flex gap-2 text-sm">
            <button data-status="pending"  class="appr-tab px-3 py-1.5 rounded-lg bg-blue-600 text-white"><?= t('appr.tab_pending') ?></button>
            <button data-status="approved" class="appr-tab px-3 py-1.5 rounded-lg bg-gray-200 dark:bg-gray-700"><?= t('appr.tab_approved') ?></button>
            <button data-status="rejected" class="appr-tab px-3 py-1.5 rounded-lg bg-gray-200 dark:bg-gray-700"><?= t('appr.tab_rejected') ?></button>
            <button data-status="all"      class="appr-tab px-3 py-1.5 rounded-lg bg-gray-200 dark:bg-gray-700"><?= t('appr.tab_all') ?></button>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('appr.col_action') ?></th>
                        <th class="text-left px-4 py-3"><?= t('appr.col_target') ?></th>
                        <th class="text-left px-4 py-3"><?= t('appr.col_machine') ?></th>
                        <th class="text-left px-4 py-3"><?= t('appr.col_requester') ?></th>
                        <th class="text-left px-4 py-3"><?= t('appr.col_status') ?></th>
                        <th class="px-4 py-3"></th>
                    </tr>
                </thead>
                <tbody id="appr-tbody">
                    <tr><td colspan="6" class="px-4 py-6 text-center text-gray-400"><?= t('appr.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/approvals/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
