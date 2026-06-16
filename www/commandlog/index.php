<?php
/**
 * commandlog/index.php - Journal des commandes (trail type bastion).
 *
 * Affiche en lecture seule les commandes privilegiees executees par RootWarden
 * sur les serveurs distants (qui, quoi, ou, quand, resultat).
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
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('cmdlog.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('cmdlog.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('cmdlog.desc') ?></p>
        </div>

        <div class="mb-4 flex flex-wrap items-center gap-3">
            <select id="f-machine" class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800">
                <option value=""><?= t('cmdlog.all_machines') ?></option>
                <?php foreach ($machines as $m): ?>
                <option value="<?= (int)$m['id'] ?>"><?= htmlspecialchars($m['name']) ?></option>
                <?php endforeach; ?>
            </select>
            <select id="f-context" class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800">
                <option value=""><?= t('cmdlog.all_contexts') ?></option>
            </select>
            <button id="refresh-btn" class="text-sm px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"><?= t('cmdlog.refresh') ?></button>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_when') ?></th>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_machine') ?></th>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_user') ?></th>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_context') ?></th>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_command') ?></th>
                        <th class="text-left px-4 py-3"><?= t('cmdlog.col_result') ?></th>
                    </tr>
                </thead>
                <tbody id="cmdlog-tbody">
                    <tr><td colspan="6" class="px-4 py-6 text-center text-gray-400"><?= t('cmdlog.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/commandlog/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
