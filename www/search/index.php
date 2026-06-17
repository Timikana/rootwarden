<?php
/**
 * search/index.php - Recherche globale (serveurs / utilisateurs / CVE / tickets / audit).
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');
$q = trim((string)($_GET['q'] ?? ''));
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('search.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('search.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('search.desc') ?></p>
            <?php $tipId = 'search'; $tipTitle = t('tip.search_title'); $tipSteps = [t('tip.search_step1'), t('tip.search_step2'), t('tip.search_step3')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
        </div>

        <div class="mb-6">
            <input id="search-input" type="search" autofocus
                   value="<?= htmlspecialchars($q) ?>"
                   title="<?= t('search.tip_input') ?>"
                   placeholder="<?= t('search.placeholder') ?>"
                   class="w-full md:w-2/3 px-4 py-3 text-base border border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
            <div id="search-meta" class="text-xs text-gray-400 mt-2"></div>
        </div>

        <div id="search-results" class="grid grid-cols-1 md:grid-cols-2 gap-4"></div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/search/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
