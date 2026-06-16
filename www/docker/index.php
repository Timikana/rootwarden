<?php
/**
 * docker/index.php - Inventaire & veille des conteneurs Docker des serveurs.
 *
 * Detecte les conteneurs par serveur, signale les mises a jour d'image (digest
 * distant different) et les stacks git en retard (+ changelog).
 *
 * Permissions : admin (2) / superadmin (3).
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);

$machines = [];
try {
    $machines = $pdo->query("SELECT id, name FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('docker.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('docker.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('docker.desc') ?></p>
            </div>
            <div class="flex items-center gap-2">
                <select id="scan-machine" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-800">
                    <?php foreach ($machines as $m): ?>
                    <option value="<?= (int)$m['id'] ?>"><?= htmlspecialchars($m['name']) ?></option>
                    <?php endforeach; ?>
                </select>
                <button id="scan-one-btn" class="text-sm px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"><?= t('docker.btn_scan_one') ?></button>
                <button id="scan-all-btn" class="text-sm px-3 py-2 bg-gray-700 hover:bg-gray-800 text-white rounded-lg"><?= t('docker.btn_scan_all') ?></button>
            </div>
        </div>

        <div id="docker-summary" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6"></div>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('docker.col_machine') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_container') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_image') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_state') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_image_update') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_git') ?></th>
                        <th class="text-left px-4 py-3"><?= t('docker.col_checked') ?></th>
                    </tr>
                </thead>
                <tbody id="docker-tbody">
                    <tr><td colspan="7" class="px-4 py-6 text-center text-gray-400"><?= t('docker.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/docker/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
