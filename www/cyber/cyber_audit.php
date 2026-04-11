<?php
/**
 * cyber/cyber_audit.php — Audit de securite cyber des serveurs Linux.
 *
 * Score global A-F base sur 6 checks : comptes, sudoers, ports,
 * SUID, MAJ securite, permissions fichiers.
 *
 * Permissions : admin (2) + superadmin (3) + can_cyber_audit
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_cyber_audit');

$stmt = $pdo->query("
    SELECT id, name, ip, port, environment
    FROM machines
    WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
    ORDER BY name
");
$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('cyber.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <!-- Header -->
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('cyber.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('cyber.subtitle') ?></p>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('cyber.desc') ?></p>
        </div>

        <!-- Actions -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
                <div class="flex-1 w-full">
                    <label for="cyber-server" class="block text-sm font-medium mb-1"><?= t('cyber.select_server') ?></label>
                    <select id="cyber-server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm">
                        <option value=""><?= t('cyber.select_server') ?></option>
                        <?php foreach ($servers as $s): ?>
                        <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>)</option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button onclick="scanServer()" class="inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-5 py-2 rounded-lg font-medium text-sm transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                    <?= t('cyber.btn_scan') ?>
                </button>
                <button onclick="scanAll()" class="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-lg font-medium text-sm transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
                    <?= t('cyber.btn_scan_all') ?>
                </button>
            </div>
        </div>

        <!-- Score card (hidden until scan) -->
        <div id="score-card" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
            <div class="flex flex-col md:flex-row items-center gap-6">
                <div class="flex flex-col items-center">
                    <div id="score-circle" class="relative w-32 h-32 flex items-center justify-center"></div>
                    <span id="score-grade" class="text-3xl font-extrabold mt-2"></span>
                    <span id="score-number" class="text-sm text-gray-500 dark:text-gray-400"></span>
                </div>
                <div class="flex flex-wrap gap-3" id="severity-badges"></div>
            </div>
        </div>

        <!-- Findings detail (hidden until scan) -->
        <div id="findings-card" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
            <h2 class="text-lg font-bold mb-4"><?= t('cyber.findings') ?></h2>
            <div id="findings-list" class="space-y-2"></div>
        </div>

        <!-- Fleet overview -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-lg font-bold"><?= t('cyber.fleet_title') ?></h2>
                <div id="fleet-summary" class="flex items-center gap-3 text-sm text-gray-400"></div>
            </div>
            <div class="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table class="w-full table-auto text-sm">
                    <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500 dark:text-gray-400 sticky top-0 z-10">
                        <tr>
                            <th class="p-2 text-left"><?= t('cyber.th_server') ?></th>
                            <th class="p-2"><?= t('cyber.th_env') ?></th>
                            <th class="p-2"><?= t('cyber.th_score') ?></th>
                            <th class="p-2"><?= t('cyber.th_grade') ?></th>
                            <th class="p-2"><?= t('cyber.th_accounts') ?></th>
                            <th class="p-2"><?= t('cyber.th_sudoers') ?></th>
                            <th class="p-2"><?= t('cyber.th_ports') ?></th>
                            <th class="p-2"><?= t('cyber.th_suid') ?></th>
                            <th class="p-2"><?= t('cyber.th_updates') ?></th>
                            <th class="p-2"><?= t('cyber.th_date') ?></th>
                        </tr>
                    </thead>
                    <tbody id="fleet-table"></tbody>
                </table>
            </div>
            <div id="fleet-empty" class="text-center py-8 text-gray-400 text-sm"><?= t('cyber.no_results') ?></div>
        </div>

    </div>

    <script src="/cyber/js/cyberAudit.js?v=<?= filemtime(__DIR__ . '/js/cyberAudit.js') ?>"></script>
    <?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
