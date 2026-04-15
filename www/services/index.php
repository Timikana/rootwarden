<?php
/**
 * services/index.php — Gestion des services systemd sur les serveurs distants.
 *
 * Permissions : lecteur (1), admin (2), superadmin (3) + can_manage_services
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_services');

// Chargement des serveurs (selon role)
$role = (int) ($_SESSION['role_id'] ?? 0);
if ($role >= 2) {
    $stmt = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name");
} else {
    $stmt = $pdo->prepare("SELECT m.id, m.name, m.ip, m.port FROM machines m INNER JOIN user_machine_access uma ON m.id = uma.machine_id WHERE uma.user_id = ? AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived') ORDER BY m.name");
    $stmt->execute([$_SESSION['user_id']]);
}
$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('services.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <!-- Header -->
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('services.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('services.desc') ?></p>
<?php $tipId = 'services'; $tipTitle = t('tip.services_title'); $tipSteps = [t('tip.services_step1'), t('tip.services_step2'), t('tip.services_step3')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
        </div>

        <!-- Selection serveur -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
                <div class="flex-1 w-full">
                    <label for="server" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= t('services.server_target') ?></label>
                    <select id="server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value=""><?= t('services.select_server') ?></option>
                        <?php foreach ($servers as $s): ?>
                            <option value="<?= htmlspecialchars(json_encode($s)) ?>">
                                <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>:<?= htmlspecialchars($s['port']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="button" onclick="loadServices()" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg font-medium transition-colors text-sm whitespace-nowrap">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    <?= t('services.load') ?>
                </button>
            </div>
        </div>

        <!-- Stats bar -->
        <div id="stats-bar" class="hidden mb-6">
            <div class="flex flex-wrap gap-3">
                <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300">
                    <?= t('services.stat_total') ?> : <span id="stat-total">0</span>
                </span>
                <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                    <?= t('services.stat_running') ?> : <span id="stat-running">0</span>
                </span>
                <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-gray-100 dark:bg-gray-600 text-gray-700 dark:text-gray-300">
                    <?= t('services.stat_stopped') ?> : <span id="stat-stopped">0</span>
                </span>
                <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                    <?= t('services.stat_failed') ?> : <span id="stat-failed">0</span>
                </span>
            </div>
        </div>

        <!-- Filters row -->
        <div id="filters-row" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row gap-3">
                <select id="filter-status" onchange="filterServices()" class="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value=""><?= t('services.filter_all') ?></option>
                    <option value="running"><?= t('services.status_running') ?></option>
                    <option value="stopped"><?= t('services.status_stopped') ?></option>
                    <option value="failed"><?= t('services.status_failed') ?></option>
                </select>
                <select id="filter-category" onchange="filterServices()" class="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value=""><?= t('services.filter_all') ?></option>
                    <option value="web"><?= t('services.cat_web') ?></option>
                    <option value="database"><?= t('services.cat_database') ?></option>
                    <option value="mail"><?= t('services.cat_mail') ?></option>
                    <option value="security"><?= t('services.cat_security') ?></option>
                    <option value="network"><?= t('services.cat_network') ?></option>
                    <option value="system"><?= t('services.cat_system') ?></option>
                    <option value="monitoring"><?= t('services.cat_monitoring') ?></option>
                    <option value="other"><?= t('services.cat_other') ?></option>
                </select>
                <input type="text" id="filter-search" oninput="filterServices()" placeholder="<?= t('services.search_placeholder') ?>" class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
        </div>

        <!-- Services table -->
        <div id="services-table-container" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <th class="py-2 px-3"><?= t('services.th_name') ?></th>
                            <th class="py-2 px-3"><?= t('services.th_status') ?></th>
                            <th class="py-2 px-3"><?= t('services.th_enabled') ?></th>
                            <th class="py-2 px-3"><?= t('services.th_category') ?></th>
                            <th class="py-2 px-3"><?= t('services.th_description') ?></th>
                            <th class="py-2 px-3 text-right"><?= t('services.th_actions') ?></th>
                        </tr>
                    </thead>
                    <tbody id="services-tbody"></tbody>
                </table>
                <p id="no-services-msg" class="hidden text-sm text-gray-400 dark:text-gray-500 py-4 text-center"><?= t('services.no_services') ?></p>
            </div>
        </div>

        <!-- Detail modal -->
        <div id="detail-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 w-full max-w-lg mx-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('services.detail_title') ?> <span id="detail-name" class="text-blue-600 dark:text-blue-400"></span></h3>
                    <button type="button" onclick="closeDetailModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                    </button>
                </div>
                <div class="space-y-3 mb-5">
                    <div class="grid grid-cols-2 gap-3">
                        <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div class="text-xs text-gray-500 dark:text-gray-400 mb-1"><?= t('services.detail_pid') ?></div>
                            <div class="text-sm font-bold text-gray-800 dark:text-gray-200" id="detail-pid">-</div>
                        </div>
                        <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div class="text-xs text-gray-500 dark:text-gray-400 mb-1"><?= t('services.detail_memory') ?></div>
                            <div class="text-sm font-bold text-gray-800 dark:text-gray-200" id="detail-memory">-</div>
                        </div>
                        <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div class="text-xs text-gray-500 dark:text-gray-400 mb-1"><?= t('services.detail_uptime') ?></div>
                            <div class="text-sm font-bold text-gray-800 dark:text-gray-200" id="detail-uptime">-</div>
                        </div>
                        <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div class="text-xs text-gray-500 dark:text-gray-400 mb-1"><?= t('services.detail_status') ?></div>
                            <div class="text-sm font-bold" id="detail-status">-</div>
                        </div>
                    </div>
                    <div class="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div class="text-xs text-gray-500 dark:text-gray-400 mb-1"><?= t('services.detail_description') ?></div>
                        <div class="text-sm text-gray-800 dark:text-gray-200" id="detail-description">-</div>
                    </div>
                </div>
                <div class="flex flex-wrap gap-2" id="detail-actions"></div>
            </div>
        </div>

        <!-- Logs modal -->
        <div id="logs-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 w-full max-w-2xl mx-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('services.logs_title') ?> <span id="logs-service-name" class="text-blue-600 dark:text-blue-400"></span></h3>
                    <button type="button" onclick="closeLogsModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                    </button>
                </div>
                <div class="flex items-center gap-3 mb-3">
                    <select id="logs-lines" class="px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                        <option value="50">50 <?= t('services.logs_lines') ?></option>
                        <option value="100" selected>100 <?= t('services.logs_lines') ?></option>
                        <option value="200">200 <?= t('services.logs_lines') ?></option>
                    </select>
                    <button type="button" onclick="refreshLogs()" class="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors font-medium">
                        <?= t('services.logs_refresh') ?>
                    </button>
                </div>
                <pre id="logs-content" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto overflow-y-auto max-h-96 font-mono"></pre>
            </div>
        </div>

        <!-- Logs -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2 uppercase tracking-wide"><?= t('services.logs') ?></h2>
            <div id="logs-container" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg font-mono max-h-64 overflow-y-auto"></div>
        </div>

    </div>

    <script src="/services/js/main.js?v=<?= filemtime(__DIR__ . '/js/main.js') ?>"></script>

    <?php require_once __DIR__ . '/../footer.php'; ?>

</body>
</html>
