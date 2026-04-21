<?php
/**
 * ssh-audit/index.php - Audit de configuration SSH des serveurs distants.
 *
 * Permissions : lecteur (1), admin (2), superadmin (3) + can_audit_ssh
 * La securite des actions (fix, save, reload) est geree cote backend (@require_role).
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_audit_ssh');

// Chargement des serveurs
$stmt = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name");
$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('ssh_audit.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <!-- Header -->
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('ssh_audit.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('ssh_audit.desc') ?></p>
<?php $tipId = 'ssh-audit'; $tipTitle = t('tip.audit_title'); $tipSteps = [t('tip.audit_step1'), t('tip.audit_step2'), t('tip.audit_step3'), t('tip.audit_step4')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
        </div>

        <!-- Server selector + buttons -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
                <div class="flex-1 w-full">
                    <label for="server" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= t('ssh_audit.server_target') ?></label>
                    <select id="server" onchange="onServerChange()" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value=""><?= t('ssh_audit.select_server') ?></option>
                        <?php foreach ($servers as $s): ?>
                            <option value="<?= htmlspecialchars(json_encode($s)) ?>">
                                <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>:<?= htmlspecialchars($s['port']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="button" onclick="scanServer()" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg font-medium transition-colors text-sm whitespace-nowrap">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                    <?= t('ssh_audit.btn_scan') ?>
                </button>
                <button type="button" onclick="scanAll()" class="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-lg font-medium transition-colors text-sm whitespace-nowrap">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
                    <?= t('ssh_audit.btn_scan_all') ?>
                </button>
            </div>
        </div>

        <!-- Action bar (visible once server selected) -->
        <div id="action-bar" class="hidden flex flex-wrap items-center gap-2 mb-4">
            <button onclick="openEditor()" class="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
                <?= t('ssh_audit.btn_edit') ?>
            </button>
            <button onclick="reloadSshd()" class="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white transition-colors font-medium">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                <?= t('ssh_audit.btn_reload') ?>
            </button>
            <button onclick="loadBackups()" class="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                <?= t('ssh_audit.btn_backups') ?>
            </button>
        </div>

        <!-- Score card (hidden until scan) -->
        <div id="score-card" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
            <div class="flex flex-col md:flex-row items-center gap-6">
                <div class="flex flex-col items-center">
                    <div id="score-circle" class="relative w-32 h-32 flex items-center justify-center"></div>
                    <span id="score-grade" class="text-3xl font-extrabold mt-2"></span>
                    <span id="score-number" class="text-sm text-gray-500 dark:text-gray-400"></span>
                </div>
                <div class="flex flex-wrap gap-3">
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                        <?= t('ssh_audit.severity_critical') ?> : <span id="count-critical">0</span>
                    </span>
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300">
                        <?= t('ssh_audit.severity_high') ?> : <span id="count-high">0</span>
                    </span>
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300">
                        <?= t('ssh_audit.severity_medium') ?> : <span id="count-medium">0</span>
                    </span>
                    <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300">
                        <?= t('ssh_audit.severity_low') ?> : <span id="count-low">0</span>
                    </span>
                </div>
            </div>
            <div class="mt-4 flex flex-wrap gap-2 justify-end">
                <button type="button" onclick="viewConfig()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <?= t('ssh_audit.btn_view_config') ?>
                </button>
            </div>
        </div>

        <!-- Findings table (hidden until scan) -->
        <div id="findings-container" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-3 uppercase tracking-wide"><?= t('ssh_audit.findings_title') ?></h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <th class="py-2 px-3"><?= t('ssh_audit.th_severity') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_directive') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_current') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_recommended') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_description') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_status') ?></th>
                            <th class="py-2 px-3 text-right"><?= t('ssh_audit.th_action') ?></th>
                        </tr>
                    </thead>
                    <tbody id="findings-tbody"></tbody>
                </table>
                <p id="no-findings-msg" class="hidden text-sm text-gray-400 dark:text-gray-500 py-4 text-center"><?= t('ssh_audit.no_findings') ?></p>
            </div>
        </div>

        <!-- Policies section (collapsible) -->
        <details id="policies-section" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm mb-6">
            <summary class="cursor-pointer p-5 text-sm font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide hover:text-gray-800 dark:hover:text-gray-200 transition-colors">
                <?= t('ssh_audit.policies_title') ?>
            </summary>
            <div class="px-5 pb-5">
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-3"><?= t('ssh_audit.policies_desc') ?></p>
                <div id="policies-list" class="space-y-2">
                    <p class="text-sm text-gray-400 dark:text-gray-500 italic"><?= t('ssh_audit.policies_select_server') ?></p>
                </div>
            </div>
        </details>

        <!-- Config viewer modal -->
        <div id="config-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 w-full max-w-3xl mx-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('ssh_audit.config_title') ?></h3>
                    <button type="button" onclick="closeConfigModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">&times;</button>
                </div>
                <pre id="config-content" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto overflow-y-auto max-h-96 font-mono"></pre>
            </div>
        </div>

        <!-- Fleet view section (hidden until scan-all) -->
        <div id="fleet-container" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-3 uppercase tracking-wide"><?= t('ssh_audit.fleet_title') ?></h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <th class="py-2 px-3"><?= t('ssh_audit.th_server') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_ip') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_score') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_grade') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_critical_count') ?></th>
                            <th class="py-2 px-3"><?= t('ssh_audit.th_last_scan') ?></th>
                        </tr>
                    </thead>
                    <tbody id="fleet-tbody"></tbody>
                </table>
            </div>
        </div>

        <!-- History section -->
        <div id="history-container" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-3 uppercase tracking-wide"><?= t('ssh_audit.history_title') ?></h2>
            <div id="history-list" class="space-y-2"></div>
            <p id="no-history-msg" class="hidden text-sm text-gray-400 dark:text-gray-500 py-4 text-center"><?= t('ssh_audit.no_history') ?></p>
        </div>

        <!-- Activity log -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2 uppercase tracking-wide"><?= t('ssh_audit.logs') ?></h2>
            <div id="logs-container" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg font-mono max-h-64 overflow-y-auto"></div>
        </div>

    </div>

    <!-- Editor modal -->
    <div id="editor-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200"><?= t('ssh_audit.editor_title') ?></h3>
                <button onclick="closeEditor()" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
            </div>
            <div class="px-6 py-2 bg-amber-50 dark:bg-amber-900/40 border-b border-amber-200 dark:border-amber-700">
                <p class="text-xs text-amber-800 dark:text-amber-300 font-medium"><?= t('ssh_audit.editor_warning') ?></p>
            </div>
            <div class="flex-1 overflow-hidden p-4">
                <textarea id="editor-content" class="w-full h-full min-h-[400px] font-mono text-sm bg-gray-900 text-green-400 p-4 rounded-lg border border-gray-700 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500" spellcheck="false"></textarea>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
                <button onclick="closeEditor()" class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"><?= t('common.cancel') ?></button>
                <button onclick="saveConfig()" class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium"><?= t('ssh_audit.btn_save_config') ?></button>
            </div>
        </div>
    </div>

    <!-- Backups modal -->
    <div id="backups-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
                <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200"><?= t('ssh_audit.backups_title') ?></h3>
                <button onclick="document.getElementById('backups-modal').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
            </div>
            <div class="p-6 max-h-80 overflow-y-auto" id="backups-list">
                <p class="text-sm text-gray-400"><?= t('common.loading') ?></p>
            </div>
        </div>
    </div>

    <script src="/ssh-audit/js/main.js?v=<?= filemtime(__DIR__ . '/js/main.js') ?>"></script>

    <?php require_once __DIR__ . '/../footer.php'; ?>

</body>
</html>
