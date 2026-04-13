<?php
/**
 * fail2ban/fail2ban_manager.php — Gestion Fail2ban sur les serveurs distants.
 *
 * Permissions : admin (2), superadmin (3) + can_manage_fail2ban
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_fail2ban');

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
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('fail2ban.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <!-- Header -->
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('fail2ban.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('fail2ban.desc') ?></p>
<?php $tipId = 'fail2ban'; $tipTitle = t('tip.fail2ban_title'); $tipSteps = [t('tip.fail2ban_step1'), t('tip.fail2ban_step2'), t('tip.fail2ban_step3')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
        </div>

        <!-- Selection serveur + actions -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
                <div class="flex-1 w-full">
                    <label for="server" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= t('fail2ban.server_target') ?></label>
                    <select id="server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value=""><?= t('fail2ban.select_server') ?></option>
                        <?php foreach ($servers as $s): ?>
                            <option value="<?= htmlspecialchars(json_encode($s)) ?>">
                                <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>:<?= htmlspecialchars($s['port']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="button" onclick="loadStatus()" title="Charger le statut Fail2ban du serveur selectionne" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg font-medium transition-colors text-sm whitespace-nowrap">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    <?= t('fail2ban.load_status') ?>
                </button>
            </div>
            <!-- Actions secondaires -->
            <div class="flex flex-wrap gap-2 mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
                <button type="button" onclick="installFail2ban()" id="btn-install" title="Installer le service Fail2ban via apt-get sur le serveur selectionne" class="hidden text-xs px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-700 text-white transition-colors font-medium"><?= t('fail2ban.install') ?></button>
                <button type="button" onclick="installAllFail2ban()" id="btn-install-all" title="Installer Fail2ban sur tous les serveurs qui ne l'ont pas encore" class="hidden text-xs px-3 py-1.5 rounded-lg bg-green-500 hover:bg-green-600 text-white transition-colors font-medium"><?= t('fail2ban.install_all') ?></button>
                <button type="button" onclick="restartFail2ban()" id="btn-restart" title="Redemarrer le service Fail2ban sur le serveur selectionne" class="hidden text-xs px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-600 text-white transition-colors font-medium"><?= t('fail2ban.restart') ?></button>
                <button type="button" onclick="loadConfig()" id="btn-config" title="Afficher le contenu du fichier jail.local du serveur" class="hidden text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('fail2ban.view_config') ?></button>
                <button type="button" onclick="loadF2bLogs()" id="btn-logs" title="Afficher les derniers logs du service Fail2ban" class="hidden text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('fail2ban.view_logs') ?></button>
            </div>
        </div>

        <!-- Statut global -->
        <div id="status-container" class="hidden mb-6">
            <div class="flex items-center gap-3 mb-4">
                <span id="f2b-badge" class="px-3 py-1 rounded-full text-xs font-bold"></span>
                <span id="f2b-version" class="text-sm text-gray-500 dark:text-gray-400"></span>
            </div>

            <!-- Grille jails -->
            <div id="jails-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"></div>
        </div>

        <!-- Services detectes + gestion jails -->
        <div id="services-panel" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('fail2ban.services_jails') ?></h2>
                <button type="button" onclick="loadServices()" class="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"><?= t('fail2ban.btn_refresh') ?></button>
            </div>
            <div id="services-grid" class="space-y-3"></div>
        </div>

        <!-- Modal config jail -->
        <div id="jail-config-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 w-full max-w-md">
                <h3 class="text-lg font-bold text-gray-800 dark:text-gray-100 mb-4"><?= t('fail2ban.configure_jail') ?> <span id="modal-jail-name" class="text-blue-600"></span></h3>
                <div class="space-y-3">
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('fail2ban.template') ?></label>
                        <select id="modal-template" onchange="applyTemplate()" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                            <option value="custom"><?= t('fail2ban.tpl_custom') ?></option>
                            <option value="permissive"><?= t('fail2ban.tpl_permissive') ?></option>
                            <option value="moderate" selected><?= t('fail2ban.tpl_moderate') ?></option>
                            <option value="strict"><?= t('fail2ban.tpl_strict') ?></option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('fail2ban.maxretry_label') ?></label>
                        <input type="number" id="modal-maxretry" value="5" min="1" max="100" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('fail2ban.bantime_label') ?></label>
                        <input type="number" id="modal-bantime" value="3600" min="60" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                        <div class="text-xs text-gray-400 mt-1">600 = 10min, 3600 = 1h, 86400 = 24h</div>
                    </div>
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('fail2ban.findtime_label') ?></label>
                        <input type="number" id="modal-findtime" value="600" min="60" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                    </div>
                </div>
                <div class="flex justify-end gap-2 mt-5">
                    <button type="button" onclick="closeJailModal()" class="px-4 py-2 text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"><?= t('common.cancel') ?></button>
                    <button type="button" onclick="submitEnableJail()" class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium"><?= t('fail2ban.btn_enable') ?></button>
                </div>
            </div>
        </div>

        <!-- Detail jail (apparait au clic sur un jail) -->
        <div id="jail-detail" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100">Jail : <span id="jail-name" class="text-blue-600 dark:text-blue-400"></span></h2>
                <button type="button" onclick="document.getElementById('jail-detail').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>

            <!-- Config -->
            <div class="grid grid-cols-3 gap-4 mb-4">
                <div class="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="text-lg font-bold text-gray-800 dark:text-gray-200" id="cfg-maxretry">-</div>
                    <div class="text-xs text-gray-500">maxretry</div>
                </div>
                <div class="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="text-lg font-bold text-gray-800 dark:text-gray-200" id="cfg-bantime">-</div>
                    <div class="text-xs text-gray-500">bantime (s)</div>
                </div>
                <div class="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="text-lg font-bold text-gray-800 dark:text-gray-200" id="cfg-findtime">-</div>
                    <div class="text-xs text-gray-500">findtime (s)</div>
                </div>
            </div>

            <!-- Ban IP form -->
            <div class="flex gap-2 mb-4">
                <input type="text" id="ban-ip-input" placeholder="<?= t('fail2ban.ban_ip_placeholder') ?>" class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                <button type="button" onclick="banIpFromForm()" title="<?= t('fail2ban.tip_ban') ?>" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors"><?= t('fail2ban.btn_ban') ?></button>
                <button type="button" onclick="banIpAllServers()" class="px-4 py-2 bg-red-800 hover:bg-red-900 text-white rounded-lg text-sm font-medium transition-colors" title="<?= t('fail2ban.tip_ban_global') ?>"><?= t('fail2ban.btn_ban_global') ?></button>
                <button type="button" onclick="unbanAllIps()" title="<?= t('fail2ban.tip_unban_all') ?>" class="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg text-sm font-medium transition-colors"><?= t('fail2ban.btn_unban_all') ?></button>
            </div>

            <!-- Tableau IPs bannies -->
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <th class="py-2 px-3"><?= t('fail2ban.th_banned_ip') ?></th>
                            <th class="py-2 px-3"><?= t('fail2ban.th_country') ?></th>
                            <th class="py-2 px-3 text-right"><?= t('fail2ban.th_action') ?></th>
                        </tr>
                    </thead>
                    <tbody id="banned-ips-table"></tbody>
                </table>
                <p id="no-bans-msg" class="hidden text-sm text-gray-400 dark:text-gray-500 py-4 text-center"><?= t('fail2ban.no_banned_ips') ?></p>
            </div>
        </div>

        <!-- Config viewer -->
        <div id="config-viewer" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100">/etc/fail2ban/jail.local</h2>
                <button type="button" onclick="document.getElementById('config-viewer').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <pre id="jail-config-content" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto max-h-96 font-mono"></pre>
        </div>

        <!-- Logs fail2ban -->
        <div id="f2b-logs-viewer" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100">/var/log/fail2ban.log</h2>
                <button type="button" onclick="document.getElementById('f2b-logs-viewer').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <pre id="f2b-logs-content" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto max-h-96 font-mono"></pre>
        </div>

        <!-- Whitelist IPs -->
        <div id="whitelist-section" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100 mb-3"><?= t('fail2ban.whitelist_title') ?></h2>
            <div class="flex gap-2 mb-3">
                <input type="text" id="whitelist-ip-input" placeholder="<?= t('fail2ban.whitelist_placeholder') ?>" class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 text-sm">
                <button type="button" onclick="addWhitelistIp()" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium"><?= t('fail2ban.btn_add') ?></button>
            </div>
            <div id="whitelist-list" class="flex flex-wrap gap-2"></div>
        </div>

        <!-- Stats timeline -->
        <div id="stats-section" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100 mb-3"><?= t('fail2ban.stats_title') ?></h2>
            <div id="stats-chart" class="flex items-end gap-1 h-32"></div>
        </div>

        <!-- Historique bans -->
        <div id="history-section" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100 mb-3"><?= t('fail2ban.history_title') ?></h2>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="text-left text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <th class="py-2 px-3"><?= t('fail2ban.th_date') ?></th>
                            <th class="py-2 px-3"><?= t('fail2ban.th_jail') ?></th>
                            <th class="py-2 px-3"><?= t('fail2ban.th_ip') ?></th>
                            <th class="py-2 px-3"><?= t('fail2ban.th_action') ?></th>
                            <th class="py-2 px-3"><?= t('fail2ban.th_by') ?></th>
                        </tr>
                    </thead>
                    <tbody id="history-table"></tbody>
                </table>
            </div>
        </div>

        <!-- Logs -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
            <h2 class="text-sm font-semibold text-gray-600 dark:text-gray-400 mb-2 uppercase tracking-wide"><?= t('fail2ban.logs') ?></h2>
            <div id="logs-container" class="bg-gray-900 text-green-400 text-xs p-4 rounded-lg font-mono max-h-64 overflow-y-auto"></div>
        </div>

    </div>

    <script src="/fail2ban/js/fail2banManager.js?v=<?= filemtime(__DIR__ . '/js/fail2banManager.js') ?>"></script>

    <?php require_once __DIR__ . '/../footer.php'; ?>

</body>
</html>
