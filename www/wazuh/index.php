<?php
/**
 * wazuh/index.php - Module Wazuh : Agent + rules/decoders/CDB editables.
 *
 * Maintenu : Equipe Admin.Sys RootWarden
 * Version  : 1.15.0
 * Modifie  : 2026-04-20
 *
 * 5 onglets : Configuration, Deploiement, Options, Rules, Historique
 * Permissions : admin(2) + superadmin(3) + can_manage_wazuh
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../includes/feature_flags.php';
require_once __DIR__ . '/../db.php';

// Module Wazuh ON/OFF via WAZUH_ENABLED dans srv-docker.env. Si OFF :
// 404 immediat - le menu cache deja l'entree mais defense-in-depth.
if (!feature_enabled('wazuh')) {
    http_response_code(404);
    echo '<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>Module Wazuh desactive (WAZUH_ENABLED=false).</p></body></html>';
    exit;
}

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_wazuh');

$stmt = $pdo->query("
    SELECT id, name, ip FROM machines
    WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
    ORDER BY name
");
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

$historyStmt = $pdo->prepare("
    SELECT ul.id, ul.action, ul.created_at, u.name AS user_name
    FROM user_logs ul LEFT JOIN users u ON ul.user_id = u.id
    WHERE ul.action LIKE '[wazuh]%'
    ORDER BY ul.created_at DESC LIMIT 100
");
$historyStmt->execute();
$history = $historyStmt->fetchAll(PDO::FETCH_ASSOC);

$jsPath = __DIR__ . '/js/wazuh.js';
$jsVersion = file_exists($jsPath) ? substr(hash('sha256', (string)filemtime($jsPath)), 0, 8) : 'dev';
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('wazuh.title') ?></title>
    <style>
        .tab-btn { transition: all 0.15s; }
        .tab-btn.active { border-bottom: 2px solid #3b82f6; color: #3b82f6; font-weight: 600; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        .log-max { max-height: 500px; overflow-y: auto; }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
    <?php require_once __DIR__ . '/../menu.php'; ?>
    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="flex items-start justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold"><?= t('wazuh.title') ?></h1>
                <p class="text-sm text-gray-500"><?= t('wazuh.subtitle') ?></p>
<?php $tipId = 'wazuh'; $tipTitle = t('tip.wazuh_title'); $tipSteps = [t('tip.wazuh_step1'), t('tip.wazuh_step2'), t('tip.wazuh_step3'), t('tip.wazuh_step4')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
            </div>
        </div>

        <div class="border-b border-gray-200 dark:border-gray-700 mb-6">
            <nav class="flex gap-6">
                <button class="tab-btn active px-1 py-3 text-sm" data-tab="config"><?= t('wazuh.tab_config') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="deploy"><?= t('wazuh.tab_deploy') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="options"><?= t('wazuh.tab_options') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="rules"><?= t('wazuh.tab_rules') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="history"><?= t('wazuh.tab_history') ?></button>
            </nav>
        </div>

        <!-- 1. Configuration manager -->
        <div class="tab-panel active" data-panel="config">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('wazuh.config_title') ?></h3>
                <p class="text-xs text-gray-500 mb-4"><?= t('wazuh.config_desc') ?></p>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.manager_ip') ?></label>
                        <input id="wz-manager-ip" type="text" placeholder="wazuh.example.com" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.manager_port') ?></label>
                        <input id="wz-manager-port" type="number" value="1514" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.registration_port') ?></label>
                        <input id="wz-registration-port" type="number" value="1515" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.registration_password') ?> <span id="wz-reg-pwd-status" class="text-gray-400"></span></label>
                        <input id="wz-reg-pwd" type="password" placeholder="<?= htmlspecialchars(t('wazuh.unchanged')) ?>" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.default_group') ?></label>
                        <input id="wz-default-group" type="text" value="default" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.agent_version') ?></label>
                        <input id="wz-agent-version" type="text" value="latest" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <label class="flex items-center gap-2">
                        <input id="wz-enable-ar" type="checkbox" class="form-checkbox">
                        <span class="text-sm"><?= t('wazuh.enable_active_response_global') ?></span>
                    </label>
                </div>
                <div class="mt-5 border-t pt-4 border-gray-200 dark:border-gray-700">
                    <h4 class="text-sm font-bold mb-2"><?= t('wazuh.api_section') ?></h4>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label class="block text-xs font-medium mb-1"><?= t('wazuh.api_url') ?></label>
                            <input id="wz-api-url" type="text" placeholder="https://wazuh.example.com:55000" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                        </div>
                        <div>
                            <label class="block text-xs font-medium mb-1"><?= t('wazuh.api_user') ?></label>
                            <input id="wz-api-user" type="text" placeholder="wazuh-wui" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                        </div>
                        <div>
                            <label class="block text-xs font-medium mb-1"><?= t('wazuh.api_password') ?> <span id="wz-api-pwd-status" class="text-gray-400"></span></label>
                            <input id="wz-api-pwd" type="password" placeholder="<?= htmlspecialchars(t('wazuh.unchanged')) ?>" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                        </div>
                    </div>
                </div>
                <button onclick="wzSaveConfig()" class="mt-4 px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"><?= t('wazuh.save') ?></button>
                <div id="wz-config-status" class="text-xs text-gray-400 mt-2"></div>
            </div>
        </div>

        <!-- 2. Deploiement -->
        <div class="tab-panel" data-panel="deploy">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-bold"><?= t('wazuh.deploy_title') ?></h3>
                    <button onclick="wzLoadServers()" class="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 rounded-lg"><?= t('wazuh.refresh') ?></button>
                </div>
                <div id="wz-servers-container" class="overflow-x-auto">
                    <div class="text-sm text-gray-500 text-center py-6"><?= t('wazuh.loading') ?></div>
                </div>
            </div>
        </div>

        <!-- 3. Options par serveur -->
        <div class="tab-panel" data-panel="options">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <div class="flex items-center gap-3 mb-4 flex-wrap">
                    <label class="text-sm font-medium"><?= t('wazuh.server') ?></label>
                    <select id="wz-opts-machine" onchange="wzLoadOptions()" class="px-3 py-1.5 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600 min-w-[260px]">
                        <option value=""><?= t('wazuh.select_server') ?></option>
                        <?php foreach ($machines as $m): ?>
                        <option value="<?= (int)$m['id'] ?>"><?= htmlspecialchars($m['name']) ?> (<?= htmlspecialchars($m['ip']) ?>)</option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div id="wz-opts-form" class="hidden">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-medium mb-1"><?= t('wazuh.log_format') ?></label>
                            <select id="wz-opts-logformat" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                                <option value="syslog">syslog</option>
                                <option value="json">json</option>
                                <option value="multi-line">multi-line</option>
                                <option value="snort-full">snort-full</option>
                                <option value="squid">squid</option>
                                <option value="nmapg">nmapg</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs font-medium mb-1"><?= t('wazuh.syscheck_frequency') ?></label>
                            <input id="wz-opts-freq" type="number" value="43200" min="60" max="604800" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                        </div>
                    </div>
                    <div class="mt-3">
                        <label class="block text-xs font-medium mb-1"><?= t('wazuh.fim_paths') ?> <span class="text-gray-400">(<?= t('wazuh.fim_paths_hint') ?>)</span></label>
                        <textarea id="wz-opts-fim" rows="6" placeholder="/etc&#10;/usr/bin&#10;/usr/sbin" class="w-full mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border dark:border-gray-700"></textarea>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
                        <label class="flex items-center gap-2">
                            <input id="wz-opts-ar" type="checkbox" class="form-checkbox">
                            <span class="text-sm"><?= t('wazuh.active_response') ?></span>
                        </label>
                        <label class="flex items-center gap-2">
                            <input id="wz-opts-sca" type="checkbox" checked class="form-checkbox">
                            <span class="text-sm"><?= t('wazuh.sca') ?></span>
                        </label>
                        <label class="flex items-center gap-2">
                            <input id="wz-opts-rk" type="checkbox" checked class="form-checkbox">
                            <span class="text-sm"><?= t('wazuh.rootcheck') ?></span>
                        </label>
                    </div>
                    <button onclick="wzSaveOptions()" class="mt-4 px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"><?= t('wazuh.save') ?></button>
                    <div id="wz-opts-status" class="text-xs text-gray-400 mt-2"></div>
                </div>
            </div>
        </div>

        <!-- 4. Rules / Decoders / CDB -->
        <div class="tab-panel" data-panel="rules">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="md:col-span-1 bg-white dark:bg-gray-800 rounded-xl shadow-sm p-3">
                    <div class="flex items-center justify-between mb-2">
                        <h4 class="text-sm font-bold"><?= t('wazuh.rules_list') ?></h4>
                        <button onclick="wzNewRule()" class="text-xs text-blue-500 hover:text-blue-700">+ <?= t('wazuh.new') ?></button>
                    </div>
                    <div id="wz-rules-list" class="space-y-1">
                        <div class="text-xs text-gray-400 text-center py-3"><?= t('wazuh.loading') ?></div>
                    </div>
                </div>
                <div class="md:col-span-3 bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                    <div class="flex items-center gap-3 mb-3 flex-wrap">
                        <input id="wz-rule-name" type="text" placeholder="<?= htmlspecialchars(t('wazuh.rule_name')) ?>" class="px-3 py-1.5 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600 flex-1 min-w-[200px]">
                        <select id="wz-rule-type" class="px-3 py-1.5 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                            <option value="rules">rules</option>
                            <option value="decoders">decoders</option>
                            <option value="cdb">cdb</option>
                        </select>
                        <button onclick="wzSaveRule()" class="px-3 py-1.5 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"><?= t('wazuh.save') ?></button>
                        <button onclick="wzDeleteRule()" class="px-3 py-1.5 text-sm bg-red-500 hover:bg-red-600 text-white rounded-lg"><?= t('wazuh.delete') ?></button>
                    </div>
                    <textarea id="wz-rule-editor" spellcheck="false" rows="22"
                              class="w-full mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border dark:border-gray-700 focus:ring-2 focus:ring-blue-500 focus:outline-none"></textarea>
                    <div id="wz-rule-status" class="text-xs text-gray-400 mt-2"></div>
                </div>
            </div>
        </div>

        <!-- 5. Historique -->
        <div class="tab-panel" data-panel="history">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('wazuh.history_title') ?></h3>
                <?php if (empty($history)): ?>
                <p class="text-sm text-gray-500"><?= t('wazuh.history_empty') ?></p>
                <?php else: ?>
                <div class="overflow-x-auto log-max">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-50 dark:bg-gray-700/50">
                            <tr>
                                <th class="text-left px-3 py-2"><?= t('wazuh.col_date') ?></th>
                                <th class="text-left px-3 py-2"><?= t('wazuh.col_user') ?></th>
                                <th class="text-left px-3 py-2"><?= t('wazuh.col_action') ?></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                            <?php foreach ($history as $h): ?>
                            <tr>
                                <td class="px-3 py-2 mono text-xs"><?= htmlspecialchars($h['created_at']) ?></td>
                                <td class="px-3 py-2"><?= htmlspecialchars($h['user_name'] ?? '-') ?></td>
                                <td class="px-3 py-2 mono text-xs break-all"><?= htmlspecialchars($h['action']) ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

<script>
window._i18n = Object.assign(window._i18n || {}, {
<?php
$jsKeys = ['wazuh.loading', 'wazuh.no_servers', 'wazuh.confirm_install', 'wazuh.confirm_uninstall',
    'wazuh.confirm_restart', 'wazuh.confirm_delete_rule', 'wazuh.saving', 'wazuh.saved',
    'wazuh.col_agent_id', 'wazuh.col_status', 'wazuh.col_version', 'wazuh.col_group', 'wazuh.col_actions',
    'wazuh.btn_install', 'wazuh.btn_detect', 'wazuh.btn_detect_tip', 'wazuh.btn_uninstall', 'wazuh.btn_restart', 'wazuh.btn_setgroup',
    'wazuh.status_active', 'wazuh.status_disconnected', 'wazuh.status_never', 'wazuh.status_pending', 'wazuh.status_unknown',
    'wazuh.pwd_set', 'wazuh.pwd_not_set', 'wazuh.prompt_group'];
foreach ($jsKeys as $k) echo "  " . json_encode($k) . ": " . json_encode(t($k)) . ",\n";
?>
});
document.querySelectorAll('.tab-btn').forEach(btn => btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelector(`.tab-panel[data-panel="${btn.dataset.tab}"]`).classList.add('active');
}));
</script>
<script src="/wazuh/js/wazuh.js?v=<?= htmlspecialchars($jsVersion) ?>"></script>
</body>
</html>
