<?php
/**
 * graylog/index.php — Module Graylog : forwarding rsyslog + templates editables.
 *
 * Maintenu : Equipe Admin.Sys RootWarden
 * Version  : 1.15.0
 * Modifie  : 2026-04-20
 *
 * 4 onglets : Configuration, Deploiement, Templates, Historique
 * Approche rsyslog : les logs sont forwardes au serveur Graylog qui gere
 * streams/extractors/dashboards cote admin Graylog.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_graylog');

$historyStmt = $pdo->prepare("
    SELECT ul.id, ul.action, ul.created_at, u.name AS user_name
    FROM user_logs ul LEFT JOIN users u ON ul.user_id = u.id
    WHERE ul.action LIKE '[graylog]%'
    ORDER BY ul.created_at DESC LIMIT 100
");
$historyStmt->execute();
$history = $historyStmt->fetchAll(PDO::FETCH_ASSOC);

$jsPath = __DIR__ . '/js/graylog.js';
$jsVersion = file_exists($jsPath) ? substr(hash('sha256', (string)filemtime($jsPath)), 0, 8) : 'dev';
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('graylog.title') ?></title>
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
                <h1 class="text-2xl font-bold"><?= t('graylog.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('graylog.subtitle') ?></p>
            </div>
        </div>

        <div class="border-b border-gray-200 dark:border-gray-700 mb-6">
            <nav class="flex gap-6">
                <button class="tab-btn active px-1 py-3 text-sm" data-tab="config"><?= t('graylog.tab_config') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="deploy"><?= t('graylog.tab_deploy') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="templates"><?= t('graylog.tab_templates') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500" data-tab="history"><?= t('graylog.tab_history') ?></button>
            </nav>
        </div>

        <!-- 1. Configuration -->
        <div class="tab-panel active" data-panel="config">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('graylog.config_title') ?></h3>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-4"><?= t('graylog.config_desc') ?></p>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.server_host') ?></label>
                        <input id="gl-host" type="text" placeholder="graylog.example.com" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.server_port') ?></label>
                        <input id="gl-port" type="number" value="514" min="1" max="65535" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.protocol') ?></label>
                        <select id="gl-proto" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                            <option value="udp">UDP (514 default, lossy)</option>
                            <option value="tcp">TCP (514, reliable)</option>
                            <option value="tls">TLS (6514, chiffre)</option>
                            <option value="relp">RELP (20514, ACK applicatif)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.tls_ca') ?></label>
                        <input id="gl-tls-ca" type="text" placeholder="/etc/ssl/certs/ca-certificates.crt" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.rl_burst') ?></label>
                        <input id="gl-rl-burst" type="number" value="0" min="0" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                    <div>
                        <label class="block text-xs font-medium mb-1"><?= t('graylog.rl_interval') ?></label>
                        <input id="gl-rl-interval" type="number" value="0" min="0" class="w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600">
                    </div>
                </div>
                <button onclick="glSaveConfig()" class="mt-4 px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"><?= t('graylog.save') ?></button>
                <div id="gl-config-status" class="text-xs text-gray-400 mt-2"></div>
            </div>
        </div>

        <!-- 2. Deploiement -->
        <div class="tab-panel" data-panel="deploy">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-bold"><?= t('graylog.deploy_title') ?></h3>
                    <button onclick="glLoadServers()" class="px-3 py-1.5 text-xs bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 rounded-lg"><?= t('graylog.refresh') ?></button>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-3"><?= t('graylog.deploy_desc') ?></p>
                <div id="gl-servers-container" class="overflow-x-auto">
                    <div class="text-sm text-gray-500 text-center py-6"><?= t('graylog.loading') ?></div>
                </div>
            </div>
        </div>

        <!-- 3. Templates rsyslog -->
        <div class="tab-panel" data-panel="templates">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="md:col-span-1 bg-white dark:bg-gray-800 rounded-xl shadow-sm p-3">
                    <div class="flex items-center justify-between mb-2">
                        <h4 class="text-sm font-bold"><?= t('graylog.templates_list') ?></h4>
                        <button onclick="glNewTemplate()" class="text-xs text-blue-500 hover:text-blue-700">+ <?= t('graylog.new') ?></button>
                    </div>
                    <div id="gl-templates-list" class="space-y-1">
                        <div class="text-xs text-gray-400 text-center py-3"><?= t('graylog.loading') ?></div>
                    </div>
                </div>
                <div class="md:col-span-3 bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                    <div class="flex items-center gap-3 mb-3 flex-wrap">
                        <input id="gl-tpl-name" type="text" placeholder="<?= htmlspecialchars(t('graylog.tpl_name')) ?>" class="px-3 py-1.5 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600 flex-1 min-w-[200px]">
                        <input id="gl-tpl-description" type="text" placeholder="<?= htmlspecialchars(t('graylog.tpl_desc')) ?>" class="px-3 py-1.5 text-sm border rounded-lg bg-white dark:bg-gray-700 dark:border-gray-600 flex-1 min-w-[200px]">
                        <label class="flex items-center gap-1 text-sm">
                            <input id="gl-tpl-enabled" type="checkbox" class="form-checkbox">
                            <span><?= t('graylog.tpl_enabled') ?></span>
                        </label>
                        <button onclick="glSaveTemplate()" class="px-3 py-1.5 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg"><?= t('graylog.save') ?></button>
                        <button onclick="glDeleteTemplate()" class="px-3 py-1.5 text-sm bg-red-500 hover:bg-red-600 text-white rounded-lg"><?= t('graylog.delete') ?></button>
                    </div>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mb-2"><?= t('graylog.tpl_editor_hint') ?></p>
                    <textarea id="gl-tpl-editor" spellcheck="false" rows="22" placeholder="# Snippet rsyslog"
                              class="w-full mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border dark:border-gray-700 focus:ring-2 focus:ring-blue-500 focus:outline-none"></textarea>
                    <div id="gl-tpl-status" class="text-xs text-gray-400 mt-2"></div>
                </div>
            </div>
        </div>

        <!-- 4. Historique -->
        <div class="tab-panel" data-panel="history">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('graylog.history_title') ?></h3>
                <?php if (empty($history)): ?>
                <p class="text-sm text-gray-500"><?= t('graylog.history_empty') ?></p>
                <?php else: ?>
                <div class="overflow-x-auto log-max">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-50 dark:bg-gray-700/50">
                            <tr>
                                <th class="text-left px-3 py-2"><?= t('graylog.col_date') ?></th>
                                <th class="text-left px-3 py-2"><?= t('graylog.col_user') ?></th>
                                <th class="text-left px-3 py-2"><?= t('graylog.col_action') ?></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                            <?php foreach ($history as $h): ?>
                            <tr>
                                <td class="px-3 py-2 mono text-xs"><?= htmlspecialchars($h['created_at']) ?></td>
                                <td class="px-3 py-2"><?= htmlspecialchars($h['user_name'] ?? '—') ?></td>
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
$jsKeys = ['graylog.loading', 'graylog.no_servers', 'graylog.confirm_deploy', 'graylog.confirm_uninstall',
    'graylog.confirm_delete_template', 'graylog.deploying', 'graylog.saving', 'graylog.saved',
    'graylog.col_status', 'graylog.col_version', 'graylog.col_last_deploy', 'graylog.col_actions',
    'graylog.btn_deploy', 'graylog.btn_uninstall', 'graylog.btn_test',
    'graylog.status_forwarding', 'graylog.status_not_deployed',
    'graylog.test_sent', 'graylog.enabled', 'graylog.disabled'];
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
<script src="/graylog/js/graylog.js?v=<?= htmlspecialchars($jsVersion) ?>"></script>
</body>
</html>
