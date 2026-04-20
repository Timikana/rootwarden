<?php
/**
 * bashrc/index.php — Module Bashrc : deploiement standardise du .bashrc.
 *
 * Maintenu  : Equipe Admin.Sys RootWarden
 * Version   : 1.14.0
 * Modifie   : 2026-04-20
 *
 * 3 onglets :
 *   1. Deploiement — selection serveur + users, preview, deploy
 *   2. Historique — audit log des deploiements (lecture user_logs)
 *   3. Templates  — affichage du template standard embarque
 *
 * Permissions : admin (2) + superadmin (3) + can_manage_bashrc
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_bashrc');

// Liste des serveurs (non archives)
$stmt = $pdo->query("
    SELECT id, name, ip, port, environment, online_status
    FROM machines
    WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
    ORDER BY name
");
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Historique : dernieres actions bashrc (audit_log via user_logs)
$historyStmt = $pdo->prepare("
    SELECT ul.id, ul.action, ul.created_at, u.name AS user_name
    FROM user_logs ul
    LEFT JOIN users u ON ul.user_id = u.id
    WHERE ul.action LIKE '[bashrc]%'
    ORDER BY ul.created_at DESC
    LIMIT 100
");
$historyStmt->execute();
$history = $historyStmt->fetchAll(PDO::FETCH_ASSOC);

// Template (lecture du fichier backend pour affichage onglet 3)
$templatePath = __DIR__ . '/../../backend/templates/bashrc_standard.sh';
$templateContent = file_exists($templatePath)
    ? file_get_contents($templatePath)
    : "# Template introuvable : $templatePath";
$templateLines = substr_count($templateContent, "\n") + 1;
$templateSha = substr(hash('sha256', $templateContent), 0, 8);
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('bashrc.title') ?></title>
    <style>
        .tab-btn { transition: all 0.15s; }
        .tab-btn.active { border-bottom: 2px solid #3b82f6; color: #3b82f6; font-weight: 600; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }
        .diff-add  { background-color: rgba(34, 197, 94, 0.15); color: #22c55e; }
        .diff-del  { background-color: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .diff-hdr  { color: #3b82f6; font-weight: bold; }
        .mono      { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        .bashrc-log { max-height: 500px; overflow-y: auto; }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <div class="flex items-start justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('bashrc.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('bashrc.subtitle') ?></p>
            </div>
        </div>

        <!-- Onglets -->
        <div class="border-b border-gray-200 dark:border-gray-700 mb-6">
            <nav class="flex gap-6">
                <button class="tab-btn active px-1 py-3 text-sm" data-tab="deploy"><?= t('bashrc.tab_deploy') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500 dark:text-gray-400" data-tab="history"><?= t('bashrc.tab_history') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500 dark:text-gray-400" data-tab="template"><?= t('bashrc.tab_template') ?></button>
            </nav>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════
             ONGLET 1 : Deploiement
             ═══════════════════════════════════════════════════════════════ -->
        <div class="tab-panel active" data-panel="deploy">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-4">
                <div class="flex items-center gap-3 mb-4 flex-wrap">
                    <label class="text-sm font-medium text-gray-700 dark:text-gray-300"><?= t('bashrc.server') ?></label>
                    <select id="machine-select" onchange="bashrcLoadUsers()" class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 min-w-[280px]">
                        <option value=""><?= t('bashrc.select_server') ?></option>
                        <?php foreach ($machines as $m): ?>
                        <option value="<?= (int)$m['id'] ?>">
                            <?= htmlspecialchars($m['name']) ?> (<?= htmlspecialchars($m['ip']) ?>)
                        </option>
                        <?php endforeach; ?>
                    </select>

                    <label class="text-sm font-medium text-gray-700 dark:text-gray-300 ml-4"><?= t('bashrc.mode') ?></label>
                    <select id="deploy-mode" class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value="overwrite"><?= t('bashrc.mode_overwrite') ?></option>
                        <option value="merge" selected><?= t('bashrc.mode_merge') ?></option>
                    </select>

                    <button id="btn-install-figlet" onclick="bashrcInstallFiglet()"
                            class="ml-auto px-3 py-1.5 text-sm bg-yellow-500 hover:bg-yellow-600 text-white rounded-lg hidden">
                        <?= t('bashrc.install_figlet') ?>
                    </button>
                </div>

                <div id="prereq-banner" class="hidden mb-3 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 text-sm text-yellow-800 dark:text-yellow-200">
                    <?= t('bashrc.figlet_missing') ?>
                </div>

                <div id="users-table-container" class="overflow-x-auto">
                    <div class="text-sm text-gray-500 dark:text-gray-400 text-center py-6"><?= t('bashrc.pick_server_first') ?></div>
                </div>

                <div class="flex items-center gap-2 mt-4">
                    <button id="btn-preview" onclick="bashrcPreview()" disabled
                            class="px-4 py-2 text-sm bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white rounded-lg"><?= t('bashrc.btn_preview') ?></button>
                    <button id="btn-deploy" onclick="bashrcDeploy(false)" disabled
                            class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-lg"><?= t('bashrc.btn_deploy') ?></button>
                    <button id="btn-dryrun" onclick="bashrcDeploy(true)" disabled
                            class="px-4 py-2 text-sm bg-gray-500 hover:bg-gray-600 disabled:bg-gray-300 text-white rounded-lg"><?= t('bashrc.btn_dry_run') ?></button>
                </div>
            </div>

            <div id="preview-panel" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-4">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-bold"><?= t('bashrc.preview_title') ?></h3>
                    <button onclick="document.getElementById('preview-panel').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">&#10005;</button>
                </div>
                <div id="preview-content" class="bashrc-log mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3"></div>
            </div>

            <div id="deploy-result" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('bashrc.deploy_result') ?></h3>
                <div id="deploy-result-content" class="text-sm"></div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════
             ONGLET 2 : Historique
             ═══════════════════════════════════════════════════════════════ -->
        <div class="tab-panel" data-panel="history">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <h3 class="text-lg font-bold mb-3"><?= t('bashrc.history_title') ?></h3>
                <?php if (empty($history)): ?>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('bashrc.history_empty') ?></p>
                <?php else: ?>
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-50 dark:bg-gray-700/50">
                            <tr>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_date') ?></th>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_user') ?></th>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_action') ?></th>
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

        <!-- ═══════════════════════════════════════════════════════════════
             ONGLET 3 : Template
             ═══════════════════════════════════════════════════════════════ -->
        <div class="tab-panel" data-panel="template">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-bold"><?= t('bashrc.template_title') ?></h3>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                        <span class="mono"><?= t('bashrc.template_lines') ?>: <?= (int)$templateLines ?></span>
                        &middot;
                        <span class="mono">sha256: <?= htmlspecialchars($templateSha) ?></span>
                    </div>
                </div>
                <p class="text-xs text-gray-500 dark:text-gray-400 mb-2"><?= t('bashrc.template_desc') ?></p>
                <pre class="bashrc-log mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3 whitespace-pre-wrap"><?= htmlspecialchars($templateContent) ?></pre>
            </div>
        </div>

    </div>

<script>
// Bridge i18n pour bashrc.js (cles utilisees cote JS)
window._i18n = Object.assign(window._i18n || {}, {
<?php
$jsKeys = [
    'bashrc.pick_server_first', 'bashrc.loading', 'bashrc.no_users',
    'bashrc.col_user', 'bashrc.col_home', 'bashrc.col_shell',
    'bashrc.col_size', 'bashrc.col_mtime', 'bashrc.col_status', 'bashrc.col_actions',
    'bashrc.status_ok', 'bashrc.status_diff', 'bashrc.status_absent',
    'bashrc.has_custom', 'bashrc.btn_restore', 'bashrc.install_figlet', 'bashrc.installing',
    'bashrc.confirm_dry', 'bashrc.confirm_deploy', 'bashrc.confirm_restore',
    'bashrc.deploying', 'bashrc.preview_empty', 'bashrc.dry_would_run',
    'bashrc.ok', 'bashrc.failed', 'bashrc.skipped',
];
foreach ($jsKeys as $k) {
    echo "  " . json_encode($k) . ": " . json_encode(t($k)) . ",\n";
}
?>
});
</script>
<script src="/bashrc/js/bashrc.js?v=<?= htmlspecialchars($templateSha) ?>"></script>
<script>
// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        document.querySelector(`.tab-panel[data-panel="${btn.dataset.tab}"]`).classList.add('active');
    });
});
</script>
</body>
</html>
