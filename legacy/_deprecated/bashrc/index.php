<?php
/**
 * bashrc/index.php - Module Bashrc : deploiement standardise du .bashrc.
 *
 * Maintenu  : Equipe Admin.Sys RootWarden
 * Version   : 1.14.0
 * Modifie   : 2026-04-20
 *
 * 3 onglets :
 *   1. Deploiement - selection serveur + users, preview, deploy
 *   2. Historique - audit log des deploiements (lecture user_logs)
 *   3. Templates  - affichage du template standard embarque
 *
 * Permissions : admin (2) + superadmin (3) + can_manage_bashrc
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_bashrc');

// Liste des serveurs (non archives) avec la date du dernier deploy bashrc.
// Le dernier deploy est extrait de user_logs : action LIKE '[bashrc] deploy%machine_id=X%'.
// LEFT JOIN garde les machines jamais deployees (last_deploy = NULL).
$stmt = $pdo->query("
    SELECT m.id, m.name, m.ip, m.port, m.environment, m.online_status,
           MAX(ul.created_at) AS last_deploy_at
    FROM machines m
    LEFT JOIN user_logs ul
      ON ul.action LIKE CONCAT('[bashrc] deploy%machine_id=', m.id, '%')
     AND ul.action NOT LIKE '%dry_run=True%'
    WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
    GROUP BY m.id, m.name, m.ip, m.port, m.environment, m.online_status
    ORDER BY m.name
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

// Cache-busting hash pour le JS (basé sur mtime du JS local)
$jsPath = __DIR__ . '/js/bashrc.js';
$jsVersion = file_exists($jsPath) ? substr(hash('sha256', (string)filemtime($jsPath)), 0, 8) : 'dev';
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
<?php $tipId = 'bashrc'; $tipTitle = t('tip.bashrc_title'); $tipSteps = [t('tip.bashrc_step1'), t('tip.bashrc_step2'), t('tip.bashrc_step3'), t('tip.bashrc_step4')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
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
                <div class="flex items-center gap-3 mb-3 flex-wrap">
                    <label class="text-sm font-medium text-gray-700 dark:text-gray-300"><?= t('bashrc.servers') ?></label>
                    <span id="machine-count" class="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">0</span>
                    <button type="button" onclick="bashrcMachineAll(true)" class="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700"><?= t('bashrc.all') ?></button>
                    <button type="button" onclick="bashrcMachineAll(false)" class="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700"><?= t('bashrc.none') ?></button>

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

                <!-- Liste serveurs multi-select en vertical avec date dernier deploy
                     (Patch bashrc multi-deploy). Classes Tailwind safe PurgeCSS. -->
                <div id="machine-list" class="border border-gray-200 dark:border-gray-700 rounded-lg mb-4 max-h-72 overflow-y-auto bg-gray-50 dark:bg-gray-800/50">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-100 dark:bg-gray-700/50 sticky top-0">
                            <tr class="text-xs text-gray-500 dark:text-gray-400 uppercase">
                                <th class="px-3 py-2 w-10"></th>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_name') ?></th>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_ip') ?></th>
                                <th class="text-left px-3 py-2 hidden md:table-cell"><?= t('bashrc.col_env') ?></th>
                                <th class="text-left px-3 py-2"><?= t('bashrc.col_last_deploy') ?></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                        <?php foreach ($machines as $m): ?>
                            <?php
                            $envBadge = match($m['environment']) {
                                'PROD'  => 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
                                'DEV'   => 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
                                'TEST'  => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
                                default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
                            };
                            $lastDeploy = $m['last_deploy_at'];
                            $lastStr = $lastDeploy ?: '';
                            // Color : vert si < 30j, ambre si 30-90j, gris si > 90j ou jamais
                            $lastClass = 'text-gray-400 dark:text-gray-500';
                            if ($lastDeploy) {
                                $ageDays = (time() - strtotime($lastDeploy)) / 86400;
                                if ($ageDays < 30) $lastClass = 'text-green-600 dark:text-green-400';
                                elseif ($ageDays < 90) $lastClass = 'text-yellow-600 dark:text-yellow-400';
                                else $lastClass = 'text-red-500 dark:text-red-400';
                            }
                            ?>
                            <tr class="hover:bg-white dark:hover:bg-gray-700/50">
                                <td class="px-3 py-2 text-center">
                                    <input type="checkbox" class="machine-chk" value="<?= (int)$m['id'] ?>"
                                           data-name="<?= htmlspecialchars($m['name'], ENT_QUOTES) ?>"
                                           onchange="bashrcMachineChange()">
                                </td>
                                <td class="px-3 py-2 font-medium"><?= htmlspecialchars($m['name']) ?></td>
                                <td class="px-3 py-2 mono text-xs text-gray-500 dark:text-gray-400"><?= htmlspecialchars($m['ip']) ?></td>
                                <td class="px-3 py-2 hidden md:table-cell">
                                    <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $envBadge ?>">
                                        <?= htmlspecialchars($m['environment']) ?>
                                    </span>
                                </td>
                                <td class="px-3 py-2 text-xs <?= $lastClass ?>" data-utc="<?= htmlspecialchars($lastStr) ?>">
                                    <?php if ($lastDeploy): ?>
                                        <span class="last-deploy-display"><?= htmlspecialchars($lastDeploy) ?></span>
                                    <?php else: ?>
                                        <span class="italic"><?= t('bashrc.never_deployed') ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Bandeau info multi-deploy (visible si >1 serveur coche) -->
                <div id="multi-info" class="hidden mb-3 p-3 rounded-lg bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 text-sm text-blue-800 dark:text-blue-200">
                    <span id="multi-info-text"></span>
                </div>

                <div id="prereq-banner" class="hidden mb-3 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 text-sm text-yellow-800 dark:text-yellow-200">
                    <?= t('bashrc.figlet_missing') ?>
                </div>

                <div id="users-table-container" class="overflow-x-auto">
                    <div class="text-sm text-gray-500 dark:text-gray-400 text-center py-6"><?= t('bashrc.pick_server_first') ?></div>
                </div>

                <div class="flex items-center gap-2 mt-4 flex-wrap">
                    <button id="btn-preview" onclick="bashrcPreview()" disabled
                            class="px-4 py-2 text-sm bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white rounded-lg"><?= t('bashrc.btn_preview') ?></button>
                    <button id="btn-deploy" onclick="bashrcDeploy(false)" disabled
                            class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-lg"><?= t('bashrc.btn_deploy') ?></button>
                    <button id="btn-dryrun" onclick="bashrcDeploy(true)" disabled
                            class="px-4 py-2 text-sm bg-gray-500 hover:bg-gray-600 disabled:bg-gray-300 text-white rounded-lg"><?= t('bashrc.btn_dry_run') ?></button>

                    <!-- Multi-deploy : actif quand >1 serveur coche.
                         Inline styles pour les variants purple-700/300/400 absents
                         du build PurgeCSS (cf. feedback-tailwind-purged-classes). -->
                    <span class="hidden md:inline mx-2 w-px h-6 bg-gray-300 dark:bg-gray-600"></span>
                    <button id="btn-multi-deploy" onclick="bashrcMultiDeploy(false)" disabled
                            class="px-4 py-2 text-sm disabled:bg-gray-400 text-white rounded-lg font-medium"
                            style="background:#7c3aed;"
                            onmouseover="if(!this.disabled)this.style.background='#6d28d9'"
                            onmouseout="if(!this.disabled)this.style.background='#7c3aed'">
                        <?= t('bashrc.btn_multi_deploy') ?>
                    </button>
                    <button id="btn-multi-dryrun" onclick="bashrcMultiDeploy(true)" disabled
                            class="px-4 py-2 text-sm disabled:bg-gray-300 rounded-lg"
                            style="background:#ede9fe;color:#5b21b6;border:1px solid #c4b5fd;"
                            onmouseover="if(!this.disabled){this.style.background='#ddd6fe';}"
                            onmouseout="if(!this.disabled){this.style.background='#ede9fe';}">
                        <?= t('bashrc.btn_multi_dryrun') ?>
                    </button>
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

        <!-- ═══════════════════════════════════════════════════════════════
             ONGLET 3 : Template editable
             ═══════════════════════════════════════════════════════════════ -->
        <div class="tab-panel" data-panel="template">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
                <div class="flex items-center justify-between mb-3 flex-wrap gap-2">
                    <div>
                        <h3 class="text-lg font-bold"><?= t('bashrc.template_title') ?></h3>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= t('bashrc.template_desc') ?></p>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="text-xs text-gray-500 dark:text-gray-400">
                            <span class="mono"><?= t('bashrc.template_lines') ?>: <span id="tpl-lines">-</span></span>
                            &middot;
                            <span class="mono">sha8: <span id="tpl-sha">-</span></span>
                            &middot;
                            <span class="mono"><span id="tpl-bytes">-</span> o</span>
                        </div>
                        <button id="btn-tpl-reset" onclick="bashrcTemplateReset()" class="px-3 py-1.5 text-xs bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded-lg"><?= t('bashrc.template_reset') ?></button>
                        <button id="btn-tpl-save" onclick="bashrcTemplateSave()" class="px-3 py-1.5 text-xs bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white rounded-lg" disabled><?= t('bashrc.template_save') ?></button>
                    </div>
                </div>
                <textarea id="tpl-editor"
                          spellcheck="false"
                          class="w-full bashrc-log mono text-xs bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border border-gray-200 dark:border-gray-700 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                          rows="25"
                          oninput="bashrcTemplateDirty()"
                          placeholder="<?= htmlspecialchars(t('bashrc.loading')) ?>"></textarea>
                <div id="tpl-danger" class="hidden mt-2 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-xs text-red-800 dark:text-red-200"></div>
                <div id="tpl-status" class="text-xs text-gray-400 mt-2"></div>
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
    'bashrc.saving', 'bashrc.template_dirty', 'bashrc.template_saved',
    'bashrc.confirm_save_template', 'bashrc.confirm_reset_template',
    'bashrc.template_danger', 'bashrc.template_danger_confirm',
    // Multi-deploy (patch bashrc multi)
    'bashrc.servers', 'bashrc.mode', 'bashrc.multi_deploy_info', 'bashrc.multi_users_auto',
    'bashrc.multi_pick_2_min', 'bashrc.multi_in_progress',
    'bashrc.confirm_multi_deploy', 'bashrc.confirm_multi_dry',
];
foreach ($jsKeys as $k) {
    echo "  " . json_encode($k) . ": " . json_encode(t($k)) . ",\n";
}
?>
});
</script>
<script src="/bashrc/js/bashrc.js?v=<?= htmlspecialchars($jsVersion) ?>"></script>
<script>
// Formate les dates "dernier deploiement" en local (UTC -> tz navigateur).
// Le PHP rend "YYYY-MM-DD HH:MM:SS" UTC ; on remplace via fmtLocalDate (utils.js).
document.querySelectorAll('#machine-list td[data-utc]').forEach(td => {
    const utc = td.getAttribute('data-utc');
    if (utc && window.fmtLocalDate) {
        const span = td.querySelector('.last-deploy-display');
        if (span) span.textContent = window.fmtLocalDate(utc, utc);
    }
});
</script>
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
