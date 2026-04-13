<?php
/**
 * platform_keys.php — Gestion de la cle plateforme + audit users distants
 * Acces : superadmin uniquement
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_platform_key');

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');

// Serveurs avec statut keypair
$servers = $pdo->query("SELECT id, name, ip, port, user, online_status, environment,
    platform_key_deployed, platform_key_deployed_at, ssh_password_required,
    service_account_deployed, service_account_deployed_at
    FROM machines ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

$nbDeployed = count(array_filter($servers, fn($s) => $s['platform_key_deployed']));
$nbTotal = count($servers);
$nbPasswordRemoved = count(array_filter($servers, fn($s) => !$s['ssh_password_required']));
$nbServiceAccount = count(array_filter($servers, fn($s) => $s['service_account_deployed']));
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>Securite SSH — <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('platform.title') ?></span>
</nav>

<div class="px-6 py-6 max-w-screen-xl mx-auto">

    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold"><?= t('platform.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('platform.desc') ?></p>
<?php $tipId = 'platform-key'; $tipTitle = t('tip.platform_title'); $tipSteps = [t('tip.platform_step1'), t('tip.platform_step2'), t('tip.platform_step3'), t('tip.platform_step4')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
        </div>
        <div class="flex gap-2">
            <button onclick="deployAll()" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg font-medium" title="<?= t('platform.tip_deploy_all') ?>">
                <?= t('platform.btn_deploy_keypair') ?>
            </button>
            <button onclick="deployAllServiceAccounts()" class="bg-indigo-600 hover:bg-indigo-700 text-white text-sm px-4 py-2 rounded-lg font-medium" title="<?= t('platform.tip_admin_distant') ?>">
                <?= t('platform.btn_admin_distant') ?> (<?= $nbDeployed - $nbServiceAccount ?>)
            </button>
            <?php if ($nbDeployed > $nbPasswordRemoved): ?>
            <button onclick="massRemovePasswords()" class="bg-orange-500 hover:bg-orange-600 text-white text-sm px-4 py-2 rounded-lg font-medium" title="<?= t('platform.tip_suppr_passwords') ?>">
                <?= t('platform.btn_suppr_passwords') ?> (<?= $nbDeployed - $nbPasswordRemoved ?>)
            </button>
            <?php endif; ?>
            <button onclick="regenerateKey()" class="border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 text-sm px-4 py-2 rounded-lg" title="<?= t('platform.tip_regenerate') ?>">
                <?= t('platform.btn_regenerate') ?>
            </button>
        </div>
    </div>

    <!-- Pubkey -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
        <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300"><?= t('platform.pubkey_label') ?></span>
            <button onclick="copyPubkey()" class="text-xs text-blue-500 hover:text-blue-700"><?= t('platform.btn_copy') ?></button>
        </div>
        <div id="pubkey-display" class="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 font-mono text-xs text-gray-600 dark:text-gray-400 truncate cursor-pointer select-all" title="<?= t('platform.tip_click_copy') ?>" onclick="copyPubkey()">
            <?= t('common.loading') ?>
        </div>
    </div>

    <!-- Progression -->
    <div class="grid grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
            <div class="text-2xl font-bold <?= $nbDeployed === $nbTotal ? 'text-green-600' : 'text-orange-500' ?>"><?= $nbDeployed ?>/<?= $nbTotal ?></div>
            <div class="text-xs text-gray-400 uppercase mt-1"><?= t('platform.stat_keypair_deployed') ?></div>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
            <div class="text-2xl font-bold <?= $nbServiceAccount === $nbTotal ? 'text-green-600' : 'text-indigo-500' ?>"><?= $nbServiceAccount ?>/<?= $nbTotal ?></div>
            <div class="text-xs text-gray-400 uppercase mt-1"><?= t('platform.stat_admin_distant') ?></div>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
            <div class="text-2xl font-bold text-blue-600"><?= $nbTotal - $nbDeployed ?></div>
            <div class="text-xs text-gray-400 uppercase mt-1"><?= t('platform.stat_pending') ?></div>
        </div>
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
            <div class="text-2xl font-bold text-green-600"><?= $nbPasswordRemoved ?></div>
            <div class="text-xs text-gray-400 uppercase mt-1"><?= t('platform.stat_password_removed') ?></div>
        </div>
    </div>

    <!-- Barre de progression migration -->
    <?php if ($nbTotal > 0):
        $pctDeployed = round(($nbDeployed / $nbTotal) * 100);
        $pctClean = round(($nbPasswordRemoved / $nbTotal) * 100);
    ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
        <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300"><?= t('platform.migration_progress') ?></span>
            <span class="text-xs text-gray-400">
                <?php if ($nbPasswordRemoved === $nbTotal): ?>
                    <?= t('platform.migration_done') ?>
                <?php elseif ($nbDeployed === $nbTotal): ?>
                    <?= t('platform.migration_remove_passwords') ?>
                <?php else: ?>
                    <?= ($nbTotal - $nbDeployed) . ' ' . t('platform.migration_servers_remaining') ?>
                <?php endif; ?>
            </span>
        </div>
        <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
            <div class="h-full rounded-full transition-all duration-500 flex">
                <div class="bg-green-500 h-full" style="width: <?= $pctClean ?>%" title="<?= t('platform.legend_keypair_only') ?>"></div>
                <div class="bg-yellow-400 h-full" style="width: <?= $pctDeployed - $pctClean ?>%" title="<?= t('platform.legend_keypair_pwd') ?>"></div>
            </div>
        </div>
        <div class="flex justify-between text-[10px] text-gray-400 mt-1">
            <span class="flex items-center gap-1"><span class="inline-block w-2 h-2 rounded-full bg-red-400"></span> <?= t('platform.legend_password_only') ?></span>
            <span class="flex items-center gap-1"><span class="inline-block w-2 h-2 rounded-full bg-yellow-400"></span> <?= t('platform.legend_keypair_pwd') ?></span>
            <span class="flex items-center gap-1"><span class="inline-block w-2 h-2 rounded-full bg-green-500"></span> <?= t('platform.legend_keypair_only') ?></span>
        </div>
    </div>
    <?php endif; ?>

    <!-- Tableau serveurs -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-4 py-3 text-left"><?= t('platform.th_server') ?></th>
                        <th class="px-4 py-3 text-left"><?= t('platform.th_ip') ?></th>
                        <th class="px-4 py-3 text-center"><?= t('platform.th_auth') ?></th>
                        <th class="px-4 py-3 text-center"><?= t('platform.th_keypair') ?></th>
                        <th class="px-4 py-3 text-center"><?= t('platform.th_admin_distant') ?></th>
                        <th class="px-4 py-3 text-center"><?= t('platform.th_password') ?></th>
                        <th class="px-4 py-3 text-left"><?= t('platform.th_deploy_date') ?></th>
                        <th class="px-4 py-3"><?= t('platform.th_actions') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($servers as $s):
                        $deployed = $s['platform_key_deployed'];
                        $pwRequired = $s['ssh_password_required'];
                        $saDeployed = $s['service_account_deployed'];
                    ?>
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/30" id="row-<?= $s['id'] ?>">
                        <td class="px-4 py-3 font-medium"><?= htmlspecialchars($s['name']) ?></td>
                        <td class="px-4 py-3 font-mono text-xs text-gray-500"><?= htmlspecialchars($s['ip']) ?>:<?= $s['port'] ?></td>
                        <td class="px-4 py-3 text-center">
                            <?php if ($deployed && !$pwRequired): ?>
                                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">keypair</span>
                            <?php elseif ($deployed): ?>
                                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">keypair + pwd</span>
                            <?php else: ?>
                                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">password</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-3 text-center">
                            <?= $deployed ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-gray-400">&#10007;</span>' ?>
                        </td>
                        <td class="px-4 py-3 text-center">
                            <?php if ($saDeployed): ?>
                                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">rootwarden</span>
                            <?php else: ?>
                                <span class="text-gray-400">&#10007;</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-4 py-3 text-center">
                            <?= $pwRequired ? '<span class="text-orange-500">' . t('platform.status_present') . '</span>' : '<span class="text-green-500">' . t('platform.status_removed') . '</span>' ?>
                        </td>
                        <td class="px-4 py-3 text-xs text-gray-400">
                            <?= $s['platform_key_deployed_at'] ? date('d/m/Y H:i', strtotime($s['platform_key_deployed_at'])) : '—' ?>
                        </td>
                        <td class="px-4 py-3">
                            <div class="flex gap-1">
                                <?php if (!$deployed): ?>
                                <button onclick="deployKey(<?= $s['id'] ?>)" class="text-[10px] px-2 py-1 rounded bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 hover:bg-blue-200" title="<?= t('platform.tip_deploy_single') ?>"><?= t('platform.btn_deploy') ?></button>
                                <?php endif; ?>
                                <button onclick="testKey(<?= $s['id'] ?>)" class="text-[10px] px-2 py-1 rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200"><?= t('platform.btn_test') ?></button>
                                <?php if ($deployed && !$saDeployed): ?>
                                <button onclick="deployServiceAccount(<?= $s['id'] ?>)" class="text-[10px] px-2 py-1 rounded bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300 hover:bg-indigo-200" title="<?= t('platform.tip_deploy_admin') ?>"><?= t('platform.btn_admin') ?></button>
                                <?php endif; ?>
                                <?php if ($deployed && $saDeployed && $pwRequired): ?>
                                <button onclick="removePassword(<?= $s['id'] ?>, '<?= htmlspecialchars(addslashes($s['name'])) ?>')" class="text-[10px] px-2 py-1 rounded bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300 hover:bg-red-200"><?= t('platform.btn_suppr_pwd') ?></button>
                                <?php elseif ($deployed && !$pwRequired): ?>
                                <button onclick="reenterPassword(<?= $s['id'] ?>, '<?= htmlspecialchars(addslashes($s['name'])) ?>')" class="text-[10px] px-2 py-1 rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200"><?= t('platform.btn_reenter_pwd') ?></button>
                                <?php endif; ?>
                                <button onclick="scanUsers(<?= $s['id'] ?>)" class="text-[10px] px-2 py-1 rounded bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300 hover:bg-purple-200"><?= t('platform.btn_users') ?></button>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Logs d'operations -->
    <div id="deploy-logs" class="mt-6 hidden">
        <div class="bg-gray-900 rounded-xl shadow-sm overflow-hidden">
            <div class="px-4 py-3 bg-gray-800 border-b border-gray-700 flex items-center justify-between">
                <h3 class="text-sm font-semibold text-gray-300"><?= t('platform.logs') ?></h3>
                <button onclick="document.getElementById('deploy-logs').classList.add('hidden')" class="text-xs text-gray-500 hover:text-gray-300"><?= t('common.close') ?></button>
            </div>
            <div id="deploy-logs-content" class="p-4 font-mono text-xs text-green-400 max-h-64 overflow-y-auto whitespace-pre-wrap" style="background:#111827;"></div>
        </div>
    </div>

    <!-- Zone scan users -->
    <div id="users-scan-result" class="mt-6 hidden"></div>
</div>

<script>
// Charger la pubkey
(async function() {
    try {
        const r = await fetch(`${window.API_URL}/platform_key`);
        const d = await r.json();
        document.getElementById('pubkey-display').textContent = d.public_key || __('platform_pubkey_none');
    } catch(e) {}
})();

function copyPubkey() {
    const text = document.getElementById('pubkey-display').textContent;
    navigator.clipboard.writeText(text).then(() => toast(__('platform_key_copied'), 'success'));
}

function appendLog(msg, type = 'info') {
    const container = document.getElementById('deploy-logs');
    const content = document.getElementById('deploy-logs-content');
    container.classList.remove('hidden');
    const ts = new Date().toLocaleTimeString('fr-FR');
    const color = type === 'error' ? 'text-red-400' : type === 'success' ? 'text-green-400' : 'text-gray-400';
    content.innerHTML += `<span class="${color}">[${ts}] ${msg}</span>\n`;
    content.scrollTop = content.scrollHeight;
}

function clearLogs() {
    document.getElementById('deploy-logs-content').innerHTML = '';
}

async function deployKey(machineId) {
    toast(__('platform_deploying'), 'info');
    clearLogs();
    appendLog(__('platform_deploying_machine').replace('%s', machineId));
    const r = await fetch(`${window.API_URL}/deploy_platform_key`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_ids: [machineId]})
    });
    const d = await r.json();
    const res = d.results?.[0];
    if (res?.success) {
        appendLog(res.message, 'success');
        toast(__('platform_keypair_deployed_ok'), 'success');
        setTimeout(() => location.reload(), 1500);
    } else {
        appendLog(res?.message || __('platform_unknown_error'), 'error');
        toast(res?.message || __('toast_error'), 'error');
    }
}

async function deployAll() {
    const ids = [<?= implode(',', array_column(array_filter($servers, fn($s) => !$s['platform_key_deployed']), 'id')) ?>];
    if (ids.length === 0) { toast(__('platform_all_servers_have_keypair'), 'info'); return; }
    if (!confirm(__('platform_confirm_deploy').replace('%s', ids.length))) return;
    clearLogs();
    appendLog(__('platform_deploying_servers').replace('%s', ids.length));
    const r = await fetch(`${window.API_URL}/deploy_platform_key`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_ids: ids})
    });
    const d = await r.json();
    d.results?.forEach(res => appendLog(`${res.name}: ${res.message}`, res.success ? 'success' : 'error'));
    const ok = d.results?.filter(r => r.success).length || 0;
    toast(__('platform_servers_migrated').replace('%ok', ok).replace('%total', ids.length), ok === ids.length ? 'success' : 'warning');
    setTimeout(() => location.reload(), 1500);
}

async function testKey(machineId) {
    appendLog(__('platform_testing_machine').replace('%s', machineId));
    const r = await fetch(`${window.API_URL}/test_platform_key`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_id: machineId})
    });
    const d = await r.json();
    appendLog(d.message, d.success ? 'success' : 'error');
    toast(d.message, d.success ? 'success' : 'error');
}

async function removePassword(machineId, name) {
    if (!confirm(__('platform_confirm_remove_pwd').replace('%s', name))) return;
    if (!confirm(__('platform_confirm_really_sure'))) return;
    appendLog(__('platform_removing_passwords').replace('%s', name));
    const r = await fetch(`${window.API_URL}/remove_ssh_password`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_id: machineId})
    });
    const d = await r.json();
    appendLog(d.message, d.success ? 'success' : 'error');
    toast(d.message, d.success ? 'success' : 'error');
    if (d.success) setTimeout(() => location.reload(), 1000);
}

async function regenerateKey() {
    if (!confirm(__('platform_confirm_regenerate'))) return;
    if (!confirm(__('platform_confirm_regenerate_final'))) return;
    const r = await fetch(`${window.API_URL}/regenerate_platform_key`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}
    });
    const d = await r.json();
    toast(d.message, d.success ? 'warning' : 'error');
    if (d.success) setTimeout(() => location.reload(), 1500);
}

async function massRemovePasswords() {
    const eligibleIds = [<?= implode(',', array_column(array_filter($servers, fn($s) => $s['platform_key_deployed'] && $s['ssh_password_required']), 'id')) ?>];
    const eligibleNames = [<?= implode(',', array_map(fn($s) => "'" . addslashes($s['name']) . "'", array_filter($servers, fn($s) => $s['platform_key_deployed'] && $s['ssh_password_required']))) ?>];
    if (eligibleIds.length === 0) { toast(__('platform_no_eligible_server'), 'info'); return; }
    if (!confirm(__('platform_confirm_mass_remove_pwd').replace('%count', eligibleIds.length).replace('%names', eligibleNames.join(', ')))) return;
    if (!confirm(__('platform_confirm_irreversible'))) return;

    let ok = 0;
    for (const id of eligibleIds) {
        try {
            const r = await fetch(`${window.API_URL}/remove_ssh_password`, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({machine_id: id})
            });
            const d = await r.json();
            if (d.success) ok++;
        } catch(e) {}
    }
    toast(__('platform_passwords_removed').replace('%ok', ok).replace('%total', eligibleIds.length), ok === eligibleIds.length ? 'success' : 'warning');
    setTimeout(() => location.reload(), 1500);
}

async function reenterPassword(machineId, name) {
    const pwd = prompt(__('platform_prompt_reenter_pwd').replace('%s', name));
    if (!pwd) return;
    const r = await fetch(`${window.API_URL}/reenter_ssh_password`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_id: machineId, password: pwd})
    });
    const d = await r.json();
    toast(d.message, d.success ? 'success' : 'error');
    if (d.success) setTimeout(() => location.reload(), 1000);
}

async function deployServiceAccount(machineId) {
    if (!confirm(__('platform_confirm_deploy_service_account'))) return;
    clearLogs();
    appendLog(__('platform_deploying_admin').replace('%s', machineId));
    const r = await fetch(`${window.API_URL}/deploy_service_account`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_ids: [machineId]})
    });
    const d = await r.json();
    const res = d.results?.[0];
    if (res?.success) {
        appendLog(res.message, 'success');
        toast(__('platform_service_account_ok'), 'success');
        setTimeout(() => location.reload(), 1500);
    } else {
        appendLog(res?.message || __('platform_unknown_error'), 'error');
        toast(res?.message || __('toast_error'), 'error');
    }
}

async function deployAllServiceAccounts() {
    const ids = [<?= implode(',', array_column(array_filter($servers, fn($s) => $s['platform_key_deployed'] && !$s['service_account_deployed']), 'id')) ?>];
    if (ids.length === 0) { toast(__('platform_all_servers_have_admin'), 'info'); return; }
    if (!confirm(__('platform_confirm_deploy_all_admin').replace('%s', ids.length))) return;
    clearLogs();
    appendLog(__('platform_deploying_admin_all').replace('%s', ids.length));
    const r = await fetch(`${window.API_URL}/deploy_service_account`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_ids: ids})
    });
    const d = await r.json();
    d.results?.forEach(res => appendLog(`${res.name}: ${res.message}`, res.success ? 'success' : 'error'));
    const ok = d.results?.filter(r => r.success).length || 0;
    toast(__('platform_accounts_deployed').replace('%ok', ok).replace('%total', ids.length), ok === ids.length ? 'success' : 'warning');
    setTimeout(() => location.reload(), 2000);
}

async function scanUsers(machineId) {
    const container = document.getElementById('users-scan-result');
    container.classList.remove('hidden');
    container.innerHTML = '<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4"><p class="text-sm text-gray-400">' + __('platform_scanning') + '</p></div>';

    const r = await fetch(`${window.API_URL}/scan_server_users`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_id: machineId})
    });
    const d = await r.json();
    if (!d.success) { container.innerHTML = `<div class="bg-red-50 dark:bg-red-900/20 rounded-xl p-4 text-red-600">${d.message}</div>`; return; }

    // Charger les users RootWarden pour comparaison
    let rootwardenUsers = [];
    try {
        const ru = await fetch(`${window.API_URL}/list_machines`);
        const du = await ru.json();
        // On a pas de route qui liste les users RootWarden avec access, on se contente d'afficher
    } catch(e) {}

    let html = `<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600 flex items-center justify-between">
            <h3 class="text-sm font-semibold">${__('platform_users_on').replace('%name', d.machine_name).replace('%count', d.users.length)}</h3>
            <span class="text-xs text-gray-400">Machine #${machineId}</span>
        </div>
        <table class="w-full text-sm">
            <thead class="text-xs uppercase text-gray-500 bg-gray-50 dark:bg-gray-700/50">
                <tr>
                    <th class="px-4 py-2 text-left">${__('platform_th_user')}</th>
                    <th class="px-4 py-2 text-left">${__('platform_th_home')}</th>
                    <th class="px-4 py-2 text-center">${__('platform_th_keys')}</th>
                    <th class="px-4 py-2 text-center">${__('platform_th_platform')}</th>
                    <th class="px-4 py-2">${__('platform_th_rootwarden_keys')}</th>
                    <th class="px-4 py-2 text-center">${__('platform_th_actions')}</th>
                </tr>
            </thead><tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;

    d.users.forEach(u => {
        const cls = u.has_platform_key ? 'bg-green-50 dark:bg-green-900/10' : (u.keys_count > 0 && !u.has_platform_key ? 'bg-yellow-50 dark:bg-yellow-900/10' : '');
        const isSystemUser = ['root','daemon','bin','sys','www-data','nobody'].includes(u.name);
        const safeName = escHtml(u.name);
        const safeHome = escHtml(u.home);
        const safeKeys = escHtml(u.rootwarden_keys.join(', ') || '—');
        html += `<tr class="${cls}">
            <td class="px-4 py-2 font-medium">${safeName}${isSystemUser ? ' <span class="text-[9px] text-gray-400">(sys)</span>' : ''}</td>
            <td class="px-4 py-2 text-xs text-gray-400 font-mono">${safeHome}</td>
            <td class="px-4 py-2 text-center">${u.keys_count}</td>
            <td class="px-4 py-2 text-center">${u.has_platform_key ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-gray-400">&#10007;</span>'}</td>
            <td class="px-4 py-2 text-xs text-gray-400">${safeKeys}</td>
            <td class="px-4 py-2 text-center">
                ${!isSystemUser ? `<button data-machine="${machineId}" data-user="${safeName}" onclick="excludeUser(this.dataset.machine, this.dataset.user)" class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400 hover:bg-red-200" title="${__('platform_tip_exclude')}">${__('platform_btn_exclude')}</button>` : ''}
            </td>
        </tr>`;
    });
    html += '</tbody></table></div>';
    container.innerHTML = html;
    container.scrollIntoView({behavior: 'smooth'});
}

async function excludeUser(machineId, username) {
    const reason = prompt(__('platform_prompt_exclude_reason').replace('%s', username));
    if (!reason) return;
    try {
        const r = await fetch(`${window.API_URL}/exclude_user`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: machineId, username: username, reason: reason})
        });
        const d = await r.json();
        toast(d.message || (d.success ? __('platform_user_excluded') : __('toast_error')), d.success ? 'success' : 'error');
        if (d.success) setTimeout(() => scanUsers(machineId), 800);
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}
</script>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
