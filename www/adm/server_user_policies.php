<?php
/**
 * server_user_policies.php - Gestion fine sudo + SFTP par utilisateur distant
 * Acces : superadmin uniquement (cf backend @require_role(3))
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([ROLE_SUPERADMIN]);

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$servers = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$selectedId = isset($_GET['server']) ? (int)$_GET['server'] : ($servers[0]['id'] ?? 0);

$users = [];
if ($selectedId) {
    $stmt = $pdo->prepare("SELECT id, username FROM server_user_inventory WHERE machine_id = ? AND status IN ('managed','pending_review') ORDER BY username");
    $stmt->execute([$selectedId]);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
$selectedUserId = isset($_GET['user']) ? (int)$_GET['user'] : ($users[0]['id'] ?? 0);

$existingSudo = null; $existingSftp = null;
if ($selectedId && $selectedUserId) {
    $stmt = $pdo->prepare("SELECT * FROM server_user_sudo_policies WHERE machine_id=? AND server_user_id=?");
    $stmt->execute([$selectedId, $selectedUserId]);
    $existingSudo = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    $stmt = $pdo->prepare("SELECT * FROM server_user_sftp_policies WHERE machine_id=? AND server_user_id=?");
    $stmt->execute([$selectedId, $selectedUserId]);
    $existingSftp = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('policies.title') ?> - <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('policies.title') ?></span>
</nav>

<div class="px-6 py-6 max-w-screen-xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('policies.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('policies.subtitle') ?></p>
        </div>
        <span class="text-xs text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30 px-2 py-1 rounded">
            <?= t('policies.superadmin_badge') ?>
        </span>
    </div>

    <!-- Selecteurs serveur + user -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
        <div class="flex flex-wrap items-center gap-3">
            <label class="text-sm font-medium"><?= t('policies.server_label') ?></label>
            <select id="server-select" onchange="location.href='?server='+this.value" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 min-w-[260px]">
                <?php foreach ($servers as $s): ?>
                <option value="<?= $s['id'] ?>" <?= $s['id'] == $selectedId ? 'selected' : '' ?>>
                    <?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>)
                </option>
                <?php endforeach; ?>
            </select>
            <label class="text-sm font-medium ml-4"><?= t('policies.user_label') ?></label>
            <select id="user-select" onchange="location.href='?server=<?= $selectedId ?>&user='+this.value" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 min-w-[200px]">
                <?php if (empty($users)): ?>
                <option><?= t('policies.no_users') ?></option>
                <?php else: foreach ($users as $u): ?>
                <option value="<?= $u['id'] ?>" <?= $u['id'] == $selectedUserId ? 'selected' : '' ?>><?= htmlspecialchars($u['username']) ?></option>
                <?php endforeach; endif; ?>
            </select>
        </div>
    </div>

<?php if ($selectedId && $selectedUserId): ?>

    <!-- Onglets -->
    <div class="border-b border-gray-200 dark:border-gray-700 mb-4">
        <nav class="flex gap-4">
            <button onclick="switchTab('sudo')" id="tab-sudo" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-blue-600 text-blue-600">
                <?= t('policies.tab_sudo') ?>
            </button>
            <button onclick="switchTab('sftp')" id="tab-sftp" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">
                <?= t('policies.tab_sftp') ?>
            </button>
            <button onclick="switchTab('history')" id="tab-history" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">
                <?= t('policies.tab_history') ?>
            </button>
        </nav>
    </div>

    <!-- TAB SUDO -->
    <div id="pane-sudo" class="tab-pane bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
        <h2 class="text-lg font-semibold mb-4"><?= t('policies.sudo_title') ?></h2>
        <form id="sudo-form" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1"><?= t('policies.sudo_preset') ?></label>
                <select name="preset" id="sudo-preset" onchange="onPresetChange()" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    <?php $cur = $existingSudo['preset'] ?? 'apt_only'; foreach (['all_nopasswd','restart_services','apt_only','read_logs','systemctl_specific','custom'] as $p): ?>
                    <option value="<?= $p ?>" <?= $cur === $p ? 'selected' : '' ?>><?= t('policies.preset_' . $p) ?></option>
                    <?php endforeach; ?>
                </select>
                <p class="text-xs text-gray-500 mt-1" id="preset-hint"><?= t('policies.preset_hint_' . $cur) ?></p>
            </div>

            <div id="custom-rules-block" class="<?= $cur === 'custom' ? '' : 'hidden' ?>">
                <label class="block text-sm font-medium mb-1"><?= t('policies.custom_rules') ?></label>
                <textarea name="custom_rules" id="sudo-custom-rules" rows="5" placeholder="ALL=(root) NOPASSWD: /usr/bin/docker ps" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono text-xs"><?= htmlspecialchars($existingSudo['custom_rules'] ?? '') ?></textarea>
                <p class="text-xs text-amber-600 mt-1"><?= t('policies.custom_warning') ?></p>
            </div>

            <div id="services-block" class="<?= $cur === 'systemctl_specific' ? '' : 'hidden' ?>">
                <label class="block text-sm font-medium mb-1"><?= t('policies.services_list') ?></label>
                <input type="text" name="services" id="sudo-services" placeholder="nginx, php8.2-fpm, redis-server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                <p class="text-xs text-gray-500 mt-1"><?= t('policies.services_hint') ?></p>
            </div>

            <div class="flex items-center gap-6">
                <label class="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="nopasswd" id="sudo-nopasswd" <?= ($existingSudo['nopasswd'] ?? false) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.nopasswd') ?></span>
                </label>
                <label class="flex items-center gap-2 text-sm">
                    <span><?= t('policies.runas') ?></span>
                    <input type="text" name="runas" id="sudo-runas" value="<?= htmlspecialchars($existingSudo['runas'] ?? 'root') ?>" class="w-32 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-sm">
                </label>
            </div>

            <div class="flex flex-wrap gap-2 pt-2">
                <button type="button" onclick="deployPolicy('sudo')" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_deploy') ?>
                </button>
                <button type="button" onclick="auditPolicy('sudo')" class="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_audit') ?>
                </button>
                <button type="button" onclick="removePolicy('sudo')" class="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_remove') ?>
                </button>
            </div>
        </form>

        <?php if ($existingSudo): ?>
        <p class="text-xs text-gray-400 mt-4">
            <?= t('policies.last_deployed') ?>: <?= $existingSudo['last_deployed_at'] ?? 'jamais' ?>
            (<?= $existingSudo['enabled'] ? '<span class="text-green-600">'.t('policies.status_enabled').'</span>' : '<span class="text-gray-500">'.t('policies.status_disabled').'</span>' ?>)
        </p>
        <?php endif; ?>

        <pre id="sudo-output" class="hidden mt-4 bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs font-mono whitespace-pre-wrap"></pre>
    </div>

    <!-- TAB SFTP -->
    <div id="pane-sftp" class="tab-pane bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 hidden">
        <h2 class="text-lg font-semibold mb-4"><?= t('policies.sftp_title') ?></h2>
        <form id="sftp-form" class="space-y-4">
            <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" name="sftp_only" id="sftp-only" <?= ($existingSftp['sftp_only'] ?? false) ? 'checked' : '' ?> class="form-checkbox">
                <span class="font-medium"><?= t('policies.sftp_only') ?></span>
            </label>
            <p class="text-xs text-gray-500 -mt-3 ml-6"><?= t('policies.sftp_only_hint') ?></p>

            <div>
                <label class="block text-sm font-medium mb-1"><?= t('policies.chroot_dir') ?></label>
                <input type="text" name="chroot_dir" id="sftp-chroot" placeholder="/srv/sftp/john" value="<?= htmlspecialchars($existingSftp['chroot_dir'] ?? '') ?>" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono text-xs">
                <p class="text-xs text-amber-600 mt-1"><?= t('policies.chroot_warning') ?></p>
            </div>

            <div>
                <label class="block text-sm font-medium mb-1"><?= t('policies.working_dir') ?></label>
                <input type="text" name="working_dir" id="sftp-working" placeholder="/upload" value="<?= htmlspecialchars($existingSftp['working_dir'] ?? '') ?>" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono text-xs">
                <p class="text-xs text-gray-500 mt-1"><?= t('policies.working_dir_hint') ?></p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-gray-200 dark:border-gray-700">
                <label class="flex items-center gap-2 text-sm pt-2">
                    <input type="checkbox" name="allow_password_auth" id="sftp-pw" <?= ($existingSftp['allow_password_auth'] ?? true) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.allow_password') ?></span>
                </label>
                <label class="flex items-center gap-2 text-sm pt-2">
                    <input type="checkbox" name="allow_tcp_forwarding" id="sftp-tcp" <?= ($existingSftp['allow_tcp_forwarding'] ?? true) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.allow_tcp_fwd') ?></span>
                </label>
                <label class="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="allow_agent_forwarding" id="sftp-agent" <?= ($existingSftp['allow_agent_forwarding'] ?? true) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.allow_agent_fwd') ?></span>
                </label>
                <label class="flex items-center gap-2 text-sm">
                    <input type="checkbox" name="x11_forwarding" id="sftp-x11" <?= ($existingSftp['x11_forwarding'] ?? false) ? 'checked' : '' ?> class="form-checkbox">
                    <span><?= t('policies.allow_x11') ?></span>
                </label>
            </div>

            <div class="flex flex-wrap gap-2 pt-2">
                <button type="button" onclick="deployPolicy('sftp')" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_deploy') ?>
                </button>
                <button type="button" onclick="auditPolicy('sftp')" class="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_audit') ?>
                </button>
                <button type="button" onclick="removePolicy('sftp')" class="bg-red-600 hover:bg-red-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                    <?= t('policies.btn_remove') ?>
                </button>
            </div>
        </form>

        <?php if ($existingSftp): ?>
        <p class="text-xs text-gray-400 mt-4">
            <?= t('policies.last_deployed') ?>: <?= $existingSftp['last_deployed_at'] ?? 'jamais' ?>
            (<?= $existingSftp['enabled'] ? '<span class="text-green-600">'.t('policies.status_enabled').'</span>' : '<span class="text-gray-500">'.t('policies.status_disabled').'</span>' ?>)
        </p>
        <?php endif; ?>

        <pre id="sftp-output" class="hidden mt-4 bg-gray-100 dark:bg-gray-900 p-3 rounded text-xs font-mono whitespace-pre-wrap"></pre>
    </div>

    <!-- TAB HISTORY -->
    <div id="pane-history" class="tab-pane bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 hidden">
        <h2 class="text-lg font-semibold mb-4"><?= t('policies.history_title') ?></h2>
        <div class="mb-3">
            <label class="text-sm"><?= t('policies.history_filter') ?>:</label>
            <select id="history-filter" onchange="loadHistory()" class="text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 ml-2 bg-white dark:bg-gray-700">
                <option value=""><?= t('policies.history_all') ?></option>
                <option value="sudo">sudo</option>
                <option value="sftp">sftp</option>
            </select>
        </div>
        <div id="history-list" class="space-y-2"></div>
    </div>

<?php endif; ?>

</div>

<script>
const MACHINE_ID = <?= (int)$selectedId ?>;
const SERVER_USER_ID = <?= (int)$selectedUserId ?>;
// Patch A02 : la cle API backend ne doit JAMAIS etre exposee dans le DOM.
// Tous les appels passent par /api_proxy.php qui injecte la cle cote serveur.
const USER_ID = <?= (int)($_SESSION['user_id'] ?? 0) ?>;
const T = {
    confirmRemove: <?= json_encode(t('policies.confirm_remove')) ?>,
    confirmRollback: <?= json_encode(t('policies.confirm_rollback')) ?>,
    deploySuccess: <?= json_encode(t('policies.deploy_success')) ?>,
    deployFail: <?= json_encode(t('policies.deploy_fail')) ?>,
    netError: <?= json_encode(t('policies.net_error')) ?>,
    auditFound: <?= json_encode(t('policies.audit_found')) ?>,
    auditNotFound: <?= json_encode(t('policies.audit_not_found')) ?>,
    removeSuccess: <?= json_encode(t('policies.remove_success')) ?>,
};
const presetHints = {
    all_nopasswd: <?= json_encode(t('policies.preset_hint_all_nopasswd')) ?>,
    restart_services: <?= json_encode(t('policies.preset_hint_restart_services')) ?>,
    apt_only: <?= json_encode(t('policies.preset_hint_apt_only')) ?>,
    read_logs: <?= json_encode(t('policies.preset_hint_read_logs')) ?>,
    systemctl_specific: <?= json_encode(t('policies.preset_hint_systemctl_specific')) ?>,
    custom: <?= json_encode(t('policies.preset_hint_custom')) ?>,
};

function switchTab(name) {
    document.querySelectorAll('.tab-btn').forEach(b => { b.classList.remove('border-blue-600', 'text-blue-600'); b.classList.add('border-transparent', 'text-gray-500'); });
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
    const btn = document.getElementById('tab-' + name);
    const pane = document.getElementById('pane-' + name);
    if (btn) { btn.classList.add('border-blue-600', 'text-blue-600'); btn.classList.remove('border-transparent', 'text-gray-500'); }
    if (pane) pane.classList.remove('hidden');
    if (name === 'history') loadHistory();
}

function onPresetChange() {
    const v = document.getElementById('sudo-preset').value;
    document.getElementById('custom-rules-block').classList.toggle('hidden', v !== 'custom');
    document.getElementById('services-block').classList.toggle('hidden', v !== 'systemctl_specific');
    const hint = document.getElementById('preset-hint');
    if (hint && presetHints[v]) hint.textContent = presetHints[v];
}

async function callApi(path, method, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch('/api_proxy.php' + path, opts);
    return await r.json();
}

function show(id, content, ok) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    el.classList.toggle('text-red-600', !ok);
}

function notifyToast(success, message) {
    if (typeof toast === 'function') {
        toast(message || (success ? T.deploySuccess : T.deployFail), success ? 'success' : 'error', success ? 3000 : 6000);
    }
}

async function deployPolicy(type) {
    const body = { machine_id: MACHINE_ID, server_user_id: SERVER_USER_ID };
    if (type === 'sudo') {
        body.preset = document.getElementById('sudo-preset').value;
        body.nopasswd = document.getElementById('sudo-nopasswd').checked;
        body.runas = document.getElementById('sudo-runas').value;
        if (body.preset === 'custom') body.custom_rules = document.getElementById('sudo-custom-rules').value;
        if (body.preset === 'systemctl_specific') {
            body.services = (document.getElementById('sudo-services').value || '').split(/[,\s]+/).filter(Boolean);
        }
    } else {
        body.sftp_only = document.getElementById('sftp-only').checked;
        body.chroot_dir = document.getElementById('sftp-chroot').value || null;
        body.working_dir = document.getElementById('sftp-working').value || null;
        body.allow_password_auth = document.getElementById('sftp-pw').checked;
        body.allow_tcp_forwarding = document.getElementById('sftp-tcp').checked;
        body.allow_agent_forwarding = document.getElementById('sftp-agent').checked;
        body.x11_forwarding = document.getElementById('sftp-x11').checked;
    }
    try {
        const data = await callApi('/policy/' + type + '/deploy', 'POST', body);
        show(type + '-output', data, data.success);
        notifyToast(data.success, data.success ? T.deploySuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
        if (data.success) setTimeout(() => location.reload(), 1500);
    } catch (e) {
        show(type + '-output', T.netError + ' : ' + e, false);
        notifyToast(false, T.netError + ' : ' + e);
    }
}

async function auditPolicy(type) {
    const body = { machine_id: MACHINE_ID, server_user_id: SERVER_USER_ID };
    try {
        const data = await callApi('/policy/' + type + '/audit', 'POST', body);
        const content = data.exists ? data.content : '(' + (T.deployFail ? 'aucun fichier' : 'no file') + ' a ' + (data.target_path || '?') + ')';
        show(type + '-output', content, data.success);
        notifyToast(data.success, data.exists ? T.auditFound : T.auditNotFound);
    } catch (e) {
        show(type + '-output', T.netError + ' : ' + e, false);
        notifyToast(false, T.netError + ' : ' + e);
    }
}

async function removePolicy(type) {
    if (!confirm(T.confirmRemove)) return;
    const body = { machine_id: MACHINE_ID, server_user_id: SERVER_USER_ID };
    try {
        const data = await callApi('/policy/' + type + '/remove', 'POST', body);
        show(type + '-output', data, data.success);
        notifyToast(data.success, data.success ? T.removeSuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
        if (data.success) setTimeout(() => location.reload(), 1500);
    } catch (e) {
        show(type + '-output', T.netError + ' : ' + e, false);
        notifyToast(false, T.netError + ' : ' + e);
    }
}

async function loadHistory() {
    const filter = document.getElementById('history-filter')?.value || '';
    const params = new URLSearchParams({ machine_id: MACHINE_ID, server_user_id: SERVER_USER_ID });
    if (filter) params.append('policy_type', filter);
    try {
        const data = await callApi('/policy/deployments?' + params.toString(), 'GET');
        const list = document.getElementById('history-list');
        if (!data.success || !data.deployments.length) {
            list.innerHTML = '<p class="text-sm text-gray-400"><?= t('policies.history_empty') ?></p>';
            return;
        }
        list.innerHTML = data.deployments.map(d => `
            <div class="border border-gray-200 dark:border-gray-700 rounded p-3 text-xs">
                <div class="flex items-center justify-between mb-1">
                    <span class="font-mono">#${d.id} - ${d.policy_type.toUpperCase()} - ${d.deployed_at}</span>
                    <span class="px-2 py-0.5 rounded text-xs ${d.status === 'applied' ? 'bg-green-100 text-green-800' : d.status === 'rolled_back' ? 'bg-amber-100 text-amber-800' : d.status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'}">${d.status}</span>
                </div>
                <div class="text-gray-500 mb-1">${d.target_path}</div>
                ${d.rollback_reason ? `<div class="text-gray-400 italic mb-1">${d.rollback_reason}</div>` : ''}
                ${d.status === 'applied' || d.status === 'superseded' ? `<button onclick="rollbackTo(${d.id})" class="text-blue-600 hover:underline"><?= t('policies.btn_rollback') ?></button>` : ''}
            </div>
        `).join('');
    } catch (e) {
        document.getElementById('history-list').innerHTML = '<p class="text-red-600 text-sm">' + T.netError + ' : ' + e + '</p>';
    }
}

async function rollbackTo(deploymentId) {
    const reason = prompt('<?= t('policies.rollback_reason') ?>:');
    if (reason === null) return;
    if (!confirm(T.confirmRollback)) return;
    try {
        const data = await callApi('/policy/rollback', 'POST', { machine_id: MACHINE_ID, deployment_id: deploymentId, reason });
        notifyToast(data.success, data.success ? T.deploySuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
        if (data.success) setTimeout(() => location.reload(), 1500);
    } catch (e) {
        notifyToast(false, T.netError + ' : ' + e);
    }
}
</script>

</body>
</html>
