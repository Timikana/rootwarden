<?php
/**
 * server_users.php - Inventaire et classification des utilisateurs distants
 * Workflow : Scan → Classification → Deploy autorise
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_remote_users');

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$servers = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$selectedId = isset($_GET['server']) ? (int)$_GET['server'] : ($servers[0]['id'] ?? 0);
$selectedName = '';
foreach ($servers as $s) { if ($s['id'] == $selectedId) $selectedName = $s['name']; }
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('server_users.title') ?> - <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('server_users.title') ?></span>
</nav>

<div class="px-6 py-6 max-w-screen-xl mx-auto">

    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('server_users.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('server_users.desc_v2') ?></p>
        </div>
    </div>

<?php
$tipId = 'server-users'; $tipTitle = t('tip.users_title'); $tipSteps = [
    t('tip.users_step1'), t('tip.users_step2'), t('tip.users_step3'), t('tip.users_step4'),
]; require __DIR__ . '/../includes/howto_tip.php';
?>

    <!-- Selecteur serveur -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
        <div class="flex flex-wrap items-center gap-3">
            <label class="text-sm font-medium text-gray-600 dark:text-gray-300"><?= t('server_users.server_label') ?></label>
            <select id="server-select" onchange="location.href='?server='+this.value" class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 min-w-[200px]">
                <?php foreach ($servers as $s): ?>
                <option value="<?= $s['id'] ?>" <?= $s['id'] == $selectedId ? 'selected' : '' ?>><?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>)</option>
                <?php endforeach; ?>
            </select>
            <button onclick="scanUsers()" id="btn-scan" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg font-medium">
                <?= t('server_users.btn_scan') ?>
            </button>
            <span id="scan-status" class="text-xs text-gray-400"></span>
        </div>
    </div>

    <!-- Alerte pending -->
    <div id="pending-alert" class="hidden bg-orange-50 dark:bg-orange-900/20 border border-orange-300 dark:border-orange-700 rounded-xl p-4 mb-4">
        <div class="flex items-center gap-2">
            <span class="text-orange-600 text-lg">&#9888;</span>
            <div>
                <p class="text-sm font-medium text-orange-800 dark:text-orange-200" id="pending-text"></p>
                <p class="text-xs text-orange-600 dark:text-orange-400"><?= t('server_users.pending_hint') ?></p>
            </div>
            <button onclick="classifyAllPending('unmanaged')" class="ml-auto text-xs px-3 py-1.5 rounded-lg border border-gray-300 text-gray-600 hover:bg-gray-100"><?= t('server_users.btn_all_unmanaged') ?></button>
            <button onclick="classifyAllPending('excluded')" class="text-xs px-3 py-1.5 rounded-lg border border-blue-300 text-blue-600 hover:bg-blue-100"><?= t('server_users.btn_all_excluded') ?></button>
        </div>
    </div>

    <!-- Legende -->
    <div class="flex flex-wrap gap-4 mb-4 text-xs text-gray-500">
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-orange-400"></span> <?= t('server_users.legend_pending') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-500"></span> <?= t('server_users.legend_managed') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-500"></span> <?= t('server_users.legend_excluded') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-gray-400"></span> <?= t('server_users.legend_unmanaged') ?></span>
    </div>

    <!-- Tableau -->
    <div id="users-container" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div class="p-8 text-center text-gray-400">
            <p class="text-sm"><?= t('server_users.empty_state') ?></p>
        </div>
    </div>
</div>

<script>
const MACHINE_ID = <?= $selectedId ?>;
const MACHINE_NAME = '<?= htmlspecialchars(addslashes($selectedName)) ?>';

const STATUS_BADGES = {
    pending_review: {cls: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300', dot: 'bg-orange-400', label: '<?= t('server_users.status_pending') ?>'},
    managed:        {cls: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300', dot: 'bg-green-500', label: '<?= t('server_users.status_managed') ?>'},
    excluded:       {cls: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300', dot: 'bg-blue-500', label: '<?= t('server_users.status_excluded') ?>'},
    unmanaged:      {cls: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300', dot: 'bg-gray-400', label: '<?= t('server_users.status_unmanaged') ?>'},
};

async function scanUsers() {
    const btn = document.getElementById('btn-scan');
    const status = document.getElementById('scan-status');
    const container = document.getElementById('users-container');
    btn.disabled = true;
    status.textContent = __('server_users_scanning');

    try {
        const r = await fetch(`${window.API_URL}/scan_server_users`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID})
        });
        const d = await r.json();
        btn.disabled = false;
        status.textContent = '';

        if (!d.success) {
            container.innerHTML = `<div class="p-6 text-red-500 text-center">${escHtml(d.message)}</div>`;
            return;
        }

        renderUsers(d.users, d.pending_count);
        status.textContent = __('server_users_detected').replace('%s', d.users.length);
    } catch(e) {
        btn.disabled = false;
        container.innerHTML = `<div class="p-6 text-red-500 text-center">${escHtml(e.message)}</div>`;
    }
}

function renderUsers(users, pendingCount) {
    const container = document.getElementById('users-container');
    const alert = document.getElementById('pending-alert');

    if (pendingCount > 0) {
        alert.classList.remove('hidden');
        document.getElementById('pending-text').textContent =
            `${pendingCount} compte(s) en attente de classification - le deploiement SSH est bloque.`;
    } else {
        alert.classList.add('hidden');
    }

    let html = `<table class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
            <tr>
                <th class="px-4 py-3 text-left">${__('server_users_th_status')}</th>
                <th class="px-4 py-3 text-left">${__('server_users_th_user')}</th>
                <th class="px-4 py-3 text-left">${__('server_users_th_home')}</th>
                <th class="px-4 py-3 text-center">${__('server_users_th_ssh_keys')}</th>
                <th class="px-4 py-3 text-center">${__('server_users_th_platform')}</th>
                <th class="px-4 py-3 text-center">Classification</th>
                <th class="px-4 py-3">${__('server_users_th_actions')}</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;

    users.forEach(u => {
        const badge = STATUS_BADGES[u.status] || STATUS_BADGES.unmanaged;
        const safeName = escHtml(u.username);
        const safeHome = escHtml(u.home_dir || '');
        const uid = u.uid || 0;
        const isSys = uid < 1000;

        html += `<tr class="hover:bg-gray-50 dark:hover:bg-gray-700/30">
            <td class="px-4 py-3">
                <span class="inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full ${badge.cls}">
                    <span class="w-1.5 h-1.5 rounded-full ${badge.dot}"></span>
                    ${badge.label}
                </span>
            </td>
            <td class="px-4 py-3">
                <span class="font-medium">${safeName}</span>
                ${isSys ? '<span class="text-[10px] text-gray-400 ml-1">(systeme)</span>' : ''}
                ${u.notes ? `<span class="text-[10px] text-gray-400 ml-1" title="${escHtml(u.notes)}">&#128221;</span>` : ''}
            </td>
            <td class="px-4 py-3 text-xs text-gray-400 font-mono">${safeHome}</td>
            <td class="px-4 py-3 text-center">
                <span class="${u.keys_count > 0 ? 'font-bold text-blue-500' : 'text-gray-400'}">${u.keys_count || 0}</span>
            </td>
            <td class="px-4 py-3 text-center">${u.has_platform_key ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-gray-400">&#10007;</span>'}</td>
            <td class="px-4 py-3 text-center">
                <select data-user="${safeName}" onchange="classifyUser(this.dataset.user, this.value)"
                        class="text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-800 ${u.status === 'pending_review' ? 'border-orange-400 ring-1 ring-orange-300' : ''}">
                    <option value="managed" ${u.status === 'managed' ? 'selected' : ''}>Gere (RootWarden)</option>
                    <option value="excluded" ${u.status === 'excluded' ? 'selected' : ''}>Exclu (ne pas toucher)</option>
                    <option value="unmanaged" ${u.status === 'unmanaged' ? 'selected' : ''}>Non gere</option>
                    ${u.status === 'pending_review' ? '<option value="pending_review" selected disabled>&#9888; A classifier</option>' : ''}
                </select>
            </td>
            <td class="px-4 py-3">
                <div class="flex gap-1">
                    ${u.keys_count > 0 && !isSys ? `
                        <button data-user="${safeName}" onclick="removeKeys(this.dataset.user, 'all')" class="text-[10px] px-2 py-1 rounded border border-orange-300 text-orange-600 hover:bg-orange-50">${__('server_users_btn_remove_all_keys')}</button>
                    ` : ''}
                    ${!isSys ? `
                        <button data-user="${safeName}" onclick="deleteUser(this.dataset.user)" class="text-[10px] px-2 py-1 rounded bg-red-100 text-red-600 hover:bg-red-200">${__('server_users_btn_delete_user')}</button>
                    ` : ''}
                </div>
            </td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

async function classifyUser(username, status) {
    try {
        const r = await fetch(`${window.API_URL}/admin/user_inventory/classify`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, username, status})
        });
        const d = await r.json();
        toast(d.success ? `${username} → ${status}` : d.message, d.success ? 'success' : 'error');
        if (d.success) scanUsers();
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

async function classifyAllPending(status) {
    try {
        const r = await fetch(`${window.API_URL}/admin/user_inventory/classify_bulk`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, status})
        });
        const d = await r.json();
        toast(d.success ? `${d.updated} classifie(s)` : d.message, d.success ? 'success' : 'error');
        if (d.success) scanUsers();
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

async function removeKeys(username, mode) {
    if (!confirm(__('server_users_confirm_remove_keys').replace('%label', __('server_users_all_ssh_keys')).replace('%user', username).replace('%server', MACHINE_NAME))) return;
    try {
        const r = await fetch(`${window.API_URL}/remove_user_keys`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, username, mode})
        });
        const d = await r.json();
        toast(d.message, d.success ? 'success' : 'error');
        if (d.success) setTimeout(() => scanUsers(), 500);
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

async function deleteUser(username) {
    if (!confirm(__('server_users_confirm_delete').replace('%user', username).replace('%server', MACHINE_NAME))) return;
    const removeHome = confirm(__('server_users_confirm_remove_home').replace('%s', username));
    try {
        const r = await fetch(`${window.API_URL}/delete_remote_user`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, username, remove_home: removeHome})
        });
        const d = await r.json();
        toast(d.message, d.success ? 'success' : 'error');
        if (d.success) setTimeout(() => scanUsers(), 1000);
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

if (MACHINE_ID > 0) {
    document.addEventListener('DOMContentLoaded', scanUsers);
}
</script>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
