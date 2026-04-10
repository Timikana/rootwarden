<?php
/**
 * server_users.php — Gestion des utilisateurs distants par serveur
 * Permet de voir, exclure, supprimer les cles SSH et supprimer les users Linux.
 * Acces : superadmin uniquement
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([1, 2, 3]);
checkPermission('can_manage_remote_users');

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$servers = $pdo->query("SELECT id, name, ip, port, user FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$selectedId = isset($_GET['server']) ? (int)$_GET['server'] : ($servers[0]['id'] ?? 0);
$selectedName = '';
foreach ($servers as $s) { if ($s['id'] == $selectedId) $selectedName = $s['name']; }
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>Utilisateurs serveurs — <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('server_users.title') ?></span>
</nav>

<div class="px-6 py-6 max-w-screen-xl mx-auto">

    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('server_users.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('server_users.desc') ?></p>
        </div>
    </div>

    <!-- Selecteur de serveur -->
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

    <!-- Legende -->
    <div class="flex flex-wrap gap-4 mb-4 text-xs text-gray-500">
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-500"></span> <?= t('server_users.legend_platform_key') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-yellow-400"></span> <?= t('server_users.legend_ssh_keys') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-gray-400"></span> <?= t('server_users.legend_no_keys') ?></span>
        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-purple-500"></span> <?= t('server_users.legend_excluded') ?></span>
    </div>

    <!-- Tableau des utilisateurs -->
    <div id="users-container" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div class="p-8 text-center text-gray-400">
            <p class="text-sm"><?= t('server_users.empty_state') ?></p>
        </div>
    </div>
</div>

<script>
const MACHINE_ID = <?= $selectedId ?>;
const MACHINE_NAME = '<?= htmlspecialchars(addslashes($selectedName)) ?>';

async function scanUsers() {
    const btn = document.getElementById('btn-scan');
    const status = document.getElementById('scan-status');
    const container = document.getElementById('users-container');
    btn.disabled = true;
    status.textContent = __('server_users_scanning');

    try {
        const r = await fetch(`${window.API_URL}/scan_server_users`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID})
        });
        const d = await r.json();
        btn.disabled = false;
        status.textContent = '';

        if (!d.success) {
            container.innerHTML = `<div class="p-6 text-red-500 text-center">${d.message}</div>`;
            return;
        }

        const users = d.users;
        const sysUsers = ['root','daemon','bin','sys','nobody','www-data','sshd','systemd-timesync','systemd-network','systemd-resolve','messagebus','_apt'];

        let html = `<table class="w-full text-sm">
            <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                <tr>
                    <th class="px-4 py-3 text-left">${__('server_users_th_status')}</th>
                    <th class="px-4 py-3 text-left">${__('server_users_th_user')}</th>
                    <th class="px-4 py-3 text-left">${__('server_users_th_home')}</th>
                    <th class="px-4 py-3 text-center">${__('server_users_th_ssh_keys')}</th>
                    <th class="px-4 py-3 text-center">${__('server_users_th_platform')}</th>
                    <th class="px-4 py-3 text-center">${__('server_users_th_excluded')}</th>
                    <th class="px-4 py-3">${__('server_users_th_actions')}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;

        users.forEach(u => {
            const isSys = sysUsers.includes(u.name);
            const dotCls = u.excluded ? 'bg-purple-500' : (u.has_platform_key ? 'bg-green-500' : (u.keys_count > 0 ? 'bg-yellow-400' : 'bg-gray-400'));
            const rowCls = u.excluded ? 'opacity-50' : '';

            const safeName = escHtml(u.name);
            const safeHome = escHtml(u.home);
            html += `<tr class="${rowCls} hover:bg-gray-50 dark:hover:bg-gray-700/30">
                <td class="px-4 py-3"><span class="w-2.5 h-2.5 rounded-full ${dotCls} inline-block"></span></td>
                <td class="px-4 py-3">
                    <span class="font-medium">${safeName}</span>
                    ${isSys ? '<span class="text-[10px] text-gray-400 ml-1">(systeme)</span>' : ''}
                    ${u.excluded ? '<span class="text-[10px] text-purple-400 ml-1">(exclu)</span>' : ''}
                </td>
                <td class="px-4 py-3 text-xs text-gray-400 font-mono">${safeHome}</td>
                <td class="px-4 py-3 text-center">
                    <span class="${u.keys_count > 0 ? 'font-bold text-blue-500' : 'text-gray-400'}">${u.keys_count}</span>
                </td>
                <td class="px-4 py-3 text-center">${u.has_platform_key ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-gray-400">&#10007;</span>'}</td>
                <td class="px-4 py-3 text-center">
                    ${u.excluded
                        ? '<span class="text-purple-400">&#10003;</span>'
                        : `<button data-user="${safeName}" onclick="excludeUser(this.dataset.user)" class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-500 hover:bg-purple-100 hover:text-purple-600">${__('server_users_btn_exclude')}</button>`
                    }
                </td>
                <td class="px-4 py-3">
                    <div class="flex gap-1">
                        ${u.keys_count > 0 && !isSys ? `
                            <button data-user="${safeName}" onclick="removeKeys(this.dataset.user, 'rootwarden_only')" class="text-[10px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-yellow-50 hover:text-yellow-700" title="${__('server_users_tip_remove_rootwarden')}">${__('server_users_btn_remove_rootwarden')}</button>
                            <button data-user="${safeName}" onclick="removeKeys(this.dataset.user, 'all')" class="text-[10px] px-2 py-1 rounded border border-orange-300 text-orange-600 hover:bg-orange-50" title="${__('server_users_tip_remove_all_keys')}">${__('server_users_btn_remove_all_keys')}</button>
                        ` : ''}
                        ${!isSys ? `
                            <button data-user="${safeName}" onclick="deleteUser(this.dataset.user)" class="text-[10px] px-2 py-1 rounded bg-red-100 text-red-600 hover:bg-red-200" title="${__('server_users_tip_delete_user')}">${__('server_users_btn_delete_user')}</button>
                        ` : ''}
                    </div>
                </td>
            </tr>`;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
        status.textContent = __('server_users_detected').replace('%s', users.length);
    } catch(e) {
        btn.disabled = false;
        status.textContent = '';
        container.innerHTML = `<div class="p-6 text-red-500 text-center">${__('toast_error')} : ${e.message}</div>`;
    }
}

async function excludeUser(username) {
    const reason = prompt(__('server_users_prompt_exclude').replace('%s', username));
    if (!reason) return;
    try {
        const r = await fetch(`${window.API_URL}/exclude_user`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, username: username, reason: reason})
        });
        const d = await r.json();
        toast(d.message || (d.success ? __('server_users_excluded') : __('toast_error')), d.success ? 'success' : 'error');
        if (d.success) setTimeout(() => scanUsers(), 500);
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

async function removeKeys(username, mode) {
    const label = mode === 'all' ? __('server_users_all_ssh_keys') : __('server_users_rootwarden_keys');
    if (!confirm(__('server_users_confirm_remove_keys').replace('%label', label).replace('%user', username).replace('%server', MACHINE_NAME))) return;
    try {
        const r = await fetch(`${window.API_URL}/remove_user_keys`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({machine_id: MACHINE_ID, username: username, mode: mode})
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
            body: JSON.stringify({machine_id: MACHINE_ID, username: username, remove_home: removeHome})
        });
        const d = await r.json();
        toast(d.message, d.success ? 'success' : 'error');
        if (d.success) setTimeout(() => scanUsers(), 1000);
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

// Auto-scan au chargement si un serveur est selectionne
if (MACHINE_ID > 0) {
    document.addEventListener('DOMContentLoaded', scanUsers);
}
</script>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
