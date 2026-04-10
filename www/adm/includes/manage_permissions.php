<?php
require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([2, 3]);

if (!function_exists('getPermissions')) {
    function getPermissions($pdo, $user_id) {
        $stmt = $pdo->prepare("SELECT * FROM permissions WHERE user_id = ?");
        $stmt->execute([$user_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?? [];
    }
}

$stmt = $pdo->query("SELECT u.id, u.name, r.name AS role, u.role_id FROM users u INNER JOIN roles r ON u.role_id = r.id ORDER BY u.role_id DESC, u.name");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Groupes de permissions avec icones et descriptions
$permGroups = [
    'Operations' => [
        'can_deploy_keys'     => ['label' => 'Cles SSH',      'desc' => 'Deployer les cles publiques'],
        'can_update_linux'    => ['label' => 'MaJ Linux',     'desc' => 'APT update, dry-run, paquets'],
        'can_manage_iptables' => ['label' => 'Iptables',      'desc' => 'Regles de pare-feu'],
        'can_manage_fail2ban' => ['label' => 'Fail2ban',      'desc' => 'Gestion des bans IP'],
        'can_manage_services' => ['label' => t('perms.label_services'), 'desc' => t('perms.desc_services')],
        'can_audit_ssh'       => ['label' => t('perms.label_ssh_audit'), 'desc' => t('perms.desc_ssh_audit')],
        'can_scan_cve'        => ['label' => 'Scan CVE',      'desc' => 'Scanner les vulnerabilites'],
    ],
    'Administration' => [
        'can_admin_portal'        => ['label' => 'Admin',         'desc' => 'Page d\'administration'],
        'can_manage_remote_users' => ['label' => 'Users distants','desc' => 'Supprimer cles/users serveurs'],
        'can_manage_platform_key' => ['label' => 'Keypair',       'desc' => 'Deployer la cle plateforme'],
    ],
    'Supervision' => [
        'can_view_compliance' => ['label' => 'Conformite', 'desc' => 'Rapport de conformite'],
        'can_manage_backups'  => ['label' => 'Backups',    'desc' => 'Sauvegardes BDD'],
        'can_schedule_cve'    => ['label' => 'Planif. CVE','desc' => 'Planifier les scans automatiques'],
    ],
];
$canEdit = $_SESSION['role_id'] >= 3;
$canEditPartial = $_SESSION['role_id'] >= 2;
?>

<div class="flex items-center justify-between mb-2">
    <div>
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('perms.title') ?></h2>
        <p class="text-xs text-gray-400 mt-0.5"><?= t('perms.desc') ?></p>
    </div>
    <input type="text" id="perm-filter" placeholder="<?= t('common.filter') ?>"
           class="w-44 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 flex-shrink-0"
           oninput="document.querySelectorAll('.perm-card').forEach(c => { c.style.display = c.dataset.name.includes(this.value.toLowerCase()) ? '' : 'none'; })">
</div>

<div class="space-y-3">
<?php foreach ($users as $user):
    $permissions = getPermissions($pdo, $user['id']);
    $isEditable = ($canEdit) || ($canEditPartial && $user['role_id'] < 3);
    $roleCls = match((int)$user['role_id']) {
        3 => 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
        2 => 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
    };
    // Compter les permissions actives
    $activeCount = 0;
    foreach ($permGroups as $perms) {
        foreach ($perms as $key => $info) {
            if ($permissions[$key] ?? 0) $activeCount++;
        }
    }
    $totalPerms = array_sum(array_map('count', $permGroups));
?>
<details class="perm-card bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden"
         data-name="<?= htmlspecialchars(strtolower($user['name'])) ?>">
    <summary class="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 select-none">
        <div class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            <?= strtoupper(substr($user['name'], 0, 1)) ?>
        </div>
        <span class="font-medium text-sm text-gray-800 dark:text-gray-200"><?= htmlspecialchars($user['name']) ?></span>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $roleCls ?>"><?= htmlspecialchars($user['role']) ?></span>
        <span class="text-xs px-2 py-0.5 rounded-full <?= $activeCount === $totalPerms ? 'bg-green-50 dark:bg-green-900/30 text-green-600 dark:text-green-300 font-medium' : ($activeCount > 0 ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 font-medium' : 'bg-gray-100 dark:bg-gray-700 text-gray-400') ?>"><?= $activeCount ?>/<?= $totalPerms ?> droits</span>
        <?php if ((int)$user['role_id'] === 3): ?>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300" title="<?= t('perms.tip_all_rights') ?>"><?= t('perms.all_rights') ?></span>
        <?php endif; ?>
    </summary>

    <div class="px-4 pb-4 pt-2 border-t border-gray-100 dark:border-gray-700">
        <?php foreach ($permGroups as $groupName => $perms): ?>
        <div class="mb-3">
            <div class="text-[10px] text-gray-400 uppercase tracking-wider mb-1.5"><?= $groupName ?></div>
            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                <?php foreach ($perms as $permKey => $permInfo):
                    $checked = ($permissions[$permKey] ?? 0) ? true : false;
                    $checkCls = $checked ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800' : 'bg-gray-50 dark:bg-gray-700/30 border-gray-200 dark:border-gray-700';
                ?>
                <label class="flex items-center gap-2 px-3 py-2 rounded-lg border <?= $checkCls ?> cursor-pointer hover:border-blue-300 dark:hover:border-blue-600 transition-colors">
                    <?php if ($isEditable): ?>
                    <input type="checkbox" data-user-id="<?= $user['id'] ?>" data-permission="<?= $permKey ?>"
                           hx-post="api/update_permissions.php" hx-trigger="change" hx-target="closest label" hx-swap="outerHTML"
                           hx-vals='js:{"user_id": this.dataset.userId, "permission": this.dataset.permission, "value": this.checked ? 1 : 0}'
                           <?= $checked ? 'checked' : '' ?>
                           class="form-checkbox h-3.5 w-3.5 text-blue-600 rounded border-gray-300 focus:ring-blue-500 flex-shrink-0">
                    <?php else: ?>
                    <span class="w-3.5 h-3.5 flex-shrink-0 <?= $checked ? 'text-green-500' : 'text-gray-400' ?>"><?= $checked ? '&#10003;' : '&#10007;' ?></span>
                    <?php endif; ?>
                    <div class="min-w-0">
                        <div class="text-xs font-medium text-gray-700 dark:text-gray-300"><?= $permInfo['label'] ?></div>
                        <div class="text-[10px] text-gray-400 truncate"><?= $permInfo['desc'] ?></div>
                    </div>
                </label>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endforeach; ?>

        <?php if ($isEditable): ?>
        <div class="flex items-center gap-2 mt-2 pt-2 border-t border-gray-100 dark:border-gray-700">
            <button onclick="setAllPerms(<?= $user['id'] ?>, true)" class="text-[10px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-green-50 hover:text-green-700 hover:border-green-300"><?= t('perms.enable_all') ?></button>
            <button onclick="setAllPerms(<?= $user['id'] ?>, false)" class="text-[10px] px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-red-50 hover:text-red-700 hover:border-red-300"><?= t('perms.disable_all') ?></button>
        </div>
        <?php endif; ?>
    </div>
</details>
<?php endforeach; ?>
</div>

<script>
// updatePermission() est maintenant gere par htmx (hx-post sur les checkboxes)

function setAllPerms(userId, enable) {
    const card = document.querySelector(`.perm-card [data-user-id="${userId}"]`)?.closest('.perm-card');
    if (!card) return;
    card.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        if (cb.checked !== enable) {
            cb.checked = enable;
            htmx.trigger(cb, 'change'); // Declenche le hx-trigger="change"
        }
    });
}
</script>

<!-- Permissions temporaires -->
<div class="mt-8">
    <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('perms.temp_title') ?></h2>
        <button onclick="document.getElementById('temp-perm-form').classList.toggle('hidden')" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"><?= t('perms.temp_grant') ?></button>
    </div>

    <!-- Formulaire -->
    <div id="temp-perm-form" class="hidden bg-gray-50 dark:bg-gray-700/30 rounded-xl p-4 mb-4">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
                <label class="text-[10px] text-gray-500"><?= t('perms.temp_user') ?></label>
                <select id="tp-user" class="w-full text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1.5 bg-white dark:bg-gray-800">
                    <?php foreach ($users as $u): ?>
                    <option value="<?= $u['id'] ?>"><?= htmlspecialchars($u['name']) ?> (<?= $u['role'] ?>)</option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="text-[10px] text-gray-500"><?= t('perms.temp_permission') ?></label>
                <select id="tp-perm" class="w-full text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1.5 bg-white dark:bg-gray-800">
                    <?php foreach ($permGroups as $group => $perms): ?>
                    <optgroup label="<?= $group ?>">
                        <?php foreach ($perms as $key => $info): ?>
                        <option value="<?= $key ?>"><?= $info['label'] ?></option>
                        <?php endforeach; ?>
                    </optgroup>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="text-[10px] text-gray-500"><?= t('perms.temp_duration') ?></label>
                <select id="tp-hours" class="w-full text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1.5 bg-white dark:bg-gray-800">
                    <option value="1"><?= getLang()==='en' ? '1 hour' : '1 heure' ?></option>
                    <option value="4"><?= getLang()==='en' ? '4 hours' : '4 heures' ?></option>
                    <option value="8"><?= getLang()==='en' ? '8 hours' : '8 heures' ?></option>
                    <option value="24" selected><?= getLang()==='en' ? '24 hours' : '24 heures' ?></option>
                    <option value="48"><?= getLang()==='en' ? '48 hours' : '48 heures' ?></option>
                    <option value="168"><?= getLang()==='en' ? '1 week' : '1 semaine' ?></option>
                    <option value="720"><?= getLang()==='en' ? '30 days' : '30 jours' ?></option>
                </select>
            </div>
            <div>
                <label class="text-[10px] text-gray-500"><?= t('perms.temp_reason') ?></label>
                <input id="tp-reason" type="text" placeholder="<?= getLang()==='en' ? 'External contractor...' : 'Intervention prestataire...' ?>" class="w-full text-xs border border-gray-300 dark:border-gray-600 rounded px-2 py-1.5 bg-white dark:bg-gray-800">
            </div>
        </div>
        <button onclick="grantTempPerm()" class="mt-3 bg-blue-600 hover:bg-blue-700 text-white text-xs px-4 py-1.5 rounded font-medium"><?= t('perms.temp_submit') ?></button>
    </div>

    <!-- Liste des permissions actives -->
    <div id="temp-perms-list" class="space-y-2">
        <p class="text-xs text-gray-400"><?= t('common.loading') ?></p>
    </div>
</div>

<script>
async function loadTempPerms() {
    try {
        const r = await fetch(`${window.API_URL}/admin/temp_permissions`);
        const d = await r.json();
        const list = document.getElementById('temp-perms-list');
        if (!d.success || !d.permissions.length) {
            list.innerHTML = '<p class="text-xs text-gray-400"><?= t('perms.temp_empty') ?></p>';
            return;
        }
        list.innerHTML = d.permissions.map(p => {
            const exp = new Date(p.expires_at);
            const now = new Date();
            const hoursLeft = Math.max(0, Math.round((exp - now) / 3600000));
            return `<div class="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800">
                <div class="flex-1 min-w-0">
                    <span class="text-sm font-medium text-gray-800 dark:text-gray-200">${escHtml(p.user_name)}</span>
                    <span class="text-xs text-yellow-600 dark:text-yellow-400 ml-2">${escHtml(p.permission)}</span>
                    ${p.machine_name ? `<span class="text-[10px] text-gray-400 ml-1">${__('temp_on')} ${escHtml(p.machine_name)}</span>` : ''}
                    <div class="text-[10px] text-gray-400">${__('temp_by')} ${escHtml(p.granted_by_name)} — ${escHtml(p.reason || __('temp_no_reason'))}</div>
                </div>
                <div class="flex items-center gap-2 flex-shrink-0">
                    <span class="text-xs font-mono ${hoursLeft < 4 ? 'text-red-500' : 'text-yellow-600'}">${hoursLeft}${__('temp_hours_left')}</span>
                    <button onclick="revokeTempPerm(${parseInt(p.id)})" class="text-[10px] px-2 py-0.5 rounded bg-red-100 text-red-600 hover:bg-red-200">${__('temp_revoke')}</button>
                </div>
            </div>`;
        }).join('');
    } catch(e) { console.error('loadTempPerms:', e); }
}

async function grantTempPerm() {
    const userId = document.getElementById('tp-user').value;
    const permission = document.getElementById('tp-perm').value;
    const hours = document.getElementById('tp-hours').value;
    const reason = document.getElementById('tp-reason').value;
    const r = await fetch(`${window.API_URL}/admin/temp_permissions`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({user_id: parseInt(userId), permission, hours: parseInt(hours), reason})
    });
    const d = await r.json();
    toast(d.message, d.success ? 'success' : 'error');
    if (d.success) { loadTempPerms(); document.getElementById('tp-reason').value = ''; }
}

async function revokeTempPerm(id) {
    if (!confirm(__('temp_revoke_confirm'))) return;
    await fetch(`${window.API_URL}/admin/temp_permissions/${id}`, {method: 'DELETE'});
    toast(__('temp_revoked'), 'success');
    loadTempPerms();
}

document.addEventListener('DOMContentLoaded', loadTempPerms);
</script>
