<?php
/**
 * manage_access.php - Attribution des serveurs aux utilisateurs
 * Design : cartes par user avec serveurs en badges toggle
 */
require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);

$stmt_users = $pdo->query("SELECT u.id, u.name, r.name AS role, u.role_id FROM users u JOIN roles r ON u.role_id = r.id ORDER BY u.role_id DESC, u.name");
$users = $stmt_users->fetchAll(PDO::FETCH_ASSOC);

$stmt_servers = $pdo->query("SELECT id, name, ip, environment FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' ORDER BY name");
$servers = $stmt_servers->fetchAll(PDO::FETCH_ASSOC);

$stmt_attr = $pdo->query("SELECT user_id, machine_id, sudo_preset, sudo_nopasswd, sudo_runas FROM user_machine_access");
$access_matrix = [];
foreach ($stmt_attr->fetchAll(PDO::FETCH_ASSOC) as $a) {
    $access_matrix[$a['user_id']][$a['machine_id']] = [
        'sudo_preset' => $a['sudo_preset'] ?? 'none',
        'sudo_nopasswd' => (bool)$a['sudo_nopasswd'],
        'sudo_runas' => $a['sudo_runas'] ?? 'root',
    ];
}
// v1.22.0 : presets sudo disponibles pour le dropdown inline
$SUDO_PRESETS = [
    'none' => t('access.sudo_preset_none'),
    'apt_only' => t('access.sudo_preset_apt_only'),
    'restart_services' => t('access.sudo_preset_restart_services'),
    'read_logs' => t('access.sudo_preset_read_logs'),
    'systemctl_specific' => t('access.sudo_preset_systemctl_specific'),
    'all_nopasswd' => t('access.sudo_preset_all_nopasswd'),
    'custom' => t('access.sudo_preset_custom'),
];
$isSuperAdmin = (int)($_SESSION['role_id'] ?? 0) === 3;
?>

<div class="flex items-center justify-between mb-2">
    <div>
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('access.title') ?></h2>
        <p class="text-xs text-gray-400 mt-0.5"><?= t('access.desc') ?></p>
    </div>
    <input type="text" placeholder="<?= t('common.filter') ?>"
           class="w-44 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 flex-shrink-0"
           oninput="document.querySelectorAll('.access-card').forEach(c => { c.style.display = c.dataset.name.includes(this.value.toLowerCase()) ? '' : 'none'; })">
</div>

<div class="space-y-3">
<?php foreach ($users as $user):
    $userAccess = $access_matrix[$user['id']] ?? [];
    $accessCount = count($userAccess);
    $roleCls = match((int)$user['role_id']) {
        3 => 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
        2 => 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
    };
?>
<details class="access-card bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden"
         data-name="<?= htmlspecialchars(strtolower($user['name'])) ?>">
    <summary class="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 select-none">
        <div class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            <?= strtoupper(substr($user['name'], 0, 1)) ?>
        </div>
        <span class="font-medium text-sm text-gray-800 dark:text-gray-200"><?= htmlspecialchars($user['name']) ?></span>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full <?= $roleCls ?>"><?= htmlspecialchars($user['role']) ?></span>
        <span class="text-xs px-2 py-0.5 rounded-full <?= $accessCount > 0 ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300 font-medium' : 'bg-gray-100 dark:bg-gray-700 text-gray-400' ?>"><?= $accessCount ?>/<?= count($servers) ?> serveur<?= count($servers) > 1 ? 's' : '' ?></span>
        <?php if ((int)$user['role_id'] >= 2): ?>
        <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300" title="<?= t('access.tip_global') ?>"><?= t('access.global_access') ?></span>
        <?php endif; ?>
    </summary>

    <div class="px-4 pb-4 pt-2 border-t border-gray-100 dark:border-gray-700">
        <div class="flex items-center justify-between mb-2">
            <span class="text-[10px] text-gray-400 uppercase tracking-wider"><?= t('access.accessible') ?></span>
            <div class="flex gap-1">
                <button onclick="toggleAllAccess(<?= $user['id'] ?>, true)" class="text-[10px] px-2 py-0.5 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-green-50 hover:text-green-700"><?= t('access.select_all') ?></button>
                <button onclick="toggleAllAccess(<?= $user['id'] ?>, false)" class="text-[10px] px-2 py-0.5 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-red-50 hover:text-red-700"><?= t('access.select_none') ?></button>
            </div>
        </div>
        <div class="flex flex-col gap-2" id="servers-<?= $user['id'] ?>">
            <?php foreach ($servers as $srv):
                $hasAccess = isset($userAccess[$srv['id']]);
                $sudoPresetCur = $hasAccess ? ($userAccess[$srv['id']]['sudo_preset'] ?? 'none') : 'none';
                $sudoNopasswdCur = $hasAccess ? ($userAccess[$srv['id']]['sudo_nopasswd'] ?? false) : false;
                $envCls = match($srv['environment'] ?? '') {
                    'PROD' => 'border-red-300 dark:border-red-700',
                    'DEV' => 'border-green-300 dark:border-green-700',
                    'TEST' => 'border-yellow-300 dark:border-yellow-700',
                    default => 'border-gray-300 dark:border-gray-600',
                };
                $activeCls = $hasAccess
                    ? 'bg-blue-50 dark:bg-blue-900/30 border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300'
                    : "bg-gray-50 dark:bg-gray-700/30 $envCls text-gray-500 dark:text-gray-400";
                // Badge sudo : couleur selon criticite
                $sudoBadgeCls = match($sudoPresetCur) {
                    'all_nopasswd' => 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
                    'custom' => 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
                    'none' => 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400',
                    default => 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
                };
            ?>
            <div class="flex flex-col gap-1.5 server-card w-full" data-user="<?= $user['id'] ?>" data-machine="<?= $srv['id'] ?>">
                <button class="access-btn flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors <?= $activeCls ?>"
                        data-user="<?= $user['id'] ?>" data-machine="<?= $srv['id'] ?>" data-active="<?= $hasAccess ? '1' : '0' ?>"
                        onclick="toggleAccess(this)">
                    <span class="w-2.5 h-2.5 rounded-full <?= $hasAccess ? 'bg-blue-500' : 'bg-gray-300 dark:bg-gray-500' ?> flex-shrink-0"></span>
                    <span class="font-medium"><?= htmlspecialchars($srv['name']) ?></span>
                    <span class="text-xs opacity-70"><?= htmlspecialchars($srv['ip']) ?></span>
                    <?php if ($hasAccess && $sudoPresetCur !== 'none'): ?>
                    <span class="text-xs px-2 py-0.5 rounded-full font-semibold ml-1 <?= $sudoBadgeCls ?>" title="<?= t('access.sudo_active') ?>">
                        sudo:<?= $sudoPresetCur ?><?= $sudoNopasswdCur ? '!' : '' ?>
                    </span>
                    <?php endif; ?>
                </button>
                <?php if ($hasAccess && $isSuperAdmin): ?>
                <!-- v1.22.1 : dropdown inline preset sudo + lien vers UI avance -->
                <div class="flex flex-wrap items-center gap-2 pl-3 pr-2 py-1.5 bg-gray-50 dark:bg-gray-900/40 rounded-lg border border-gray-200 dark:border-gray-700 sudo-row">
                    <label class="text-xs font-medium text-gray-600 dark:text-gray-300 flex items-center gap-1">
                        <svg class="w-3.5 h-3.5 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                        <?= t('access.sudo_label') ?>
                    </label>
                    <select class="sudo-preset text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500 min-w-[220px]"
                            data-user="<?= $user['id'] ?>" data-machine="<?= $srv['id'] ?>"
                            onchange="updateSudoPreset(this)">
                        <?php foreach ($SUDO_PRESETS as $val => $label): ?>
                        <option value="<?= $val ?>" <?= $val === $sudoPresetCur ? 'selected' : '' ?>><?= htmlspecialchars($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <label class="text-xs text-gray-600 dark:text-gray-300 flex items-center gap-1.5 cursor-pointer">
                        <input type="checkbox" class="sudo-nopasswd form-checkbox h-4 w-4 text-purple-600 rounded"
                               <?= $sudoNopasswdCur ? 'checked' : '' ?>
                               data-user="<?= $user['id'] ?>" data-machine="<?= $srv['id'] ?>"
                               onchange="updateSudoPreset(this)">
                        <span class="font-medium">NOPASSWD</span>
                    </label>
                    <a href="/adm/server_user_policies.php?server=<?= $srv['id'] ?>" target="_blank"
                       class="text-xs text-blue-600 dark:text-blue-400 hover:underline ml-auto flex items-center gap-1"
                       title="<?= t('access.advanced_tip') ?>">
                        <?= t('access.advanced') ?>
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                    </a>
                </div>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php if ((int)$user['role_id'] >= 2): ?>
        <p class="text-[10px] text-gray-400 mt-2"><?= getLang()==='en' ? 'Admins and superadmins see all servers even without explicit assignment.' : 'Les admins et superadmins voient tous les serveurs meme sans attribution explicite.' ?></p>
        <?php endif; ?>
    </div>
</details>
<?php endforeach; ?>
</div>

<script>
async function updateSudoPreset(el) {
    const userId = el.dataset.user;
    const machineId = el.dataset.machine;
    const card = el.closest('.server-card');
    if (!card) return;
    const preset = card.querySelector('.sudo-preset')?.value || 'none';
    const nopasswd = card.querySelector('.sudo-nopasswd')?.checked ? 1 : 0;
    try {
        const r = await fetch('api/update_server_access.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId, machine_id: machineId, action: 'update_sudo',
                sudo_preset: preset, sudo_nopasswd: nopasswd, sudo_runas: 'root',
                csrf_token: '<?= htmlspecialchars($_SESSION['csrf_token']) ?>'
            })
        });
        const d = await r.json();
        if (typeof toast === 'function') {
            toast(d.message || (d.success ? 'OK' : 'Erreur'), d.success ? 'success' : 'error', d.success ? 2500 : 5000);
        }
        if (d.success) {
            // Refresh badge sur le bouton parent
            const btn = card.querySelector('.access-btn');
            const existing = btn?.querySelector('span.rounded');
            if (existing) existing.remove();
            if (preset !== 'none') {
                const badge = document.createElement('span');
                badge.className = 'text-[9px] px-1 py-0.5 rounded ' + (
                    preset === 'all_nopasswd' ? 'bg-red-100 text-red-700' :
                    preset === 'custom' ? 'bg-amber-100 text-amber-700' :
                    'bg-purple-100 text-purple-700'
                );
                badge.textContent = 'sudo:' + preset + (nopasswd ? '!' : '');
                btn?.appendChild(badge);
            }
        }
    } catch (e) {
        if (typeof toast === 'function') toast('Erreur reseau : ' + e, 'error');
    }
}

async function toggleAccess(btn) {
    const userId = btn.dataset.user;
    const machineId = btn.dataset.machine;
    const isActive = btn.dataset.active === '1';
    const newState = !isActive;

    try {
        const r = await fetch('api/update_server_access.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                user_id: userId,
                machine_id: machineId,
                action: newState ? 'add' : 'remove',
                csrf_token: '<?= htmlspecialchars($_SESSION['csrf_token']) ?>'
            })
        });
        const d = await r.json();
        if (d.success) {
            btn.dataset.active = newState ? '1' : '0';
            const dot = btn.querySelector('.rounded-full');
            if (newState) {
                btn.className = btn.className.replace(/bg-gray-50|dark:bg-gray-700\/30|border-\w+-300|dark:border-\w+-\d+|text-gray-\d+/g, '');
                btn.classList.add('bg-blue-50','dark:bg-blue-900/30','border-blue-300','dark:border-blue-700','text-blue-700','dark:text-blue-300');
                dot.classList.remove('bg-gray-300','dark:bg-gray-500');
                dot.classList.add('bg-blue-500');
            } else {
                btn.className = btn.className.replace(/bg-blue-50|dark:bg-blue-900\/30|border-blue-300|dark:border-blue-700|text-blue-\d+|dark:text-blue-\d+/g, '');
                btn.classList.add('bg-gray-50','dark:bg-gray-700/30','border-gray-300','dark:border-gray-600','text-gray-500','dark:text-gray-400');
                dot.classList.remove('bg-blue-500');
                dot.classList.add('bg-gray-300','dark:bg-gray-500');
            }
            // Update counter in summary
            const card = btn.closest('.access-card');
            const count = card.querySelectorAll('.access-btn[data-active="1"]').length;
            const total = card.querySelectorAll('.access-btn').length;
            const counter = card.querySelector('summary span.text-xs');
            if (counter) counter.textContent = `${count}/${total} serveur${total > 1 ? 's' : ''}`;
        } else {
            toast(d.message || __('toast_error'), 'error');
        }
    } catch(e) { toast(__('toast_network_error'), 'error'); }
}

function toggleAllAccess(userId, enable) {
    const container = document.getElementById('servers-' + userId);
    if (!container) return;
    container.querySelectorAll('.access-btn').forEach(btn => {
        if ((btn.dataset.active === '1') !== enable) toggleAccess(btn);
    });
}
</script>
