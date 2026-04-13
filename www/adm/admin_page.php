<?php
/**
 * admin_page.php — Page d'administration principale (superadmin uniquement)
 *
 * Rôle : tableau de bord central réservé aux superadmins. Orchestre l'affichage
 *        de six sections métier incluses dynamiquement :
 *          - manage_users           : gestion des clés SSH des utilisateurs portail
 *          - user_exclusions        : exclusions d'utilisateurs de la synchronisation
 *          - manage_servers         : gestion des machines (CRUD serveurs)
 *          - manage_access          : attribution des accès utilisateur ↔ machine
 *          - manage_roles           : gestion des comptes portail (activation, sudo…)
 *          - manage_permissions     : gestion des droits fonctionnels par utilisateur
 *
 * Accès requis : rôle superadmin (role_name = 'superadmin', role_id = 3).
 *                Un premier filtre rapide est assuré par checkAuth([2, 3]) ;
 *                une seconde vérification stricte via la BDD n'autorise que le superadmin.
 *
 * Type de réponse : HTML (page complète avec layout Tailwind CSS).
 *
 * Endpoints AJAX appelés depuis cette page :
 *   POST update_user_status.php   — active/désactive un utilisateur
 *   POST update_server_access.php — ajoute ou retire un accès machine
 */

// --- Dépendances ---
// verify.php : démarre la session et valide le jeton JWT/session
// functions.php : fournit checkAuth(), checkCsrfToken(), etc.
// db.php : initialise l'objet PDO $pdo
// crypto.php : fonctions de chiffrement/déchiffrement Sodium
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/includes/crypto.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Controle d'acces : admin/superadmin + permission can_admin_portal
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

// --- Import CSV (traitement POST) ---
require_once __DIR__ . '/includes/import_csv.php';

// --- Chargement de la liste des utilisateurs ---
// Utilisée par les sections includes pour afficher les tableaux de gestion.
$stmt = $pdo->query("SELECT id, name, ssh_key, active, sudo FROM users");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// --- Vérification de la session ---
// Sécurité additionnelle : s'assure qu'un user_id est bien présent en session
// (normalement garanti par verify.php, mais défense en profondeur).
if (!isset($_SESSION['user_id'])) {
    die(t('admin.error_no_user'));
}

// Journalisation de l'ID de l'utilisateur actif pour le débogage applicatif.
error_log("ID utilisateur connecté : " . $_SESSION['user_id']);

// Controle d'acces deja assure par checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])
// + checkPermission('can_admin_portal') en haut du fichier.
// Le role et les permissions sont verifies en DB par ces fonctions.

// --- Chargement de la liste des serveurs ---
// Utilisée notamment par manage_access et manage_servers pour construire
// les tableaux et listes déroulantes.
$stmt_servers = $pdo->query("SELECT id, name FROM machines");
$all_servers = $stmt_servers->fetchAll(PDO::FETCH_ASSOC);

/**
 * Retourne les permissions fonctionnelles d'un utilisateur.
 *
 * Interroge la table `permissions` pour un utilisateur donné et retourne un
 * tableau associatif avec les droits disponibles. Si aucune ligne n'existe
 * pour cet utilisateur, les permissions sont initialisées à 0 (tout refusé).
 *
 * @param PDO $pdo     Connexion PDO active.
 * @param int $user_id Identifiant de l'utilisateur cible.
 *
 * @return array Tableau associatif des permissions :
 *               [
 *                 'can_deploy_keys'    => int,  // 0 ou 1
 *                 'can_update_linux'   => int,  // 0 ou 1
 *                 'can_manage_iptables'=> int,  // 0 ou 1
 *               ]
 */
function getPermissions($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT * FROM permissions WHERE user_id = ?");
    $stmt->execute([$user_id]);
    // Valeurs par défaut si l'utilisateur n'a pas encore de ligne de permissions
    return $stmt->fetch(PDO::FETCH_ASSOC) ?? [
        'can_deploy_keys' => 0,
        'can_update_linux' => 0,
        'can_manage_iptables' => 0
    ];
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>Administration — <?= htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden') ?></title>
    <style>
        .tab-btn { transition: all 0.15s; }
        .tab-btn.active { border-bottom: 3px solid #3b82f6; color: #3b82f6; font-weight: 600; }
        .tab-btn:not(.active) { border-bottom: 3px solid transparent; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6">

        <!-- ── Header avec stats ───────────────────────────────────────── -->
        <?php
        $nbUsers = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
        $nbServers = $pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn();
        $nbOnline = $pdo->query("SELECT COUNT(*) FROM machines WHERE online_status = 'Online'")->fetchColumn();
        $nbRetiring = 0; $nbArchived = 0;
        try {
            $nbRetiring = $pdo->query("SELECT COUNT(*) FROM machines WHERE lifecycle_status = 'retiring'")->fetchColumn();
            $nbArchived = $pdo->query("SELECT COUNT(*) FROM machines WHERE lifecycle_status = 'archived'")->fetchColumn();
        } catch (\Exception $e) {}
        $recentLogs = $pdo->query("SELECT l.action, l.created_at, u.name FROM user_logs l JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);
        ?>
        <div class="flex items-center justify-between mb-4">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('admin.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= $nbUsers ?> <?= t('admin.stats_users') ?> &middot; <?= $nbServers ?> <?= t('admin.stats_servers') ?> (<?= $nbOnline ?> <?= t('admin.stats_online') ?>)<?php if ($nbRetiring > 0): ?> &middot; <span class="text-yellow-500"><?= $nbRetiring ?> <?= t('admin.stats_retiring') ?></span><?php endif; ?><?php if ($nbArchived > 0): ?> &middot; <span class="text-red-400"><?= $nbArchived ?> <?= t('admin.stats_archived') ?></span><?php endif; ?></p>
            </div>
            <div class="flex flex-wrap gap-2">
                <a href="/adm/audit_log.php" title="<?= t('admin.tip_journal') ?>" class="inline-flex items-center gap-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
                    <?= t('admin.btn_journal') ?>
                </a>
                <a href="/adm/health_check.php" title="<?= t('admin.tip_diagnostic') ?>" class="inline-flex items-center gap-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    <?= t('admin.btn_diagnostic') ?>
                </a>
                <a href="/adm/server_users.php" title="<?= t('admin.tip_remote_users') ?>" class="inline-flex items-center gap-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
                    <?= t('admin.btn_remote_users') ?>
                </a>
                <a href="/adm/platform_keys.php" title="<?= t('admin.tip_ssh_key') ?>" class="inline-flex items-center gap-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                    <?= t('admin.btn_ssh_key') ?>
                </a>
                <button onclick="manageBackups()" title="<?= t('admin.tip_backups') ?>" class="inline-flex items-center gap-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                    <?= t('admin.btn_backups') ?>
                </button>
            </div>
        </div>
        <?php if (!empty($recentLogs)): ?>
        <div class="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-3 mb-4">
            <p class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-2"><?= t('admin.recent_activity') ?></p>
            <div class="space-y-1">
                <?php foreach ($recentLogs as $log): ?>
                <div class="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                    <span class="text-gray-400"><?= date('d/m H:i', strtotime($log['created_at'])) ?></span>
                    <span class="font-medium text-gray-700 dark:text-gray-300"><?= htmlspecialchars($log['name']) ?></span>
                    <span><?= htmlspecialchars($log['action']) ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- ── Onglets ────────────────────────────────────────────────── -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <!-- Tab bar -->
            <div class="flex border-b border-gray-200 dark:border-gray-700 overflow-x-auto" id="admin-tabs">
                <button class="tab-btn active px-5 py-3 text-sm whitespace-nowrap hover:bg-gray-50 dark:hover:bg-gray-700" data-tab="users">
                    <svg class="w-4 h-4 inline mr-1.5 -mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
                    <?= t('admin.tab_users') ?>
                </button>
                <button class="tab-btn px-5 py-3 text-sm whitespace-nowrap text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700" data-tab="servers">
                    <svg class="w-4 h-4 inline mr-1.5 -mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
                    <?= t('admin.tab_servers') ?>
                </button>
                <button class="tab-btn px-5 py-3 text-sm whitespace-nowrap text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700" data-tab="access">
                    <svg class="w-4 h-4 inline mr-1.5 -mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                    <?= t('admin.tab_access') ?>
                </button>
                <!-- Exclusions supprimees — gerees dans /adm/server_users.php -->
            </div>

            <?php if ($importResult): ?>
            <div class="px-6 pt-4">
                <div class="rounded-lg p-3 text-sm <?= $importResult['type'] === 'success' ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border border-green-200' : ($importResult['type'] === 'error' ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border border-red-200' : 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border border-yellow-200') ?>">
                    <strong><?= htmlspecialchars($importResult['msg']) ?></strong>
                    <?php if (!empty($importResult['details'])): ?>
                    <details class="mt-2">
                        <summary class="text-xs cursor-pointer"><?= getLang()==='en' ? 'View errors' : 'Voir les erreurs' ?></summary>
                        <ul class="text-xs mt-1 space-y-0.5 list-disc ml-4">
                            <?php foreach ($importResult['details'] as $err): ?>
                            <li><?= htmlspecialchars($err) ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </details>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- ── Tab 1 : Utilisateurs ───────────────────────────────── -->
            <div class="tab-panel active p-6" id="panel-users">
<?php
$tipId = 'admin-setup'; $tipTitle = t('tip.admin_title'); $tipSteps = [
    t('tip.admin_step1'), t('tip.admin_step2'), t('tip.admin_step3'),
    t('tip.admin_step4'), t('tip.admin_step5'),
]; require __DIR__ . '/../includes/howto_tip.php';
?>
                <!-- Import CSV utilisateurs -->
                <details class="mb-6 bg-gray-50 dark:bg-gray-700/30 rounded-xl">
                    <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-gray-600 dark:text-gray-300 hover:text-blue-600">
                        <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                        <?= t('admin.import_users') ?>
                    </summary>
                    <form method="POST" enctype="multipart/form-data" class="px-4 pb-4">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="import_type" value="users">
                        <div class="flex flex-wrap items-end gap-3 mt-2">
                            <div>
                                <label class="text-xs text-gray-500"><?= t('admin.csv_file') ?></label>
                                <input type="file" name="csv_file" accept=".csv" required class="block text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                            </div>
                            <label class="flex items-center gap-1.5 text-xs text-gray-500"><input type="checkbox" name="skip_duplicates" checked class="rounded"> <?= t('admin.skip_duplicates') ?></label>
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-1.5 rounded font-medium"><?= t('admin.import') ?></button>
                        </div>
                        <p class="text-[10px] text-gray-400 mt-1"><?= t('admin.csv_hint_users') ?></p>
                    </form>
                </details>
                <?php require_once __DIR__ . '/includes/manage_users.php'; ?>
                <hr class="my-8 border-gray-200 dark:border-gray-700">
                <?php require_once __DIR__ . '/includes/manage_roles.php'; ?>
            </div>

            <!-- ── Tab 2 : Serveurs ───────────────────────────────────── -->
            <div class="tab-panel p-6" id="panel-servers">
                <!-- Import CSV serveurs -->
                <details class="mb-6 bg-gray-50 dark:bg-gray-700/30 rounded-xl">
                    <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-gray-600 dark:text-gray-300 hover:text-blue-600">
                        <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                        <?= t('admin.import_servers') ?>
                    </summary>
                    <form method="POST" enctype="multipart/form-data" class="px-4 pb-4">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="import_type" value="servers">
                        <div class="flex flex-wrap items-end gap-3 mt-2">
                            <div>
                                <label class="text-xs text-gray-500"><?= t('admin.csv_file') ?></label>
                                <input type="file" name="csv_file" accept=".csv" required class="block text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                            </div>
                            <label class="flex items-center gap-1.5 text-xs text-gray-500"><input type="checkbox" name="skip_duplicates" checked class="rounded"> <?= t('admin.skip_duplicates') ?></label>
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-1.5 rounded font-medium"><?= t('admin.import') ?></button>
                        </div>
                        <p class="text-[10px] text-gray-400 mt-1"><?= t('admin.csv_hint_servers') ?></p>
                    </form>
                </details>
                <?php require_once __DIR__ . '/includes/manage_servers.php'; ?>
            </div>

            <!-- ── Tab 3 : Acces & Droits ─────────────────────────────── -->
            <div class="tab-panel p-6" id="panel-access">
                <?php require_once __DIR__ . '/includes/manage_access.php'; ?>
                <hr class="my-8 border-gray-200 dark:border-gray-700">
                <?php require_once __DIR__ . '/includes/manage_permissions.php'; ?>
                <hr class="my-8 border-gray-200 dark:border-gray-700">
                <?php require_once __DIR__ . '/includes/manage_notifications.php'; ?>
            </div>

            <!-- Exclusions gerees dans /adm/server_users.php -->
        </div>
    </div>

    <!-- Scripts : onglets + AJAX -->
    <script>
    // ── Gestion des onglets ──────────────────────────────────────────────────
    function switchTab(tabName) {
        const tabs = document.querySelectorAll('.tab-btn');
        const panels = document.querySelectorAll('.tab-panel');
        tabs.forEach(t => { t.classList.remove('active'); t.classList.add('text-gray-500'); });
        panels.forEach(p => p.classList.remove('active'));
        const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
        if (btn) {
            btn.classList.add('active');
            btn.classList.remove('text-gray-500');
        }
        const panel = document.getElementById('panel-' + tabName);
        if (panel) panel.classList.add('active');
        history.replaceState(null, '', '#' + tabName);
    }

    // Bind click events
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Restore from hash on full page load (after all scripts)
    window.addEventListener('load', () => {
        const hash = location.hash.replace('#', '');
        if (hash && document.querySelector(`.tab-btn[data-tab="${hash}"]`)) {
            switchTab(hash);
        }
    });
    </script>

    <script>
    /**
     * Met à jour un champ booléen d'un utilisateur (actif, sudo, etc.) via AJAX.
     *
     * Appelle POST update_user_status.php avec un body JSON :
     *   { user_id: int, field: string, value: 0|1 }
     * Réponse attendue :
     *   { success: bool, message: string }
     *
     * @param {number} userId - Identifiant de l'utilisateur cible.
     * @param {string} field  - Nom du champ à mettre à jour ('active', 'sudo'…).
     * @param {boolean} value - Nouvelle valeur (convertie en 0 ou 1 côté serveur).
     */
    function updateUserStatus(userId, field, value) {
        fetch('api/update_user_status.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, field: field, value: value ? 1 : 0 })
        }).then(response => response.json())
          .then(data => { if (data.success !== false) { toast(data.message || __('toast_success'), 'success'); setTimeout(() => location.reload(), 800); } else toast(data.message, 'error'); })
          .catch(error => console.error('Error:', error));
    }

    /**
     * Gestionnaire générique sur les cases à cocher de classe 'server-checkbox'.
     * Envoie une requête AJAX à update_server_access.php pour ajouter ou retirer
     * un accès utilisateur ↔ machine.
     *
     * Attributs data requis sur la case à cocher :
     *   data-user-id    : identifiant de l'utilisateur
     *   data-machine-id : identifiant de la machine
     *
     * Body JSON envoyé :
     *   { user_id: int, machine_id: int, action: 'add'|'remove' }
     * Réponse attendue :
     *   { success: bool, message: string }
     *
     * En cas d'erreur (réseau ou métier), l'état de la case est annulé (rollback visuel).
     */
    document.querySelectorAll('.server-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            const userId = checkbox.dataset.userId;
            const machineId = checkbox.dataset.machineId;
            // Détermine l'action en fonction du nouvel état de la case
            const action = checkbox.checked ? 'add' : 'remove';

            fetch('api/update_server_access.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, machine_id: machineId, action: action })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    toast(data.message || __('access_updated'), 'success');
                } else {
                    toast(__('toast_error') + ' : ' + data.message, 'error');
                    console.error('Error:', data.message);
                    checkbox.checked = !checkbox.checked; // Annule le changement
                }
            })
            .catch(error => {
                console.error('Network error:', error);
                toast(__('toast_network_error'), 'error');
                checkbox.checked = !checkbox.checked; // Annule le changement
            });
        });
    });

    /**
     * Met à jour l'accès d'un utilisateur à un serveur depuis la section
     * manage_access (cases à cocher individuelles avec data-server-id).
     *
     * Appelle POST update_server_access.php.
     * Body JSON :
     *   { user_id: int, server_id: int, action: 'add'|'remove' }
     * Réponse attendue :
     *   { success: bool, message: string }
     *
     * @param {HTMLInputElement} checkbox - Case à cocher déclenchant l'événement.
     */
    function updateAccess(checkbox) {
        const userId = checkbox.dataset.userId;
        const serverId = checkbox.dataset.serverId;
        const action = checkbox.checked ? 'add' : 'remove';

        fetch('api/update_server_access.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, server_id: serverId, action: action })
        })
        .then(response => response.json())
        .then(data => {
            if (!data.success) {
                toast(data.message, 'error');
                checkbox.checked = !checkbox.checked; // Annule en cas d'erreur
            }
        })
        .catch(error => {
            console.error('Network error:', error);
            toast(__('toast_network_error'), 'error');
            checkbox.checked = !checkbox.checked;
        });
    }
</script>

<!-- Backup modal -->
<div id="backup-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200"><?= t('admin.backup_title') ?></h3>
            <button onclick="document.getElementById('backup-modal').classList.add('hidden')" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
        </div>
        <div class="p-6">
            <div class="flex items-center justify-between mb-4">
                <button onclick="createBackup()" id="btn-create-backup" class="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-2 rounded-lg font-medium disabled:opacity-50">
                    <?= t('admin.backup_create') ?>
                </button>
                <span id="backup-status" class="text-xs text-gray-400"></span>
            </div>
            <div id="backup-list" class="space-y-2 max-h-64 overflow-y-auto">
                <p class="text-sm text-gray-400"><?= t('common.loading') ?></p>
            </div>
        </div>
    </div>
</div>
<script>
async function manageBackups() {
    document.getElementById('backup-modal').classList.remove('hidden');
    loadBackupList();
}
async function loadBackupList() {
    const list = document.getElementById('backup-list');
    try {
        const r = await fetch(`${window.API_URL}/admin/backups`);
        const d = await r.json();
        if (!d.success || !d.backups.length) {
            list.innerHTML = '<p class="text-sm text-gray-400">' + __('no_backup') + '</p>';
            return;
        }
        list.innerHTML = d.backups.map(b => {
            const date = new Date(b.created_at).toLocaleString(window.LANG === 'en' ? 'en-GB' : 'fr-FR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
            return `<div class="flex items-center justify-between px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                <div><span class="text-sm font-mono text-gray-700 dark:text-gray-300">${b.filename}</span>
                <span class="text-xs text-gray-400 ml-2">${b.size_mb} MB</span></div>
                <span class="text-xs text-gray-400">${date}</span>
            </div>`;
        }).join('');
    } catch(e) { list.innerHTML = '<p class="text-sm text-red-400">' + __('toast_error') + '</p>'; }
}
async function createBackup() {
    const btn = document.getElementById('btn-create-backup');
    const status = document.getElementById('backup-status');
    btn.disabled = true; status.textContent = __('backup_progress');
    try {
        const r = await fetch(`${window.API_URL}/admin/backups`, {method:'POST', headers:{'Content-Type':'application/json'}});
        const d = await r.json();
        if (d.success) { toast(__('backup_created'), 'success'); loadBackupList(); }
        else toast(d.message || __('toast_error'), 'error');
    } catch(e) { toast(__('toast_network_error'), 'error'); }
    btn.disabled = false; status.textContent = '';
}
</script>
<script src="/js/admin.js?v=<?= filemtime(__DIR__ . '/../js/admin.js') ?>"></script>

</body>
<?php require_once __DIR__ . '/../footer.php'; ?>

</html>