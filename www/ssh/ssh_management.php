<?php
/**
 * ssh/ssh_management.php — Interface de déploiement des clés SSH
 *
 * Rôle :
 *   Affiche la liste de toutes les machines disponibles et permet à
 *   l'administrateur de sélectionner des cibles pour déclencher un
 *   déploiement de clé SSH via le backend Python.
 *   Après l'appel POST /deploy, les logs du déploiement sont récupérés
 *   en temps réel via Server-Sent Events (SSE) depuis l'endpoint /logs.
 *
 * Permissions :
 *   - admin      (role_id = 2) : autorisé
 *   - superadmin (role_id = 3) : autorisé
 *   Accès refusé pour les utilisateurs standards (role_id = 1).
 *
 * Dépendances PHP :
 *   - auth/verify.php : fonctions checkAuth() et gestion de session
 *   - db.php          : connexion PDO ($pdo)
 *   - head.php / menu.php / footer.php : gabarits HTML communs
 *
 * APIs backend appelées (JavaScript côté client) :
 *   - POST /deploy : déclenche le déploiement SSH sur les machines sélectionnées
 *                    Corps JSON : { machines: [id, ...] }
 *                    Header     : X-API-KEY
 *   - GET  /logs   : flux SSE des logs de déploiement en temps réel
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
// Restreint l'accès aux administrateurs (2) et superadmins (3)
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_deploy_keys');

// Récupère les machines avec filtrage par acces utilisateur
$role = (int) ($_SESSION['role_id'] ?? 0);
if ($role >= 2) {
    // Admins et superadmins voient toutes les machines
    $stmt = $pdo->query("SELECT m.id, m.name, m.ip, m.port, m.environment,
        GROUP_CONCAT(mt.tag SEPARATOR ',') as tags
        FROM machines m LEFT JOIN machine_tags mt ON m.id = mt.machine_id
        WHERE (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')
        GROUP BY m.id ORDER BY m.name");
} else {
    // Users voient seulement les machines qui leur sont attribuees
    $stmt = $pdo->prepare("SELECT m.id, m.name, m.ip, m.port, m.environment,
        GROUP_CONCAT(mt.tag SEPARATOR ',') as tags
        FROM machines m
        INNER JOIN user_machine_access uma ON uma.machine_id = m.id
        LEFT JOIN machine_tags mt ON m.id = mt.machine_id
        WHERE uma.user_id = ? AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')
        GROUP BY m.id ORDER BY m.name");
    $stmt->execute([$_SESSION['user_id']]);
}
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Liste des tags et environnements pour les filtres
$allTags = $pdo->query("SELECT DISTINCT tag FROM machine_tags ORDER BY tag")->fetchAll(PDO::FETCH_COLUMN);
$allEnvs = array_unique(array_filter(array_column($machines, 'environment')));
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('ssh.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/../menu.php'; ?>
    
    <div class="px-6 py-6">
        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('ssh.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= count($machines) ?> <?= t('ssh.servers_available') ?></p>
                <p class="text-xs text-gray-400 mt-0.5"><?= t('ssh.desc') ?></p>
            </div>
<?php
$tipId = 'ssh-deploy'; $tipTitle = t('tip.ssh_title'); $tipSteps = [
    t('tip.ssh_step1'), t('tip.ssh_step2'), t('tip.ssh_step3'),
    t('tip.ssh_step4'), t('tip.ssh_step5'),
]; require __DIR__ . '/../includes/howto_tip.php';
?>
            <div class="flex flex-wrap items-center gap-2">
                <?php if (!empty($allTags)): ?>
                <select id="filter-tag" onchange="filterMachines()" class="text-xs border border-gray-300 dark:border-gray-600 rounded-lg px-2 py-1.5 bg-white dark:bg-gray-800">
                    <option value=""><?= t('ssh.all_tags') ?></option>
                    <?php foreach ($allTags as $tag): ?>
                    <option value="<?= htmlspecialchars($tag) ?>"><?= htmlspecialchars($tag) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php endif; ?>
                <?php if (!empty($allEnvs)): ?>
                <select id="filter-env" onchange="filterMachines()" class="text-xs border border-gray-300 dark:border-gray-600 rounded-lg px-2 py-1.5 bg-white dark:bg-gray-800">
                    <option value=""><?= t('ssh.all_envs') ?></option>
                    <?php foreach ($allEnvs as $env): ?>
                    <option value="<?= htmlspecialchars($env) ?>"><?= htmlspecialchars($env) ?></option>
                    <?php endforeach; ?>
                </select>
                <?php endif; ?>
                <button type="button" onclick="selectFiltered(true)" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                    <?= t('ssh.btn_check_filtered') ?>
                </button>
                <button type="button" onclick="selectAll(true)" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                    <?= t('ssh.btn_all') ?>
                </button>
                <button type="button" onclick="selectAll(false)" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                    <?= t('ssh.btn_none') ?>
                </button>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Colonne gauche : selection des serveurs -->
            <div class="lg:col-span-1">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('ssh.target_servers') ?></h2>
                    </div>
                    <form id="deploy-form">
                        <div class="divide-y divide-gray-100 dark:divide-gray-700">
                        <?php foreach ($machines as $machine): ?>
                            <?php if (empty($machine['id'])) continue; ?>
                            <label class="machine-item flex items-center gap-3 px-4 py-3 hover:bg-blue-50 dark:hover:bg-blue-900/20 cursor-pointer transition-colors"
                                   data-tags="<?= htmlspecialchars($machine['tags'] ?? '') ?>"
                                   data-env="<?= htmlspecialchars($machine['environment'] ?? '') ?>">
                                <input type="checkbox" name="selected_machines[]" value="<?= $machine['id'] ?>"
                                       class="form-checkbox h-4 w-4 text-blue-600 rounded border-gray-300 dark:border-gray-600 focus:ring-blue-500">
                                <div class="flex-1 min-w-0">
                                    <div class="text-sm font-medium text-gray-800 dark:text-gray-200 truncate">
                                        <?= htmlspecialchars($machine['name']) ?>
                                        <?php if ($machine['environment']): ?>
                                        <span class="text-[10px] px-1 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-500 ml-1"><?= htmlspecialchars($machine['environment']) ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="text-xs text-gray-400 font-mono"><?= htmlspecialchars($machine['ip']) ?>:<?= htmlspecialchars($machine['port']) ?><?php if ($machine['tags']): ?> <span class="text-indigo-400"><?= htmlspecialchars($machine['tags']) ?></span><?php endif; ?></div>
                                </div>
                            </label>
                        <?php endforeach; ?>
                        <?php if (empty($machines)): ?>
                            <div class="px-4 py-8 text-center text-gray-400 text-sm"><?= t('ssh.no_servers') ?></div>
                        <?php endif; ?>
                        </div>
                    </form>
                    <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-t border-gray-200 dark:border-gray-600">
                        <button id="deploy-btn" onclick="deploySSH()"
                                class="w-full inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2.5 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                            <svg id="deploy-spinner" class="hidden w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                            <svg class="w-4 h-4" id="deploy-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                            <span id="deploy-label"><?= t('ssh.btn_deploy') ?></span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Colonne droite : logs -->
            <div class="lg:col-span-2">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden h-full flex flex-col">
                    <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('ssh.deploy_logs') ?></h2>
                    </div>
                    <div id="logs" class="flex-1 bg-gray-900 text-green-400 p-4 font-mono text-xs leading-relaxed overflow-y-auto min-h-[400px] whitespace-pre-line">
                        <span class="text-gray-500"><?= t('ssh.waiting_deploy') ?></span>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
// Variables PHP injectees
const availableMachines = <?= json_encode($machines) ?>;
</script>
<script src="/ssh/js/sshManagement.js?v=<?= filemtime(__DIR__ . '/js/sshManagement.js') ?>"></script>
</body>
<?php require_once __DIR__ . '/../footer.php'; ?>
</html>
