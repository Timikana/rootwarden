<?php
/**
 * update/linux_updates.php — Interface principale de gestion des mises à jour Linux
 *
 * Rôle :
 *   Tableau de bord permettant aux admins de visualiser, filtrer et opérer sur
 *   la flotte de serveurs Linux. Fonctionnalités disponibles :
 *     - Filtrage par environnement (PROD/DEV/TEST/OTHER), criticité et type réseau
 *     - Vérification des versions Linux installées et des statuts en ligne
 *     - Lancement de mises à jour globales (apt update/upgrade) ou de sécurité
 *     - Mise à jour de l'agent Zabbix sur les machines sélectionnées
 *     - Planification de mises à jour de sécurité (date + heure + récurrence)
 *     - Affichage des logs de mise à jour par serveur (fenêtres séparées)
 *
 * Permissions :
 *   - admin      (role_id = 2) : autorisé
 *   - superadmin (role_id = 3) : autorisé
 *   Accès refusé aux utilisateurs standards (role_id = 1).
 *
 * Dépendances PHP (includes) :
 *   - auth/verify.php           : fonctions checkAuth() et gestion de session
 *   - update/functions/machines.php    : fonctions de récupération/rafraîchissement des machines
 *   - update/functions/scheduling.php  : gestion de la planification des mises à jour
 *   - update/functions/zabbix.php      : fonctions spécifiques à l'agent Zabbix
 *   - update/functions/filter.php      : logique de filtrage des serveurs
 *   - db.php                    : connexion PDO ($pdo)
 *   - head.php / menu.php / footer.php : gabarits HTML communs
 *
 * Scripts JavaScript inclus :
 *   - update/js/domManipulation.js : manipulation DOM (tableau, logs, modals)
 *   - update/js/apiCalls.js        : appels API backend (versions, statuts, mises à jour)
 *
 * Colonnes chargées depuis la BDD :
 *   id, name, ip, port, linux_version, last_checked, online_status,
 *   zabbix_agent_version, maj_secu_date, maj_secu_last_exec_date,
 *   last_reboot, environment, criticality, network_type
 */

// Inclusion des fichiers nécessaires
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/functions/machines.php';    // Fonctions CRUD et rafraîchissement machines
require_once __DIR__ . '/functions/scheduling.php';  // Planification des mises à jour
require_once __DIR__ . '/functions/zabbix.php';      // Mise à jour agent Zabbix
require_once __DIR__ . '/functions/filter.php';      // Filtrage serveurs (env/criticité/réseau)
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Restreint l'accès aux administrateurs (2) et superadmins (3)
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_update_linux');

// Récupération des machines avec filtrage par acces utilisateur
$role = (int) ($_SESSION['role_id'] ?? 0);
$machineQuery = "SELECT m.id, m.name, m.ip, m.port, m.linux_version, m.last_checked,
    m.online_status, m.zabbix_agent_version, m.maj_secu_date, m.maj_secu_last_exec_date,
    m.last_reboot, m.environment, m.criticality, m.network_type
    FROM machines m";
if ($role < 2) {
    $machineQuery = "SELECT m.id, m.name, m.ip, m.port, m.linux_version, m.last_checked,
        m.online_status, m.zabbix_agent_version, m.maj_secu_date, m.maj_secu_last_exec_date,
        m.last_reboot, m.environment, m.criticality, m.network_type
        FROM machines m
        INNER JOIN user_machine_access uma ON m.id = uma.machine_id
        WHERE uma.user_id = ?";
    $stmt = $pdo->prepare($machineQuery);
    $stmt->execute([$_SESSION['user_id']]);
} else {
    $stmt = $pdo->query($machineQuery);
}
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);


?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('updates.title') ?></title>
    <style>
        .logs-container {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            /*max-height: 500px; /* Limite la hauteur globale */
            /*overflow-y: auto; /* Active le scroll si nécessaire */
        }

        .server-log-window {
            border: 1px solid #444;
            background-color: #1e1e1e;
            color: #d4d4d4;
            width: 45%; /* Ajuste la taille */
            min-height: 200px; /* Taille minimum */
            max-height: 400px; /* Évite les fenêtres trop grandes */
            padding: 0.5rem;
            overflow-y: auto; /* Active le scroll dans chaque fenêtre */
            border-radius: 5px;
        }

        .server-log-window h3 {
            margin: 0 0 0.5rem 0;
            font-family: sans-serif;
            font-size: 1.1rem;
            color: #90caf9;
        }

        .log-line {
            margin: 0;
            padding: 2px 0;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 300px; /* Évite que les logs débordent */
            overflow-y: auto;
        }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6">
        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('updates.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('updates.subtitle') ?></p>
                <p class="text-xs text-gray-400 mt-0.5"><?= t('updates.desc') ?></p>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" onclick="selectAll(true)" class="text-xs px-3 py-1.5 rounded-lg border border-green-300 dark:border-green-700 text-green-700 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/30 transition-colors"><?= t('updates.btn_check_all') ?></button>
                <button type="button" onclick="selectAll(false)" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('updates.btn_uncheck_all') ?></button>
                <button onclick="refreshMachineList()" class="text-xs px-3 py-1.5 rounded-lg border border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 transition-colors"><?= t('updates.btn_refresh') ?></button>
            </div>
        </div>

        <!-- Filtres + Actions dans une barre compacte -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
            <div class="flex flex-wrap items-end gap-3">
                <!-- Filtres inline -->
                <div class="flex-1 min-w-0">
                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('updates.filter_env') ?></label>
                    <select id="environment" class="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        <option value=""><?= t('updates.filter_all') ?></option><option value="PROD">PROD</option><option value="DEV">DEV</option><option value="TEST">TEST</option><option value="OTHER"><?= t('updates.filter_other') ?></option>
                    </select>
                </div>
                <div class="flex-1 min-w-0">
                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('updates.filter_criticality') ?></label>
                    <select id="criticality" class="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        <option value=""><?= t('updates.filter_all') ?></option><option value="CRITIQUE"><?= t('updates.filter_critical') ?></option><option value="NON CRITIQUE"><?= t('updates.filter_non_critical') ?></option>
                    </select>
                </div>
                <div class="flex-1 min-w-0">
                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('updates.filter_network') ?></label>
                    <select id="network-type" class="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        <option value=""><?= t('updates.filter_all') ?></option><option value="INTERNE"><?= t('updates.filter_internal') ?></option><option value="EXTERNE"><?= t('updates.filter_external') ?></option>
                    </select>
                </div>
                <div class="flex-1 min-w-0">
                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('updates.filter_tag') ?></label>
                    <select id="tag-filter" class="w-full px-2 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        <option value=""><?= t('updates.filter_all') ?></option>
                        <?php
                        $tagList = $pdo->query("SELECT DISTINCT tag FROM machine_tags ORDER BY tag")->fetchAll(PDO::FETCH_COLUMN);
                        foreach ($tagList as $t): ?>
                            <option value="<?= htmlspecialchars($t) ?>"><?= htmlspecialchars($t) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button onclick="filterServers()" class="px-4 py-1.5 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors whitespace-nowrap"><?= t('updates.btn_filter') ?></button>
                <!-- Separator -->
                <div class="hidden lg:block w-px h-8 bg-gray-200 dark:bg-gray-700"></div>
                <!-- Actions groupees -->
                <div class="flex flex-wrap gap-1.5">
                    <button onclick="checkLinuxVersion()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('updates.btn_versions') ?></button>
                    <button onclick="checkServerStatus()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('updates.btn_statuses') ?></button>
                    <button type="button" onclick="getSelectedMachineIds().forEach(id => fetchLastReboot(id))" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('updates.btn_boot') ?></button>
                    <button onclick="checkPendingPackages()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('updates.btn_packages') ?></button>
                    <button onclick="dryRunUpdate()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors" title="<?= t('updates.dry_run_tip') ?>"><?= t('updates.dry_run') ?></button>
                    <span class="w-px h-6 bg-gray-300 dark:bg-gray-600 self-center"></span>
                    <button onclick="updateLinux()" class="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors font-medium"><?= t('updates.btn_apt_update') ?></button>
                    <button onclick="applySecurityUpdates()" class="text-xs px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-600 text-white transition-colors font-medium"><?= t('updates.btn_secu_update') ?></button>
                    <button onclick="dpkgRepair()" class="text-xs px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white transition-colors font-medium" title="<?= t('updates.tip_dpkg_repair') ?>"><?= t('updates.btn_dpkg_repair') ?></button>
                </div>
            </div>
            <!-- Zabbix compact -->
            <div class="flex items-center gap-3 mt-3 pt-3 border-t border-gray-100 dark:border-gray-700">
                <span class="text-xs font-medium text-purple-600 dark:text-purple-400 whitespace-nowrap"><?= t('updates.zabbix_agent') ?></span>
                <input type="text" id="zabbix-version" placeholder="7.0" class="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 w-24">
                <button onclick="updateZabbix()" class="text-xs px-3 py-1.5 rounded-lg bg-purple-500 hover:bg-purple-600 text-white transition-colors"><?= t('updates.btn_update_zabbix') ?></button>
            </div>
        </div>

        <div class="flex gap-3 text-[10px] text-gray-400 mt-1 mb-2">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-red-500 inline-block"></span> PROD</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-500 inline-block"></span> DEV</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-yellow-500 inline-block"></span> TEST</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-500 inline-block"></span> PREPROD</span>
        </div>

        <!-- ── Tableau principal ───────────────────────────────────────────────────
             Généré en PHP au chargement initial ; peut être rechargé via JS
             (populateMachineTable dans domManipulation.js) après filtrage AJAX.
             Chaque ligne a data-machine-id, data-ip et data-port pour les appels JS.
             Les classes CSS (linux-version, online-status…) servent de sélecteurs
             aux fonctions de mise à jour DOM dans domManipulation.js. -->
        <form id="update-form">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-x-auto mb-6">
            <table class="w-full table-auto text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500 dark:text-gray-400">
                    <tr>
                        <th class="p-2"><?= t('updates.th_selection') ?></th>
                        <th class="p-2"><?= t('updates.th_name') ?></th>
                        <th class="p-2"><?= t('updates.th_linux') ?></th>
                        <th class="p-2"><?= t('updates.th_last_check') ?></th>
                        <th class="p-2"><?= t('updates.th_ip_port') ?></th>
                        <th class="p-2"><?= t('updates.th_status') ?></th>
                        <th class="p-2"><?= t('updates.th_zabbix') ?></th>
                        <th class="p-2"><?= t('updates.th_secu_schedule') ?></th>
                        <th class="p-2"><?= t('updates.th_last_exec') ?></th>
                        <th class="p-2"><?= t('updates.th_last_reboot') ?></th>
                        <th class="p-2"><?= t('updates.th_env') ?></th>
                        <th class="p-2"><?= t('updates.th_criticality') ?></th>
                        <th class="p-2"><?= t('updates.th_network') ?></th>
                        <th class="p-2"><?= t('updates.th_actions') ?></th>
                    </tr>
                </thead>
                <tbody id="server-table-body">
                    <?php foreach ($machines as $m): ?>
                        <tr class="border-b border-gray-200 dark:border-gray-700"
                            data-machine-id="<?= $m['id'] ?>"
                            data-ip="<?= htmlspecialchars($m['ip']) ?>"
                            data-port="<?= htmlspecialchars($m['port']) ?>">

                            <td class="p-2 text-center">
                                <input type="checkbox" name="selected_machines[]" value="<?= $m['id'] ?>" class="form-checkbox h-4 w-4 text-blue-600 dark:text-blue-400">
                            </td>
                            <td class="p-2 font-semibold server-name"><?= htmlspecialchars($m['name']) ?></td>
                            <td class="p-2 linux-version"><?= htmlspecialchars($m['linux_version'] ?? t('updates.not_checked')) ?></td>
                            <td class="p-2 last-checked"><?= htmlspecialchars($m['last_checked'] ?? t('updates.not_checked')) ?></td>
                            <td class="p-2"><?= htmlspecialchars($m['ip']) ?>:<?= htmlspecialchars($m['port']) ?></td>
                            <td class="p-2 online-status"><?= htmlspecialchars($m['online_status'] ?? t('updates.unknown')) ?></td>
                            <td class="p-2 zabbix-version text-center"><?= htmlspecialchars($m['zabbix_agent_version'] ?? 'N/A') ?></td>
                            <td class="p-2 maj-secu-date text-center"><?= htmlspecialchars($m['maj_secu_date'] ?? 'N/A') ?></td>
                            <td class="p-2 maj-secu-lastexec-date text-center"><?= htmlspecialchars($m['maj_secu_last_exec_date'] ?? 'N/A') ?></td>
                            <td class="p-2 last-reboot" id="last-reboot-<?= htmlspecialchars($m['id']) ?>"><?= htmlspecialchars($m['last_reboot'] ?? 'N/A') ?></td>
                            <td class="p-2 environment text-center"><?= htmlspecialchars($m['environment'] ?? 'OTHER') ?></td>
                            <td class="p-2 criticality text-center"><?= htmlspecialchars($m['criticality'] ?? 'NON CRITIQUE') ?></td>
                            <td class="p-2 network-type text-center"><?= htmlspecialchars($m['network_type'] ?? 'INTERNE') ?></td>
                            <td class="p-2 space-y-1 text-xs">
                                <button type="button" onclick="openScheduleModal(<?= (int)$m['id'] ?>)"
                                        class="bg-gray-500 dark:bg-gray-600 text-white px-2 py-1 rounded block hover:bg-gray-600 dark:hover:bg-gray-700 w-full">
                                    <?= t('updates.btn_schedule') ?>
                                </button>
                                <button type="button" onclick="openSecurityScheduleModal(<?= (int)$m['id'] ?>)"
                                        class="bg-amber-500 dark:bg-amber-600 text-white px-2 py-1 rounded block hover:bg-amber-600 dark:hover:bg-amber-700 w-full">
                                    <?= t('updates.btn_schedule_secu') ?>
                                </button>
                                <!-- Bouton pour rafraîchir le dernier redémarrage -->

                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        </form>

        <!-- ── Modal de planification avancée (mise à jour de sécurité) ───────────
             Ouvert par openSecurityScheduleModal(machineId) (domManipulation.js).
             Collecte date, heure et récurrence, puis appelle saveSecuritySchedule(). -->
        <!-- Modal de planification générale -->
        <div id="schedule-modal" class="hidden fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
            <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg w-full max-w-md">
                <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-3"><?= t('updates.modal_schedule_title') ?></h3>
                <div class="space-y-3">
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('updates.modal_date') ?></label>
                        <input type="date" id="sched-date" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('updates.modal_time') ?></label>
                        <input type="time" id="sched-time" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1"><?= t('updates.modal_repeat') ?></label>
                        <select id="sched-repeat" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            <option value="none"><?= t('updates.repeat_none') ?></option>
                            <option value="daily"><?= t('updates.repeat_daily') ?></option>
                            <option value="weekly"><?= t('updates.repeat_weekly') ?></option>
                            <option value="monthly"><?= t('updates.repeat_monthly') ?></option>
                        </select>
                    </div>
                </div>
                <div class="flex justify-end gap-2 mt-4">
                    <button onclick="closeScheduleModal()" class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('common.cancel') ?></button>
                    <button onclick="saveAdvancedSchedule()" class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"><?= t('common.save') ?></button>
                </div>
            </div>
        </div>

        <!-- Modal de planification sécurité -->
        <div id="security-schedule-modal" class="hidden fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
            <div class="bg-white dark:bg-gray-800 p-6 rounded shadow-md w-1/3">
                <h3 class="text-xl font-bold text-red-600 dark:text-red-400 mb-2"><?= t('updates.modal_secu_title') ?></h3>
                <p class="text-sm text-gray-700 dark:text-gray-300 mb-3"><?= t('updates.modal_secu_desc') ?></p>

                <label class="block text-gray-700 dark:text-gray-300"><?= t('updates.modal_date') ?> :</label>
                <input type="date" id="sec-date" class="border dark:border-gray-700 rounded p-2 w-full mb-2 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                
                <label class="block text-gray-700 dark:text-gray-300"><?= t('updates.modal_time') ?> :</label>
                <input type="time" id="sec-time" class="border dark:border-gray-700 rounded p-2 w-full mb-2 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                
                <label class="block text-gray-700 dark:text-gray-300"><?= t('updates.modal_repeat') ?> :</label>
                <select id="sec-repeat" class="border dark:border-gray-700 rounded p-2 w-full mb-2 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                    <option value="none"><?= t('updates.repeat_none') ?></option>
                    <option value="daily"><?= t('updates.repeat_daily') ?></option>
                    <option value="weekly"><?= t('updates.repeat_weekly') ?></option>
                    <option value="monthly"><?= t('updates.repeat_monthly') ?></option>
                </select>
                
                <div class="flex justify-end space-x-2 mt-4">
                    <button class="bg-green-600 dark:bg-green-700 text-white px-4 py-2 rounded hover:bg-green-700 dark:hover:bg-green-800"
                            onclick="saveSecuritySchedule()">
                        <?= t('common.save') ?>
                    </button>
                    <button class="bg-red-500 dark:bg-red-600 text-white px-4 py-2 rounded hover:bg-red-600 dark:hover:bg-red-700"
                            onclick="closeSecurityScheduleModal()">
                        <?= t('common.cancel') ?>
                    </button>
                </div>
            </div>
        </div>



        <!-- ── Logs de mise à jour ─────────────────────────────────────────────────
             Deux zones de logs coexistent :
             - #logs-container : fenêtres de logs par serveur (créées dynamiquement
               par appendServerLog() dans domManipulation.js via la classe .server-log-window)
             - #logs : zone de logs globale (appendLog() dans domManipulation.js) -->
        <!-- Logs -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
            <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('updates.logs_title') ?></h2>
        </div>
        <!-- Fenêtres de logs individuelles par serveur (layout flex-wrap défini en CSS) -->
        <div id="logs-container" class="logs-container"></div>
        <!-- Zone de logs globale pour les messages généraux -->
        <div id="logs" class="bg-gray-900 text-green-400 p-4 font-mono text-xs leading-relaxed h-48 overflow-y-auto whitespace-pre-line"></div>
        </div>
    </div>

    <!-- Scripts JavaScript -->
    <!-- domManipulation.js : manipulation DOM, construction du tableau, gestion des modals -->
    <script src="/update/js/domManipulation.js?v=<?= filemtime(__DIR__ . '/js/domManipulation.js') ?>"></script>
    <!-- apiCalls.js : appels API backend (versions, statuts, mises à jour, filtrage) -->
    <script src="/update/js/apiCalls.js?v=<?= filemtime(__DIR__ . '/js/apiCalls.js') ?>"></script>
    <?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
