<?php
// manage_servers.php

require_once __DIR__ . '/../../auth/functions.php';
require_once __DIR__ . '/../../auth/verify.php';
require_once __DIR__ . '/../../db.php';
require_once __DIR__ . '/crypto.php';

// Autorise les utilisateurs ayant le rôle admin (2) ou superadmin (3)
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Valide un nom de serveur : uniquement lettres, chiffres, tirets et underscores (1–255 caractères).
 *
 * @param  string $name  Nom à valider.
 * @return bool
 */
function validateServerName($name) {
    return preg_match('/^[a-zA-Z0-9-_]{1,255}$/', $name);
}

/**
 * Valide et assainit une valeur selon son type attendu.
 *
 * @param  string $data  Valeur brute à valider.
 * @param  string $type  Type : 'name' | 'ip' | 'port' | 'string' | 'rsa_key' |
 *                              'environment' | 'criticality' | 'network_type'
 * @return string|false  Valeur assainie, ou false si invalide.
 */
function validateInput($data, $type) {
    $data = trim($data); // Supprime les espaces inutiles
    switch ($type) {
        case 'name':
            return validateServerName($data) ? $data : false;
        case 'ip':
            return filter_var($data, FILTER_VALIDATE_IP) ? $data : false;
        case 'port':
            return filter_var($data, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]) ? $data : false;
        case 'string':
            return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        case 'rsa_key': // Validation simple pour une clé RSA
            $data = trim($data);
            if (empty($data)) {
                // Utiliser la clé par défaut depuis la variable d'environnement
                return getenv('DEFAULT_RSA_KEY');
            }
            // Vérifier que la clé est une chaîne hexadécimale de 64 caractères
            return preg_match('/^[a-fA-F0-9]{64}$/', $data) ? $data : false;
        case 'environment':
            $valid_env = ['PROD', 'DEV', 'TEST', 'OTHER'];
            return in_array($data, $valid_env) ? $data : false;
        case 'criticality':
            $valid_crit = ['CRITIQUE', 'NON CRITIQUE'];
            return in_array($data, $valid_crit) ? $data : false;
        case 'network_type':
            $valid_net = ['INTERNE', 'EXTERNE'];
            return in_array($data, $valid_net) ? $data : false;
        default:
            return false;
    }
}

// Variables pour stocker les messages
$successSERVER = null;
$error = null;

// Traitement des actions non-AJAX (pour la compatibilité)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['add_server'])) {
        checkCsrfToken();
    
        $name = validateInput($_POST['name'], 'name');
        $ip = validateInput($_POST['ip'], 'ip');
        $user = validateInput($_POST['user'], 'string');
        $password = encryptPassword(trim($_POST['password']), false);
        $root_password = encryptPassword(trim($_POST['root_password']), false);
        $port = validateInput($_POST['port'], 'port');
        $environment = validateInput($_POST['environment'], 'environment');
        $criticality = validateInput($_POST['criticality'], 'criticality');
        $network_type = validateInput($_POST['network_type'], 'network_type');

        $invalidFields = array_filter([
            !$name         ? t('servers.field_name')        : null,
            !$ip           ? t('servers.field_ip')          : null,
            !$user         ? t('servers.field_user')        : null,
            !$port         ? t('servers.field_port')        : null,
            !$environment  ? t('servers.field_environment') : null,
            !$criticality  ? t('servers.field_criticality') : null,
            !$network_type ? t('servers.field_network')     : null,
        ]);

        if (!empty($invalidFields)) {
            $error = t('servers.error_invalid_fields') . ' ' . implode(', ', $invalidFields) . ".";
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO machines (name, ip, user, password, root_password, port, environment, criticality, network_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$name, $ip, $user, $password, $root_password, $port, $environment, $criticality, $network_type]);
                $successSERVER = t('servers.added_success');
            } catch (PDOException $e) {
                if ($e->getCode() == 23000) {
                    $error = t('servers.error_duplicate');
                } else {
                    error_log("Erreur SQL manage_servers (add): " . $e->getMessage());
                    $error = t('servers.error_add');
                }
            }
        }
    } elseif (isset($_POST['update_server'])) {
        checkCsrfToken();
    
        $server_id = validateInput($_POST['server_id'], 'port');
        $name = validateInput($_POST['name'], 'name');
        $ip = validateInput($_POST['ip'], 'ip');
        $user = validateInput($_POST['user'], 'string');
        $port = validateInput($_POST['port'], 'port');
        $environment = validateInput($_POST['environment'], 'environment');
        $criticality = validateInput($_POST['criticality'], 'criticality');
        $network_type = validateInput($_POST['network_type'], 'network_type');

        $invalidFields = array_filter([
            !$server_id    ? t('servers.field_server_id')   : null,
            !$name         ? t('servers.field_name')        : null,
            !$ip           ? t('servers.field_ip')          : null,
            !$user         ? t('servers.field_user')        : null,
            !$port         ? t('servers.field_port')        : null,
            !$environment  ? t('servers.field_environment') : null,
            !$criticality  ? t('servers.field_criticality') : null,
            !$network_type ? t('servers.field_network')     : null,
        ]);

        if (!empty($invalidFields)) {
            $error = t('servers.error_invalid_fields') . ' ' . implode(', ', $invalidFields) . ".";
        } else {
            $stmt = $pdo->prepare("SELECT password, root_password FROM machines WHERE id = ?");
            $stmt->execute([$server_id]);
            $current_passwords = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$current_passwords) {
                $error = t('servers.error_not_found');
            } else {
                $password = empty($_POST['password']) ? $current_passwords['password'] : encryptPassword(trim($_POST['password']), false);
                $root_password = empty($_POST['root_password']) ? $current_passwords['root_password'] : encryptPassword(trim($_POST['root_password']), false);
    
                try {
                    $cleanup_users = isset($_POST['cleanup_users']) ? 1 : 0;
                    $stmt = $pdo->prepare("UPDATE machines SET name = ?, ip = ?, user = ?, password = ?, root_password = ?, port = ?, environment = ?, criticality = ?, network_type = ?, cleanup_users = ? WHERE id = ?");
                    $stmt->execute([$name, $ip, $user, $password, $root_password, $port, $environment, $criticality, $network_type, $cleanup_users, $server_id]);
                    $successSERVER = t('servers.updated_success');
                } catch (PDOException $e) {
                    if ($e->getCode() == 23000) {
                        $error = t('servers.error_duplicate');
                    } else {
                        error_log("Erreur SQL manage_servers (update): " . $e->getMessage());
                        $error = t('servers.error_update');
                    }
                }
            }
        }
    } elseif (isset($_POST['delete_server'])) {
        checkCsrfToken();
    
        $server_id = validateInput($_POST['server_id'], 'port');
        if (!$server_id) {
            $error = t('servers.error_invalid_id');
        } else {
            try {
                $stmt = $pdo->prepare("DELETE FROM machines WHERE id = ?");
                $stmt->execute([$server_id]);
                $successSERVER = t('servers.deleted_success');
            } catch (PDOException $e) {
                error_log("Erreur SQL manage_servers (delete): " . $e->getMessage());
                $error = t('servers.error_delete');
            }
        }
    }
}

// Paramètres par défaut pour le chargement initial
$itemsPerPage = 5;
$currentPage = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$offset = ($currentPage - 1) * $itemsPerPage;
$searchQuery = isset($_GET['search']) ? trim($_GET['search']) : '';
$filterEnvironment = isset($_GET['environment']) ? $_GET['environment'] : '';
$filterNetwork = isset($_GET['network']) ? $_GET['network'] : '';
$filterCriticality = isset($_GET['criticality']) ? $_GET['criticality'] : '';
$sortColumn = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$sortDirection = isset($_GET['dir']) && $_GET['dir'] === 'desc' ? 'DESC' : 'ASC';

// Requête pour obtenir les données initiales
$countSql = "SELECT COUNT(*) FROM machines";
$sql = "SELECT * FROM machines";

$whereConditions = [];
$params = [];

if (!empty($searchQuery)) {
    $whereConditions[] = "(name LIKE ? OR ip LIKE ? OR user LIKE ?)";
    $searchParam = "%$searchQuery%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $params[] = $searchParam;
}

if (!empty($filterEnvironment)) {
    $whereConditions[] = "environment = ?";
    $params[] = $filterEnvironment;
}

if (!empty($filterNetwork)) {
    $whereConditions[] = "network_type = ?";
    $params[] = $filterNetwork;
}

if (!empty($filterCriticality)) {
    $whereConditions[] = "criticality = ?";
    $params[] = $filterCriticality;
}

if (!empty($whereConditions)) {
    $whereClause = " WHERE " . implode(' AND ', $whereConditions);
    $countSql .= $whereClause;
    $sql .= $whereClause;
}

// Valider le tri
$allowedColumns = ['name', 'ip', 'port', 'user', 'environment', 'criticality', 'network_type', 'online_status'];
if (!in_array($sortColumn, $allowedColumns)) {
    $sortColumn = 'name';
}

$sql .= " ORDER BY `$sortColumn` $sortDirection LIMIT " . (int)$offset . ", " . (int)$itemsPerPage;

// Récupération des données
$countStmt = $pdo->prepare($countSql);
$countStmt->execute($params);
$totalItems = $countStmt->fetchColumn();
$totalPages = ceil($totalItems / $itemsPerPage);

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$all_servers = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupération des serveurs
$stmt_servers = $pdo->query("SELECT * FROM machines");
$all_servers = $stmt_servers->fetchAll(PDO::FETCH_ASSOC);
?>

        <div class="flex items-center justify-between mb-4">
            <h2 class="text-xl font-bold text-gray-800 dark:text-gray-100"><?= t('servers.title') ?></h2>
            <span class="text-xs text-gray-400"><?= t('servers.count', ['count' => count($all_servers)]) ?></span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5"><?= t('servers.desc') ?></p>
        <div class="flex gap-3 text-[10px] text-gray-400 mt-1 mb-2">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-red-500 inline-block"></span> PROD</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-green-500 inline-block"></span> DEV</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-yellow-500 inline-block"></span> TEST</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-500 inline-block"></span> PREPROD</span>
        </div>

        <?php if (isset($successSERVER)): ?>
            <script>document.addEventListener('DOMContentLoaded', () => toast(<?= json_encode($successSERVER) ?>, 'success'));</script>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <script>document.addEventListener('DOMContentLoaded', () => toast(<?= json_encode($error) ?>, 'error'));</script>
        <?php endif; ?>

        <div id="notification" class="mb-4 p-4 hidden border rounded"></div>

        <!-- Formulaire d'ajout (collapsible) -->
        <details class="bg-green-50 dark:bg-green-900/20 rounded-lg mb-6">
            <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-900/40 rounded-lg transition-colors">
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg>
                <?= t('servers.add_server_title') ?>
            </summary>
            <form id="add-server-form" method="POST" class="p-4 pt-2">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_name') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="text" name="name" required maxlength="255" placeholder="srv-web-01" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_ip') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="text" name="ip" required placeholder="192.168.1.10" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_port') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="number" name="port" required min="1" max="65535" value="22" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_user') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="text" name="user" required maxlength="255" placeholder="admin" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_password') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="password" name="password" required class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_root_password') ?><span class="text-red-500 ml-0.5">*</span></label>
                        <input type="password" name="root_password" required class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_environment') ?></label>
                        <select name="environment" required title="<?= t('servers.environment_title') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                            <option value="PROD">PROD</option><option value="DEV" selected>DEV</option><option value="TEST">TEST</option><option value="OTHER"><?= t('servers.env_other') ?></option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_criticality') ?></label>
                        <select name="criticality" required title="<?= t('servers.criticality_title') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                            <option value="NON CRITIQUE" selected><?= t('servers.crit_non_critical') ?></option><option value="CRITIQUE"><?= t('servers.crit_critical') ?></option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-gray-600 dark:text-gray-400 mb-1"><?= t('servers.field_network') ?></label>
                        <select name="network_type" required class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                            <option value="INTERNE" selected><?= t('servers.net_internal') ?></option><option value="EXTERNE"><?= t('servers.net_external') ?></option>
                        </select>
                    </div>
                </div>
                <button type="submit" name="add_server" class="mt-4 px-6 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors"><?= t('servers.btn_add_server') ?></button>
                <p class="text-[10px] text-gray-400 mt-1"><?= t('servers.required_fields') ?></p>
            </form>
        </details>

        <!-- Liste des serveurs (cards) -->
        <div id="servers-cards-list">
            <!-- Recherche -->
            <div class="mb-3">
                <input type="text" placeholder="<?= t('servers.filter_placeholder') ?>" class="w-full sm:w-64 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500"
                       oninput="document.querySelectorAll('.server-card').forEach(c => { c.style.display = c.dataset.name.includes(this.value.toLowerCase()) ? '' : 'none'; })">
            </div>
            <div class="space-y-2">
                <?php foreach ($all_servers as $server):
                    $statusClass = strtolower($server['online_status'] ?? '') === 'online' ? 'bg-green-500' : (strtolower($server['online_status'] ?? '') === 'offline' ? 'bg-red-500' : 'bg-gray-400');
                ?>
                <details class="server-card bg-gray-50 dark:bg-gray-700/50 rounded-lg overflow-hidden" data-name="<?= htmlspecialchars(strtolower($server['name'])) ?>">
                    <summary class="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600/50 transition-colors select-none">
                        <svg class="w-4 h-4 text-gray-400 transition-transform flex-shrink-0" style="transition: transform 0.2s" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                        <span class="inline-block w-2 h-2 rounded-full <?= $statusClass ?> flex-shrink-0"></span>
                        <span class="font-semibold text-sm text-gray-800 dark:text-gray-200"><?= htmlspecialchars($server['name']) ?></span>
                        <span class="text-xs text-gray-400 font-mono"><?= htmlspecialchars($server['ip']) ?>:<?= htmlspecialchars($server['port']) ?></span>
                        <div class="flex gap-1.5 ml-auto">
                            <?php if ($server['platform_key_deployed'] ?? false): ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400" title="<?= t('servers.auth_keypair_title') ?>">keypair</span>
                            <?php else: ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-400" title="<?= t('servers.auth_password_title') ?>">password</span>
                            <?php endif; ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400"><?= htmlspecialchars($server['environment'] ?? 'OTHER') ?></span>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-gray-200 text-gray-600 dark:bg-gray-600 dark:text-gray-300"><?= htmlspecialchars($server['network_type'] ?? 'INTERNE') ?></span>
                        </div>
                    </summary>
                    <div class="px-4 pb-4 pt-2 border-t border-gray-200 dark:border-gray-600">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                            <input type="hidden" name="server_id" value="<?= (int)$server['id'] ?>">
                            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_name') ?></label>
                                    <input type="text" name="name" value="<?= htmlspecialchars($server['name']) ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500" maxlength="255">
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_ip') ?></label>
                                    <input type="text" name="ip" value="<?= htmlspecialchars($server['ip']) ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_port') ?></label>
                                    <input type="number" name="port" value="<?= (int)$server['port'] ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500" min="1" max="65535">
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_user') ?></label>
                                    <input type="text" name="user" value="<?= htmlspecialchars($server['user']) ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500" maxlength="255">
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_password') ?></label>
                                    <input type="password" name="password" placeholder="<?= ($server['ssh_password_required'] ?? true) ? t('servers.placeholder_unchanged') : t('servers.placeholder_removed_keypair') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 <?= !($server['ssh_password_required'] ?? true) ? 'opacity-50' : '' ?>" <?= !($server['ssh_password_required'] ?? true) ? 'disabled' : '' ?>>
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_root_password') ?></label>
                                    <input type="password" name="root_password" placeholder="<?= t('servers.placeholder_unchanged') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_environment') ?></label>
                                    <select name="environment" title="<?= t('servers.environment_title') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                                        <option value="PROD" <?= ($server['environment'] ?? '') === 'PROD' ? 'selected' : '' ?>>PROD</option>
                                        <option value="DEV" <?= ($server['environment'] ?? '') === 'DEV' ? 'selected' : '' ?>>DEV</option>
                                        <option value="TEST" <?= ($server['environment'] ?? '') === 'TEST' ? 'selected' : '' ?>>TEST</option>
                                        <option value="OTHER" <?= ($server['environment'] ?? '') === 'OTHER' ? 'selected' : '' ?>><?= t('servers.env_other') ?></option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_criticality') ?></label>
                                    <select name="criticality" title="<?= t('servers.criticality_title') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                                        <option value="CRITIQUE" <?= ($server['criticality'] ?? '') === 'CRITIQUE' ? 'selected' : '' ?>><?= t('servers.crit_critical') ?></option>
                                        <option value="NON CRITIQUE" <?= ($server['criticality'] ?? '') === 'NON CRITIQUE' ? 'selected' : '' ?>><?= t('servers.crit_non_critical') ?></option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('servers.field_network') ?></label>
                                    <select name="network_type" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                                        <option value="INTERNE" <?= ($server['network_type'] ?? '') === 'INTERNE' ? 'selected' : '' ?>><?= t('servers.net_internal') ?></option>
                                        <option value="EXTERNE" <?= ($server['network_type'] ?? '') === 'EXTERNE' ? 'selected' : '' ?>><?= t('servers.net_external') ?></option>
                                    </select>
                                </div>
                            </div>
                            <div class="text-[10px] text-gray-400 uppercase tracking-wider mt-3 mb-1.5"><?= t('servers.deploy_options') ?></div>
                            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                                <label class="flex items-center gap-2 px-3 py-2 rounded-lg border <?= ($server['cleanup_users'] ?? 1) ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800' : 'bg-gray-50 dark:bg-gray-700/30 border-gray-200 dark:border-gray-700' ?> cursor-pointer transition-colors">
                                    <input type="checkbox" name="cleanup_users" value="1" <?= ($server['cleanup_users'] ?? 1) ? 'checked' : '' ?> class="form-checkbox h-3.5 w-3.5 text-blue-600 rounded border-gray-300 focus:ring-blue-500">
                                    <div class="min-w-0">
                                        <div class="text-xs font-medium text-gray-700 dark:text-gray-300"><?= t('servers.opt_cleanup') ?></div>
                                        <div class="text-[10px] text-gray-400 truncate"><?= t('servers.opt_cleanup_desc') ?></div>
                                    </div>
                                </label>
                            </div>
                            <?php
                            $lifecycle = $server['lifecycle_status'] ?? 'active';
                            $lifecycleCls = match($lifecycle) {
                                'retiring' => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
                                'archived' => 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
                                default => '',
                            };
                            ?>
                            <?php if ($lifecycle !== 'active'): ?>
                            <div class="flex items-center gap-2 mb-2 px-2 py-1.5 rounded-lg <?= $lifecycleCls ?>">
                                <span class="text-xs font-medium"><?= $lifecycle === 'retiring' ? '&#9888; ' . t('servers.lifecycle_retiring') : '&#128451; ' . t('servers.lifecycle_archived') ?></span>
                                <?php if ($server['retire_date'] ?? null): ?>
                                <span class="text-[10px]">- <?= t('servers.lifecycle_planned_date', ['date' => htmlspecialchars($server['retire_date'])]) ?></span>
                                <?php endif; ?>
                            </div>
                            <?php endif; ?>
                            <div class="flex items-center gap-2">
                                <button type="submit" name="update_server" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"><?= t('servers.btn_save') ?></button>
                                <button type="button" onclick="testServerConnection(<?= (int)$server['id'] ?>, '<?= htmlspecialchars($server['ip']) ?>', <?= (int)$server['port'] ?>)" class="px-4 py-2 border border-green-300 text-green-600 hover:bg-green-50 dark:border-green-700 dark:text-green-400 dark:hover:bg-green-900/30 text-sm rounded-lg transition-colors"><?= t('servers.btn_test') ?></button>
                                <?php if ($lifecycle === 'active'): ?>
                                <button type="button" onclick="setLifecycle(<?= (int)$server['id'] ?>, 'retiring')" class="px-3 py-2 border border-yellow-400 text-yellow-600 hover:bg-yellow-50 dark:border-yellow-700 dark:text-yellow-400 text-xs rounded-lg transition-colors" title="<?= t('servers.btn_retire_title') ?>"><?= t('servers.btn_retire') ?></button>
                                <?php elseif ($lifecycle === 'retiring'): ?>
                                <button type="button" onclick="setLifecycle(<?= (int)$server['id'] ?>, 'archived')" class="px-3 py-2 border border-red-400 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 text-xs rounded-lg transition-colors"><?= t('servers.btn_archive') ?></button>
                                <button type="button" onclick="setLifecycle(<?= (int)$server['id'] ?>, 'active')" class="px-3 py-2 border border-green-400 text-green-600 hover:bg-green-50 text-xs rounded-lg transition-colors"><?= t('servers.btn_reactivate') ?></button>
                                <?php elseif ($lifecycle === 'archived'): ?>
                                <button type="button" onclick="setLifecycle(<?= (int)$server['id'] ?>, 'active')" class="px-3 py-2 border border-green-400 text-green-600 hover:bg-green-50 text-xs rounded-lg transition-colors"><?= t('servers.btn_reactivate') ?></button>
                                <?php endif; ?>
                                <button type="submit" name="delete_server" class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm rounded-lg transition-colors" onclick="return confirm('<?= t('servers.confirm_delete', ['name' => htmlspecialchars(addslashes($server['name']))]) ?>')"><?= t('servers.btn_delete') ?></button>
                                <span id="server-status-<?= (int)$server['id'] ?>" class="ml-auto text-xs <?= strtolower($server['online_status'] ?? '') === 'online' ? 'text-green-500' : 'text-gray-400' ?>"><?= htmlspecialchars($server['online_status'] ?? t('servers.status_unknown')) ?></span>
                            </div>
                        </form>
                        <!-- Tags -->
                        <?php
                        $tagStmt = $pdo->prepare("SELECT tag FROM machine_tags WHERE machine_id = ? ORDER BY tag");
                        $tagStmt->execute([(int)$server['id']]);
                        $tags = $tagStmt->fetchAll(PDO::FETCH_COLUMN);
                        ?>
                        <div class="mt-2 pt-2 border-t border-gray-200 dark:border-gray-600 flex items-center gap-2 flex-wrap">
                            <span class="text-xs text-gray-400"><?= t('servers.tags_label') ?></span>
                            <?php foreach ($tags as $tag): ?>
                                <span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-400">
                                    <?= htmlspecialchars($tag) ?>
                                    <button type="button" onclick="removeTag(<?= (int)$server['id'] ?>, '<?= htmlspecialchars(addslashes($tag)) ?>')" class="hover:text-red-500">&times;</button>
                                </span>
                            <?php endforeach; ?>
                            <input type="text" placeholder="+ tag" class="text-xs px-2 py-0.5 w-20 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-1 focus:ring-indigo-500 focus:w-32 transition-all"
                                   onkeydown="if(event.key==='Enter'){event.preventDefault();addTag(<?= (int)$server['id'] ?>, this.value);this.value='';}"
                                   title="<?= t('servers.tag_input_title') ?>">
                        </div>
                        <!-- Notes -->
                        <?php
                        $notesStmt = $pdo->prepare("SELECT id, author, content, created_at FROM server_notes WHERE machine_id = ? ORDER BY created_at DESC LIMIT 5");
                        try {
                            $notesStmt->execute([(int)$server['id']]);
                            $notes = $notesStmt->fetchAll(PDO::FETCH_ASSOC);
                        } catch (\Exception $e) { $notes = []; }
                        ?>
                        <div class="mt-2 pt-2 border-t border-gray-200 dark:border-gray-600">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-xs text-gray-400"><?= t('servers.notes_label') ?></span>
                            </div>
                            <?php foreach ($notes as $note): ?>
                            <div class="flex items-start gap-2 text-xs mb-1 px-2 py-1 rounded bg-gray-100 dark:bg-gray-600/30">
                                <span class="text-gray-500 flex-shrink-0"><?= date('d/m H:i', strtotime($note['created_at'])) ?></span>
                                <span class="text-gray-400 flex-shrink-0"><?= htmlspecialchars($note['author']) ?> :</span>
                                <span class="text-gray-700 dark:text-gray-300 flex-1"><?= htmlspecialchars($note['content']) ?></span>
                                <button onclick="deleteNote(<?= (int)$note['id'] ?>, <?= (int)$server['id'] ?>)" class="text-red-400 hover:text-red-600 flex-shrink-0">&times;</button>
                            </div>
                            <?php endforeach; ?>
                            <div class="flex gap-1 mt-1">
                                <input type="text" id="note-input-<?= (int)$server['id'] ?>" placeholder="<?= t('servers.note_placeholder') ?>" class="flex-1 text-xs px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 focus:ring-1 focus:ring-blue-500"
                                       onkeydown="if(event.key==='Enter'){event.preventDefault();addNote(<?= (int)$server['id'] ?>, this.value);this.value='';}">
                                <button onclick="addNote(<?= (int)$server['id'] ?>, document.getElementById('note-input-<?= (int)$server['id'] ?>').value); document.getElementById('note-input-<?= (int)$server['id'] ?>').value='';" class="text-xs px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded">+</button>
                            </div>
                        </div>
                    </div>
                </details>
                <?php endforeach; ?>
                <?php if (empty($all_servers)): ?>
                    <p class="text-sm text-gray-400 py-4"><?= t('servers.empty_state') ?></p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Script : tags + test connectivité -->
        <script>
        async function addTag(machineId, tag) {
            tag = tag.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
            if (!tag) return;
            try {
                const r = await fetch('/adm/includes/server_actions.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: 'add_tag', machine_id: machineId, tag: tag})
                });
                const d = await r.json();
                if (d.success) { toast(__('servers.tag_added', {tag: tag}), 'success', 2000); location.reload(); }
                else toast(d.message, 'error');
            } catch(e) { toast(__('servers.error_network'), 'error'); }
        }

        async function removeTag(machineId, tag) {
            try {
                const r = await fetch('/adm/includes/server_actions.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: 'remove_tag', machine_id: machineId, tag: tag})
                });
                const d = await r.json();
                if (d.success) { toast(__('servers.tag_removed'), 'success', 2000); location.reload(); }
                else toast(d.message, 'error');
            } catch(e) { toast(__('servers.error_network'), 'error'); }
        }

        async function testServerConnection(id, ip, port) {
            const statusEl = document.getElementById('server-status-' + id);
            if (statusEl) statusEl.textContent = __('servers.test_in_progress');
            try {
                const r = await fetch(window.API_URL + '/server_status', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip, port: parseInt(port)})
                });
                const d = await r.json();
                if (d.success && d.status === 'online') {
                    if (statusEl) { statusEl.textContent = 'ONLINE'; statusEl.className = 'ml-auto text-xs text-green-500 font-semibold'; }
                    toast(__('servers.test_connected', {ip: ip}), 'success');
                } else {
                    if (statusEl) { statusEl.textContent = 'OFFLINE'; statusEl.className = 'ml-auto text-xs text-red-500 font-semibold'; }
                    toast(__('servers.test_unreachable', {ip: ip}), 'error');
                }
            } catch(e) {
                if (statusEl) statusEl.textContent = __('servers.error_generic');
                toast(__('servers.test_error', {message: e.message}), 'error');
            }
        }

        async function addNote(machineId, content) {
            content = (content || '').trim();
            if (!content) return;
            try {
                const r = await fetch('/adm/includes/server_actions.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: 'add_note', machine_id: machineId, content: content})
                });
                const d = await r.json();
                if (d.success) { toast(__('servers.note_added'), 'success'); setTimeout(() => location.reload(), 500); }
                else toast(d.message || __('servers.error_generic'), 'error');
            } catch(e) { toast(__('servers.error_network'), 'error'); }
        }

        async function deleteNote(noteId, machineId) {
            if (!confirm(__('servers.confirm_delete_note'))) return;
            try {
                const r = await fetch('/adm/includes/server_actions.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({action: 'delete_note', note_id: noteId})
                });
                const d = await r.json();
                if (d.success) { toast(__('servers.note_deleted'), 'success'); setTimeout(() => location.reload(), 500); }
                else toast(d.message || __('servers.error_generic'), 'error');
            } catch(e) { toast(__('servers.error_network'), 'error'); }
        }

        async function setLifecycle(machineId, status) {
            const labels = {retiring: __('servers.lifecycle_confirm_retire'), archived: __('servers.lifecycle_confirm_archive'), active: __('servers.lifecycle_confirm_reactivate')};
            if (!confirm(__('servers.lifecycle_confirm', {action: labels[status] || status}))) return;
            try {
                const r = await fetch(window.API_URL + '/server_lifecycle', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({machine_id: machineId, lifecycle_status: status})
                });
                const d = await r.json();
                if (d.success) {
                    toast(__('servers.lifecycle_updated'), 'success');
                    setTimeout(() => location.reload(), 800);
                } else {
                    toast(d.message || __('servers.error_generic'), 'error');
                }
            } catch(e) {
                toast(__('servers.error_network'), 'error');
            }
        }
        </script>

        <!-- Script JS pour la gestion AJAX -->
        <script>
        /*
        // Variables d'état global
        let currentPage = <?= $currentPage ?>;
        let currentSort = '<?= $sortColumn ?>';
        let currentDir = '<?= $sortDirection === 'ASC' ? 'asc' : 'desc' ?>';
        let currentSearch = '<?= htmlspecialchars($searchQuery) ?>';
        let currentEnvironment = '<?= htmlspecialchars($filterEnvironment) ?>';
        let currentNetwork = '<?= htmlspecialchars($filterNetwork) ?>';
        let currentCriticality = '<?= htmlspecialchars($filterCriticality) ?>';

        // Fonction pour afficher une notification
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.className = `mb-4 p-4 ${type === 'success' ? 'bg-green-100 dark:bg-green-700 border-green-400 dark:border-green-600 text-green-700 dark:text-green-100' : 'bg-red-100 dark:bg-red-700 border-red-400 dark:border-red-600 text-red-700 dark:text-red-100'} border rounded`;
            notification.textContent = message;
            notification.classList.remove('hidden');
            
            // Faire défiler jusqu'au message
            window.scrollTo({ top: 0, behavior: 'smooth' });
            
            // Masquer le message après 5 secondes
            setTimeout(() => {
                notification.classList.add('hidden');
            }, 5000);
        }

        // Fonction pour charger le tableau des serveurs
        function loadServersTable() {
            // Construire l'URL avec tous les paramètres
            const params = new URLSearchParams();
            params.append('page', currentPage);
            params.append('sort', currentSort);
            params.append('dir', currentDir === 'asc' ? 'asc' : 'desc');
            
            if (currentSearch) params.append('search', currentSearch);
            if (currentEnvironment) params.append('environment', currentEnvironment);
            if (currentNetwork) params.append('network', currentNetwork);
            if (currentCriticality) params.append('criticality', currentCriticality);
            
            // Mettre à jour l'URL du navigateur
            const newUrl = window.location.pathname + '?' + params.toString();
            window.history.pushState({ path: newUrl }, '', newUrl);
            
            // Afficher un indicateur de chargement
            document.getElementById('servers-table-container').innerHTML = 
                '<div class="flex justify-center py-8"><div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div></div>';
            
            // Effectuer la requête AJAX
            fetch('includes/manage_servers_table.php?' + params.toString())
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Erreur réseau: ' + response.status);
                    }
                    return response.text();
                })
                .then(html => {
                    document.getElementById('servers-table-container').innerHTML = html;
                    attachTableEventHandlers();
                })
                .catch(error => {
                    console.error('Erreur de chargement:', error);
                    document.getElementById('servers-table-container').innerHTML = 
                        `<div class="bg-red-100 dark:bg-red-700 border border-red-400 dark:border-red-600 text-red-700 dark:text-red-100 px-4 py-3 rounded mb-4">
                            Erreur de chargement: ${escHtml(error.message)}
                        </div>`;
                });
        }

        // Fonction pour attacher les gestionnaires d'événements au tableau
        function attachTableEventHandlers() {
            // Gestion de la pagination
            document.querySelectorAll('.pagination-link').forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    currentPage = parseInt(this.getAttribute('data-page'));
                    loadServersTable();
                });
            });
            
            // Gestion du tri
            document.querySelectorAll('.sort-link').forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const column = this.getAttribute('data-column');
                    
                    // Inverser la direction si on clique sur la même colonne
                    if (column === currentSort) {
                        currentDir = currentDir === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSort = column;
                        currentDir = 'asc';
                    }
                    
                    loadServersTable();
                });
            });
            
            // Gestion des boutons de modification
            document.querySelectorAll('.update-server-btn').forEach(button => {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    const serverId = this.getAttribute('data-server-id');
                    const form = document.querySelector(`.server-form[data-server-id="${serverId}"]`);
                    
                    if (form) {
                        const formData = new FormData(form);
                        formData.append('action', 'update_server');
                        formData.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token']) ?>');
                        
                        fetch('server_actions.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                showNotification(data.message, 'success');
                                loadServersTable(); // Recharger pour actualiser les données
                            } else {
                                showNotification(data.message, 'error');
                            }
                        })
                        .catch(error => {
                            console.error('Erreur:', error);
                            showNotification('Une erreur est survenue lors de la modification.', 'error');
                        });
                    }
                });
            });
            
            // Gestion des boutons de suppression
            document.querySelectorAll('.delete-server-btn').forEach(button => {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    const serverId = this.getAttribute('data-server-id');
                    
                    if (confirm('Supprimer ce serveur ? Cette action est irreversible.')) {
                        const formData = new FormData();
                        formData.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token']) ?>');
                        formData.append('action', 'delete_server');
                        formData.append('server_id', serverId);
                        
                        fetch('server_actions.php', {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                showNotification(data.message, 'success');
                                loadServersTable(); // Recharger pour actualiser les données
                            } else {
                                showNotification(data.message, 'error');
                            }
                        })
                        .catch(error => {
                            console.error('Erreur:', error);
                            showNotification('Une erreur est survenue lors de la suppression.', 'error');
                        });
                    }
                });
            });
        }

        // Gestion du formulaire d'ajout de serveur
        document.getElementById('add-server-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            
            fetch('server_actions.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(data.message, 'success');
                    // Vider le formulaire
                    this.reset();
                    // Recharger la table
                    loadServersTable();
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Erreur:', error);
                showNotification('Une erreur est survenue lors de l\'ajout du serveur.', 'error');
            });
        });

        // Gestion du formulaire de filtrage
        document.getElementById('filter-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            currentSearch = document.getElementById('search').value;
            currentEnvironment = document.getElementById('filter-environment').value;
            currentNetwork = document.getElementById('filter-network').value;
            currentCriticality = document.getElementById('filter-criticality').value;
            currentPage = 1; // Retour à la première page lors d'un nouveau filtrage
            
            loadServersTable();
        });

        // Gestion du bouton de réinitialisation des filtres
        document.getElementById('reset-filters').addEventListener('click', function(e) {
            e.preventDefault();
            
            document.getElementById('search').value = '';
            document.getElementById('filter-environment').value = '';
            document.getElementById('filter-network').value = '';
            document.getElementById('filter-criticality').value = '';
            
            currentSearch = '';
            currentEnvironment = '';
            currentNetwork = '';
            currentCriticality = '';
            currentPage = 1;
            currentSort = 'name';
            currentDir = 'asc';
            
            loadServersTable();
        });

        // Masquer les messages après un délai
        document.addEventListener('DOMContentLoaded', function() {
            // Attacher les gestionnaires aux éléments du tableau
            attachTableEventHandlers();
            
            // Masquer les messages de succès/erreur après 5 secondes
            const messages = document.querySelectorAll('#success-message, #error-message');
            setTimeout(() => {
                messages.forEach(msg => {
                    msg.style.transition = 'opacity 0.5s';
                    msg.style.opacity = '0';
                    setTimeout(() => msg.remove(), 500);
                });
            }, 5000);
            
            // Gérer le bouton retour du navigateur
            window.addEventListener('popstate', function(event) {
                // Récupérer les paramètres de l'URL
                const urlParams = new URLSearchParams(window.location.search);
                currentPage = urlParams.has('page') ? parseInt(urlParams.get('page')) : 1;
                currentSort = urlParams.has('sort') ? urlParams.get('sort') : 'name';
                currentDir = urlParams.has('dir') && urlParams.get('dir') === 'desc' ? 'desc' : 'asc';
                currentSearch = urlParams.has('search') ? urlParams.get('search') : '';
                currentEnvironment = urlParams.has('environment') ? urlParams.get('environment') : '';
                currentNetwork = urlParams.has('network') ? urlParams.get('network') : '';
                currentCriticality = urlParams.has('criticality') ? urlParams.get('criticality') : '';
                
                // Mettre à jour les champs du formulaire
                document.getElementById('search').value = currentSearch;
                document.getElementById('filter-environment').value = currentEnvironment;
                document.getElementById('filter-network').value = currentNetwork;
                document.getElementById('filter-criticality').value = currentCriticality;
                
                // Recharger le tableau
                loadServersTable();
            });
        });
        */

        // Masquer les messages après un délai
        document.addEventListener('DOMContentLoaded', function() {
            // Masquer les messages de succès/erreur après 5 secondes
            const messages = document.querySelectorAll('#success-message, #error-message');
            setTimeout(() => {
                messages.forEach(msg => {
                    msg.style.transition = 'opacity 0.5s';
                    msg.style.opacity = '0';
                    setTimeout(() => msg.remove(), 500);
                });
            }, 5000);
        });
        </script>

