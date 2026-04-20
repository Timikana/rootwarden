<?php
/**
 * adm/includes/manage_servers_table.php
 *
 * Composant HTML du tableau des serveurs, conçu pour être chargé via AJAX
 * ou inclus directement dans admin_page.php.
 *
 * Fonctionnalités :
 *   - Pagination côté serveur (5 éléments par page, paramètre GET 'page')
 *   - Filtrage par recherche textuelle (name, ip, user), environnement, réseau, criticité
 *   - Tri par colonne (name, ip, port, user, environment, criticality, network_type, online_status)
 *   - Formulaires inline d'édition et de suppression par serveur (POST vers manage_servers_fonctionnel.php)
 *
 * Paramètres GET acceptés :
 *   page, search, environment, network, criticality, sort, dir
 *
 * @package RootWarden\Admin
 */
// manage_servers_table.php - Composant pour afficher le tableau des serveurs (utilisé avec AJAX)

// Si ce fichier est appelé directement, inclure les dépendances nécessaires
if (!function_exists('checkAuth')) {
    require_once __DIR__ . '/../../auth/functions.php';
    require_once __DIR__ . '/../../auth/verify.php';
    require_once __DIR__ . '/../../db.php';
    require_once __DIR__ . '/crypto.php';
    
    // Autorise les utilisateurs ayant le rôle admin (2) ou superadmin (3)
    checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

// Paramètres de pagination
$itemsPerPage = 5; // Nombre d'éléments par page
$currentPage = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$offset = ($currentPage - 1) * $itemsPerPage;

// Paramètres de filtrage
$searchQuery = isset($_GET['search']) ? trim($_GET['search']) : '';
$filterEnvironment = isset($_GET['environment']) ? $_GET['environment'] : '';
$filterNetwork = isset($_GET['network']) ? $_GET['network'] : '';
$filterCriticality = isset($_GET['criticality']) ? $_GET['criticality'] : '';

// Paramètres de tri
$sortColumn = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$sortDirection = isset($_GET['dir']) && $_GET['dir'] === 'desc' ? 'DESC' : 'ASC';

// Colonnes autorisées pour le tri
$allowedColumns = ['name', 'ip', 'port', 'user', 'environment', 'criticality', 'network_type', 'online_status'];
if (!in_array($sortColumn, $allowedColumns)) {
    $sortColumn = 'name';
}

// Construction de la requête SQL avec filtres
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

$sql .= " ORDER BY `$sortColumn` $sortDirection LIMIT " . (int)$offset . ", " . (int)$itemsPerPage . "";

// Récupération du nombre total de serveurs
$countStmt = $pdo->prepare($countSql);
$countStmt->execute($params);
$totalItems = $countStmt->fetchColumn();
$totalPages = ceil($totalItems / $itemsPerPage);

// Récupération des serveurs avec pagination et filtres
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$all_servers = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!-- Information sur le nombre d'éléments -->
<div class="mb-4 text-sm text-gray-500 dark:text-gray-400">
    <?php if ($totalItems > 0): ?>
        Affichage de <?= min($offset + 1, $totalItems) ?>-<?= min($offset + $itemsPerPage, $totalItems) ?> sur <?= $totalItems ?> serveur(s)
    <?php else: ?>
        Aucun serveur trouvé
    <?php endif; ?>
</div>

<!-- Tableau des serveurs avec formulaire de mise à jour -->
<div class="overflow-x-auto">
    <table class="min-w-full bg-white dark:bg-gray-800 shadow-md rounded-lg">
        <thead>
            <tr class="bg-blue-800 dark:bg-blue-700 text-white uppercase text-sm leading-normal">
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="name">
                        Nom
                        <span class="ml-1">
                            <?php if ($sortColumn === 'name'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="ip">
                        IP
                        <span class="ml-1">
                            <?php if ($sortColumn === 'ip'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="port">
                        Port
                        <span class="ml-1">
                            <?php if ($sortColumn === 'port'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="user">
                        Utilisateur
                        <span class="ml-1">
                            <?php if ($sortColumn === 'user'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">Mot de Passe</th>
                <th class="py-3 px-4 text-left">Mot de Passe Root</th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="environment">
                        Environnement
                        <span class="ml-1">
                            <?php if ($sortColumn === 'environment'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="criticality">
                        Criticité
                        <span class="ml-1">
                            <?php if ($sortColumn === 'criticality'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="network_type">
                        Réseau
                        <span class="ml-1">
                            <?php if ($sortColumn === 'network_type'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-left">
                    <a href="#" class="sort-link flex items-center text-white" data-column="online_status">
                        Statut en Ligne
                        <span class="ml-1">
                            <?php if ($sortColumn === 'online_status'): ?>
                                <?= ($sortDirection === 'ASC') ? '↑' : '↓' ?>
                            <?php else: ?>
                                <span class="text-gray-300">⇕</span>
                            <?php endif; ?>
                        </span>
                    </a>
                </th>
                <th class="py-3 px-4 text-center">Actions</th>
            </tr>
        </thead>
        <tbody class="text-gray-600 dark:text-gray-300 text-sm font-light">
            <?php foreach ($all_servers as $server): ?>
                <tr class="border-b dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-700">
                    <form class="server-form" method="POST">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="server_id" value="<?= htmlspecialchars($server['id']) ?>">
                        
                        <!-- Nom -->
                        <td class="py-3 px-4">
                            <input type="text" name="name" value="<?= htmlspecialchars($server['name']) ?>" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500" maxlength="255">
                        </td>
                        <!-- IP -->
                        <td class="py-3 px-4">
                            <input type="text" name="ip" value="<?= htmlspecialchars($server['ip']) ?>" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </td>
                        <!-- Port -->
                        <td class="py-3 px-4">
                            <input type="number" name="port" value="<?= htmlspecialchars($server['port']) ?>" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500" min="1" max="65535">
                        </td>
                        <!-- Utilisateur -->
                        <td class="py-3 px-4">
                            <input type="text" name="user" value="<?= htmlspecialchars($server['user']) ?>" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500" maxlength="255">
                        </td>
                        <!-- Mot de Passe -->
                        <td class="py-3 px-4">
                            <input type="password" name="password" placeholder="Laisser vide pour ne pas modifier" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </td>
                        <!-- Mot de Passe Root -->
                        <td class="py-3 px-4">
                            <input type="password" name="root_password" placeholder="Laisser vide pour ne pas modifier" class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </td>
                        <!-- Environnement -->
                        <td class="py-3 px-4">
                            <select name="environment" required class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="PROD" <?= $server['environment'] === 'PROD' ? 'selected' : '' ?>>PROD</option>
                                <option value="DEV" <?= $server['environment'] === 'DEV' ? 'selected' : '' ?>>DEV</option>
                                <option value="TEST" <?= $server['environment'] === 'TEST' ? 'selected' : '' ?>>TEST</option>
                                <option value="OTHER" <?= $server['environment'] === 'OTHER' ? 'selected' : '' ?>>AUTRES</option>
                            </select>
                        </td>
                        <!-- Criticité -->
                        <td class="py-3 px-4">
                            <select name="criticality" required class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="CRITIQUE" <?= $server['criticality'] === 'CRITIQUE' ? 'selected' : '' ?>>CRITIQUE</option>
                                <option value="NON CRITIQUE" <?= $server['criticality'] === 'NON CRITIQUE' ? 'selected' : '' ?>>NON CRITIQUE</option>
                            </select>
                        </td>
                        <!-- Réseau -->
                        <td class="py-3 px-4">
                            <select name="network_type" required class="w-full px-3 py-2 border dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="INTERNE" <?= $server['network_type'] === 'INTERNE' ? 'selected' : '' ?>>INTERNE</option>
                                <option value="EXTERNE" <?= $server['network_type'] === 'EXTERNE' ? 'selected' : '' ?>>EXTERNE</option>
                            </select>
                        </td>
                        <!-- Statut en Ligne -->
                        <td class="py-3 px-4">
                            <span class="
                                <?= 
                                    strtolower($server['online_status']) === 'online' ? 'text-green-500' : 
                                    (strtolower($server['online_status']) === 'offline' ? 'text-red-500' : 'text-yellow-500') 
                                ?>">
                                <?= htmlspecialchars($server['online_status'] ?: 'Unknown') ?>
                            </span>
                        </td>
                        <!-- Actions -->
                        <td class="py-3 px-4 text-center space-x-2">
                            <button type="submit" name="update_server" class="bg-green-500 dark:bg-green-600 hover:bg-green-600 dark:hover:bg-green-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-300">
                                Modifier
                            </button>
                            <button type="submit" name="delete_server" class="bg-red-500 dark:bg-red-600 hover:bg-red-600 dark:hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg transition duration-300" onclick="return confirm('Êtes-vous sûr de vouloir supprimer ce serveur ?');">
                                Supprimer
                            </button>
                        </td>
                    </form>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<!-- Pagination -->
<?php if ($totalPages > 1): ?>
    <div class="mt-6 flex justify-center">
        <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
            <!-- Bouton Précédent -->
            <?php if ($currentPage > 1): ?>
                <a href="#" class="pagination-link relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600" data-page="<?= $currentPage - 1 ?>">
                    <span class="sr-only">Précédent</span>
                    &laquo;
                </a>
            <?php else: ?>
                <span class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-800 text-sm font-medium text-gray-400 dark:text-gray-500 cursor-not-allowed">
                    <span class="sr-only">Précédent</span>
                    &laquo;
                </span>
            <?php endif; ?>
            
            <!-- Pages numérotées -->
            <?php 
            $startPage = max(1, min($currentPage - 2, $totalPages - 4));
            $endPage = min($totalPages, max(5, $currentPage + 2));
            
            for ($i = $startPage; $i <= $endPage; $i++): 
            ?>
                <?php if ($i == $currentPage): ?>
                    <span class="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 bg-blue-50 dark:bg-blue-800 text-sm font-medium text-blue-600 dark:text-blue-200">
                        <?= $i ?>
                    </span>
                <?php else: ?>
                    <a href="#" class="pagination-link relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600" data-page="<?= $i ?>">
                        <?= $i ?>
                    </a>
                <?php endif; ?>
            <?php endfor; ?>
            
            <!-- Bouton Suivant -->
            <?php if ($currentPage < $totalPages): ?>
                <a href="#" class="pagination-link relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600" data-page="<?= $currentPage + 1 ?>">
                    <span class="sr-only">Suivant</span>
                    &raquo;
                </a>
            <?php else: ?>
                <span class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-800 text-sm font-medium text-gray-400 dark:text-gray-500 cursor-not-allowed">
                    <span class="sr-only">Suivant</span>
                    &raquo;
                </span>
            <?php endif; ?>
        </nav>
    </div>
<?php endif; ?> 