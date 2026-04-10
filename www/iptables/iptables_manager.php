<?php
/**
 * iptables/iptables_manager.php — Interface de gestion des règles iptables
 *
 * Rôle :
 *   Permet au superadmin de visualiser, modifier, sauvegarder et restaurer
 *   les règles iptables (IPv4 et IPv6) pour chaque serveur.
 *   La page charge les règles actuelles depuis le serveur via le backend Python
 *   et propose un éditeur de fichiers rules.v4 / rules.v6.
 *   Les règles peuvent être stockées en base de données (table iptables_rules)
 *   pour une restauration ultérieure.
 *
 * Permissions :
 *   - superadmin (role_id = 3) uniquement — accès refusé à tous les autres rôles
 *
 * Dépendances PHP :
 *   - auth/verify.php : fonctions checkAuth() et gestion de session
 *   - db.php          : connexion PDO ($pdo)
 *   - head.php / menu.php / footer.php : gabarits HTML communs
 *
 * Actions POST gérées directement par ce fichier (appels AJAX internes) :
 *   - load_from_db  : retourne rules_v4 / rules_v6 stockées en BDD (JSON)
 *   - save_to_db    : remplace les règles BDD pour un serveur (DELETE + INSERT)
 *   - restore       : récupère les règles BDD et les applique via le backend Python
 *
 * APIs backend Python appelées (JavaScript côté client) :
 *   - POST /iptables         : récupère les règles actives + fichiers rules.v4/v6 du serveur
 *   - POST /iptables-apply   : applique les règles éditées sur le serveur
 *   - POST /iptables-restore : restaure les règles depuis la BDD vers le serveur
 *   - GET  /iptables-logs    : flux SSE des logs iptables en temps réel
 *   Tous ces appels requièrent le header X-API-KEY.
 *
 * Variables d'environnement utilisées :
 *   - API_URL : URL de base du backend Python
 *   - API_KEY : clé d'authentification inter-services
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Réservé au superadmin uniquement (role_id = 3)
checkAuth([1, 2, 3]);
checkPermission('can_manage_iptables');

// Récuperation des serveurs avec filtrage par acces utilisateur
$role = (int) ($_SESSION['role_id'] ?? 0);
if ($role >= 2) {
    $stmt = $pdo->query("SELECT id, name, ip, port FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'");
} else {
    $stmt = $pdo->prepare("SELECT m.id, m.name, m.ip, m.port FROM machines m INNER JOIN user_machine_access uma ON uma.machine_id = m.id WHERE uma.user_id = ? AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')");
    $stmt->execute([$_SESSION['user_id']]);
}
$servers = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Traitement des actions AJAX POST : load_from_db, save_to_db, restore
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action   = $_POST['action'];
    $serverId = $_POST['server_id'] ?? null;

    // Toute action nécessite un server_id valide
    if (!$serverId) {
        echo json_encode(['success' => false, 'message' => 'ID du serveur manquant.']);
        exit;
    }

    switch ($action) {
        case 'load_from_db':
            loadRulesFromDB($pdo, $serverId);
            break;
        case 'save_to_db':
            saveRulesToDB($pdo, $serverId);
            break;
        case 'restore':
            restoreRulesToServer($pdo, $serverId);
            break;
        default:
            echo json_encode(['success' => false, 'message' => 'Action inconnue.']);
            exit;
    }
}

/**
 * Charge les règles iptables stockées en base de données pour un serveur.
 * Retourne un JSON { success, rules_v4, rules_v6 } ou une erreur si absent.
 * Termine l'exécution avec exit après avoir émis la réponse JSON.
 *
 * @param PDO    $pdo      - Connexion PDO
 * @param int    $serverId - ID du serveur cible
 */
function loadRulesFromDB($pdo, $serverId) {
    $stmt = $pdo->prepare("SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = ?");
    $stmt->execute([$serverId]);
    $rules = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($rules) {
        echo json_encode([
            'success' => true,
            'rules_v4' => $rules['rules_v4'],
            'rules_v6' => $rules['rules_v6'],
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Aucune règle trouvée dans la base de données.',
        ]);
    }
    exit;
}

/**
 * Sauvegarde les règles iptables éditées dans la base de données.
 * Utilise un DELETE puis INSERT (remplacement complet) pour garantir
 * qu'il n'existe qu'une seule entrée par serveur.
 * Retourne un JSON { success, message }.
 *
 * @param PDO    $pdo      - Connexion PDO
 * @param int    $serverId - ID du serveur cible
 */
function saveRulesToDB($pdo, $serverId) {
    $rulesV4 = $_POST['rules_v4'] ?? '';
    $rulesV6 = $_POST['rules_v6'] ?? '';

    // Suppression de l'ancienne entrée avant remplacement (pas d'UPSERT)
    $deleteStmt = $pdo->prepare("DELETE FROM iptables_rules WHERE server_id = ?");
    $deleteStmt->execute([$serverId]);

    // Insertion des nouvelles règles
    $insertStmt = $pdo->prepare(
        "INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) 
        VALUES (?, ?, ?)"
    );
    $success = $insertStmt->execute([$serverId, $rulesV4, $rulesV6]);

    if ($success) {
        echo json_encode(['success' => true, 'message' => 'Règles sauvegardées avec succès.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Erreur lors de la sauvegarde des règles.']);
    }
    exit;
}

/**
 * Restaure les règles iptables depuis la BDD et les applique sur le serveur distant.
 * Récupère les credentials SSH du serveur puis appelle le backend Python via
 * file_get_contents() + stream_context_create() avec les headers X-API-KEY.
 * Retourne un JSON { success, message } reflétant la réponse du backend.
 *
 * @param PDO    $pdo      - Connexion PDO
 * @param int    $serverId - ID du serveur cible
 */
function restoreRulesToServer($pdo, $serverId) {
    $stmt = $pdo->prepare("SELECT ip, user, password, root_password FROM machines WHERE id = ?");
    $stmt->execute([$serverId]);
    $server = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$server) {
        echo json_encode(['success' => false, 'message' => 'Serveur introuvable.']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = ?");
    $stmt->execute([$serverId]);
    $rules = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$rules) {
        echo json_encode(['success' => false, 'message' => 'Aucune règle trouvée pour ce serveur.']);
        exit;
    }

    $data = [
        'server_ip' => $server['ip'],
        'server_port' => $server['port'],
        'ssh_user' => $server['user'],
        'ssh_password' => $server['password'],
        'root_password' => $server['root_password'],
        'rules_v4' => $rules['rules_v4'],
        'rules_v6' => $rules['rules_v6'],
    ];

    // Appel POST vers le backend Python pour appliquer les règles restaurées
    // Le header X-API-KEY authentifie la requête PHP→Python
    $apiUrl = rtrim(getenv('API_URL') ?: '', '/');
    $apiKey = getenv('API_KEY') ?: '';
    $url = $apiUrl . '/iptables-restore';
    $options = [
        'http' => [
            'header'  => "Content-type: application/json\r\nX-API-KEY: " . $apiKey . "\r\n",
            'method'  => 'POST',
            'content' => json_encode($data),
        ],
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE) {
        echo json_encode(['success' => false, 'message' => 'Erreur lors de l\'appel au backend Flask.']);
        exit;
    }

    $response = json_decode($result, true);
    if ($response['success']) {
        echo json_encode(['success' => true, 'message' => 'Règles restaurées et appliquées avec succès.']);
    } else {
        echo json_encode(['success' => false, 'message' => $response['message']]);
    }
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('iptables.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <!-- Menu -->
    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6">

        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('iptables.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('iptables.subtitle') ?></p>
                <p class="text-xs text-gray-400 mt-0.5"><?= t('iptables.desc') ?></p>
            </div>
        </div>

        <!-- Selection serveur + actions -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
                <div class="flex-1 w-full">
                    <label for="server" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"><?= t('iptables.server_target') ?></label>
                    <select id="server" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <option value=""><?= t('iptables.select_server') ?></option>
                        <?php foreach ($servers as $server): ?>
                            <option value="<?= htmlspecialchars(json_encode($server)) ?>">
                                <?= htmlspecialchars($server['name']) ?> (<?= htmlspecialchars($server['ip']) ?>:<?= htmlspecialchars($server['port']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="button" id="fetch-rules" onclick="fetchLogs()" title="Charger les regles iptables actives depuis le serveur selectionne" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg font-medium transition-colors text-sm whitespace-nowrap">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    <?= t('iptables.load_rules') ?>
                </button>
            </div>
            <!-- Actions secondaires -->
            <div class="flex flex-wrap gap-2 mt-4 pt-4 border-t border-gray-100 dark:border-gray-700">
                <button type="button" id="validate-rules" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors" title="<?= t('iptables.tip_validate') ?>"><?= t('iptables.btn_validate') ?></button>
                <button type="button" id="apply-rules" class="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors font-medium" title="<?= t('iptables.tip_apply') ?>"><?= t('iptables.btn_apply') ?></button>
                <button type="button" id="save-rules" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors" title="<?= t('iptables.tip_save') ?>"><?= t('iptables.btn_save') ?></button>
                <button type="button" id="load-rules" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors" title="<?= t('iptables.tip_load_db') ?>"><?= t('iptables.btn_load_db') ?></button>
                <button type="button" id="restore-rules" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors" title="<?= t('iptables.tip_restore') ?>"><?= t('iptables.btn_restore') ?></button>
            </div>
        </div>

        <!-- Logs -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden mb-6">
            <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('iptables.logs') ?></h2>
            </div>
            <div id="iptables-logs" class="bg-gray-900 text-green-400 p-4 font-mono text-xs leading-relaxed h-48 overflow-y-auto whitespace-pre-line">
                <span class="text-gray-500"><?= t('iptables.logs_placeholder') ?></span>
            </div>
        </div>

        <!-- Regles (hidden until loaded) -->
        <div id="rules-container" class="hidden space-y-6">
            <!-- Regles actuelles -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h3 class="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase" title="<?= t('iptables.tip_current_v4') ?>"><?= t('iptables.current_rules_v4') ?></h3>
                    </div>
                    <pre id="current-rules-v4" class="p-3 bg-gray-900 text-green-400 font-mono text-xs h-64 overflow-auto"></pre>
                </div>
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h3 class="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase" title="<?= t('iptables.tip_current_v6') ?>"><?= t('iptables.current_rules_v6') ?></h3>
                    </div>
                    <pre id="current-rules-v6" class="p-3 bg-gray-900 text-green-400 font-mono text-xs h-64 overflow-auto"></pre>
                </div>
            </div>
            <!-- Templates iptables -->
            <div class="flex items-center gap-3 mb-4">
                <span class="text-xs text-gray-500"><?= t('iptables.template_label') ?></span>
                <select onchange="if(this.value){loadTemplate(this.value);this.value='';}" class="text-xs border border-gray-300 dark:border-gray-600 rounded-lg px-2 py-1.5 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300">
                    <option value=""><?= t('iptables.template_select') ?></option>
                    <option value="web"><?= t('iptables.tpl_web') ?></option>
                    <option value="db"><?= t('iptables.tpl_db') ?></option>
                    <option value="ssh_only"><?= t('iptables.tpl_ssh_only') ?></option>
                    <option value="deny_all"><?= t('iptables.tpl_deny_all') ?></option>
                    <option value="docker"><?= t('iptables.tpl_docker') ?></option>
                </select>
            </div>
            <!-- Editeurs -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-blue-50 dark:bg-blue-900/30 border-b border-blue-200 dark:border-blue-800">
                        <h3 class="text-xs font-semibold text-blue-700 dark:text-blue-400 uppercase" title="<?= t('iptables.tip_edit_v4') ?>"><?= t('iptables.edit_rules_v4') ?></h3>
                    </div>
                    <textarea id="file-rules-v4" class="p-3 bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-200 font-mono text-xs h-64 w-full border-0 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"></textarea>
                </div>
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-blue-50 dark:bg-blue-900/30 border-b border-blue-200 dark:border-blue-800">
                        <h3 class="text-xs font-semibold text-blue-700 dark:text-blue-400 uppercase" title="<?= t('iptables.tip_edit_v6') ?>"><?= t('iptables.edit_rules_v6') ?></h3>
                    </div>
                    <textarea id="file-rules-v6" class="p-3 bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-200 font-mono text-xs h-64 w-full border-0 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"></textarea>
                </div>
            </div>
            <!-- BDD -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h3 class="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase" title="<?= t('iptables.tip_db_v4') ?>"><?= t('iptables.db_rules_v4') ?></h3>
                    </div>
                    <textarea id="bdd-rules-v4" class="p-3 bg-gray-100 dark:bg-gray-900 text-gray-600 dark:text-gray-400 font-mono text-xs h-48 w-full border-0 resize-none" readonly></textarea>
                </div>
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-4 py-2 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                        <h3 class="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase" title="<?= t('iptables.tip_db_v6') ?>"><?= t('iptables.db_rules_v6') ?></h3>
                    </div>
                    <textarea id="bdd-rules-v6" class="p-3 bg-gray-100 dark:bg-gray-900 text-gray-600 dark:text-gray-400 font-mono text-xs h-48 w-full border-0 resize-none" readonly></textarea>
                </div>
            </div>

            <!-- Historique des modifications -->
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600 flex items-center justify-between">
                    <h3 class="text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase"><?= t('iptables.history_title') ?></h3>
                    <button onclick="loadHistory()" class="text-xs text-blue-500 hover:text-blue-700"><?= t('iptables.btn_refresh') ?></button>
                </div>
                <div id="iptables-history" class="p-3 max-h-64 overflow-y-auto">
                    <p class="text-xs text-gray-400"><?= t('iptables.history_placeholder') ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="/iptables/js/iptablesManager.js?v=<?= filemtime(__DIR__ . '/js/iptablesManager.js') ?>"></script>
</body>
<?php require_once __DIR__ . '/../footer.php'; ?>
</html>
