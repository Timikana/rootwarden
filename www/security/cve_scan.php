<?php
/**
 * security/cve_scan.php — Interface de scan de vulnérabilités CVE
 *
 * Rôle :
 *   Affiche la liste des serveurs accessibles à l'utilisateur et permet de
 *   lancer un scan CVE par serveur (ou sur l'ensemble) via le backend Python.
 *   Les résultats sont streamés en JSON-lines (une ligne JSON par événement)
 *   et rendus en temps réel dans l'interface.
 *
 * Permissions :
 *   - superadmin (role_id = 3) : toujours autorisé
 *   - admin      (role_id = 2) : autorisé si can_scan_cve = 1
 *   - user       (role_id = 1) : autorisé si can_scan_cve = 1
 *   Le superadmin gère qui détient ce droit via Administration → Droits d'accès.
 *
 * Dépendances PHP :
 *   - auth/verify.php   : fonctions checkAuth() et gestion de session
 *   - auth/functions.php: utilitaires d'authentification
 *   - db.php            : connexion PDO ($pdo)
 *   - head.php / menu.php / footer.php : gabarits HTML communs
 *
 * APIs backend appelées (JavaScript côté client) :
 *   - GET  /cve_test_connection : vérifie la connexion à OpenCVE
 *   - GET  /cve_results?machine_id=X : récupère le dernier scan stocké
 *   - POST /cve_scan : lance un scan (streaming JSON-lines)
 *
 * Variables d'environnement utilisées :
 *   - CVE_MIN_CVSS : seuil CVSS par défaut (défaut : 7.0)
 *   - OPENCVE_URL  : URL de l'instance OpenCVE
 *   - API_URL      : URL de base du backend Python
 *   - APP_NAME     : nom de l'application affiché dans le titre
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../auth/functions.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) { session_start(); }

// Autorise tous les rôles (1 = user, 2 = admin, 3 = superadmin) à atteindre
// cette page ; le filtrage fin par permission can_scan_cve se fait ensuite.
checkAuth([1, 2, 3]);

// Lecture du rôle et de la permission can_scan_cve depuis la session
$role       = (int) ($_SESSION['role_id'] ?? 0);
$canScanCve = (bool) ($_SESSION['permissions']['can_scan_cve'] ?? 0);

// Bloque l'accès si l'utilisateur n'est pas superadmin ET n'a pas la permission CVE
if (!$canScanCve && $role < 3) {
    http_response_code(403);
    require_once __DIR__ . '/../head.php';
    echo '<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">';
    require_once __DIR__ . '/../menu.php';
    echo '<div class="max-w-md mx-auto mt-12">
            <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-xl p-8 text-center">
                <div class="text-5xl mb-4">🔒</div>
                <h1 class="text-2xl font-bold mb-2 text-red-700 dark:text-red-300">' . t('common.access_denied') . '</h1>
                <p class="text-red-600 dark:text-red-400">' . t('cve.no_permission') . '</p>
            </div>
          </div>';
    require_once __DIR__ . '/../footer.php';
    echo '</body></html>';
    exit();
}

// Récupération de la liste des serveurs accessibles à l'utilisateur courant :
// • admin (role_id >= 2) et superadmin : tous les serveurs de la table machines
// • user  (role_id = 1) : uniquement les serveurs assignés via user_machine_access
if ($role >= 2) {
    $stmt = $pdo->query(
        "SELECT id, name, ip, environment, criticality FROM machines WHERE (lifecycle_status IS NULL OR lifecycle_status != 'archived') ORDER BY name"
    );
} else {
    $stmt = $pdo->prepare(
        "SELECT m.id, m.name, m.ip, m.environment, m.criticality
         FROM machines m
         INNER JOIN user_machine_access uma ON uma.machine_id = m.id
         WHERE uma.user_id = ?
         ORDER BY m.name"
    );
    $stmt->execute([$_SESSION['user_id']]);
}
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Lecture des paramètres de configuration depuis les variables d'environnement
$default_min_cvss = getenv('CVE_MIN_CVSS') ?: '7.0';   // Seuil CVSS minimal (ex. 7.0 = HIGH+)
$opencve_url      = getenv('OPENCVE_URL')  ?: 'https://app.opencve.io'; // URL OpenCVE affichée en sous-titre
$api_url          = rtrim(getenv('API_URL') ?: '', '/'); // URL du backend Python (sans slash final)
$app_name         = getenv('APP_NAME')     ?: 'RootWarden'; // Nom affiché dans le <title>
$api_key          = getenv('API_KEY') ?: '';

// Test de connexion OpenCVE côté serveur (PHP → Python, pas de CORS)
$connOk = false;
$connMsg = 'Backend inaccessible';
$ch = curl_init("https://python:5000/cve_test_connection");
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER => ["X-API-KEY: $api_key"],
]);
$resp = curl_exec($ch);
if ($resp !== false) {
    $data = json_decode($resp, true);
    $connOk = $data['success'] ?? false;
    $connMsg = $connOk ? "Connecté ({$data['url']})" : ($data['message'] ?? 'Erreur');
}
curl_close($ch);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>Scan CVE — <?= htmlspecialchars($app_name) ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<div class="px-6 py-6">

    <!-- ── En-tête ───────────────────────────────────────────────────────── -->
    <div class="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
            <h1 class="text-2xl font-bold flex items-center gap-2">
                <?= t('cve.title') ?>
            </h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('cve.desc') ?></p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Via <span class="font-mono text-xs"><?= htmlspecialchars($opencve_url) ?></span>
                &nbsp;—&nbsp;
                <span id="conn-status" class="<?= $connOk ? 'text-green-600 dark:text-green-400' : 'text-red-500' ?> font-medium text-xs"><?= $connOk ? '✓' : '✗' ?> <?= htmlspecialchars($connMsg) ?></span>
            </p>
        </div>

        <!-- Contrôles globaux -->
        <div class="flex flex-wrap items-center gap-3">

            <!-- Seuil CVSS -->
            <div class="flex items-center gap-2">
                <label class="text-sm font-medium text-gray-600 dark:text-gray-300 whitespace-nowrap"
                       title="Score CVSS : echelle de severite des vulnerabilites de 0 (faible) a 10 (critique)">
                    <?= t('cve.cvss_threshold') ?>
                </label>
                <select id="global-min-cvss"
                        class="text-sm border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5
                               bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500">
                    <option value="0" <?= $default_min_cvss == '0' ? 'selected':'' ?>>
                        <?= t('cve.cvss_all') ?>
                    </option>
                    <option value="4" <?= ($default_min_cvss>='4'&&$default_min_cvss<'7') ? 'selected':'' ?>>
                        <?= t('cve.cvss_medium') ?>
                    </option>
                    <option value="7" <?= ($default_min_cvss>='7'&&$default_min_cvss<'9') ? 'selected':'' ?>>
                        <?= t('cve.cvss_high') ?>
                    </option>
                    <option value="9" <?= $default_min_cvss>='9' ? 'selected':'' ?>>
                        <?= t('cve.cvss_critical') ?>
                    </option>
                </select>
            </div>

            <?php if ($role >= 2 || count($machines) > 1): ?>
            <!-- Bouton scan global (visible si admin ou plusieurs serveurs autorisés) -->
            <button id="btn-scan-all"
                    onclick="scanAll()"
                    class="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                           text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
                <?= t('cve.btn_scan_all') ?> (<?= count($machines) ?>)
            </button>
            <?php endif; ?>
        </div>
    </div>

    <?php if (empty($machines)): ?>
    <div class="bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700
                rounded-xl p-6 text-center text-yellow-700 dark:text-yellow-300">
        <?= t('cve.no_servers') ?>
    </div>
    <?php else: ?>

    <!-- ── Barre de progression globale ──────────────────────────────────── -->
    <div id="global-progress" class="hidden mb-6">
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow p-4">
            <div class="flex justify-between text-sm text-gray-600 dark:text-gray-400 mb-2">
                <span id="global-progress-label"><?= t('cve.scan_in_progress') ?></span>
                <span id="global-progress-pct">0 %</span>
            </div>
            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div id="global-progress-bar"
                     class="bg-blue-500 h-2 rounded-full transition-all duration-300"
                     style="width:0%"></div>
            </div>
        </div>
    </div>

    <!-- ── Résumé global ─────────────────────────────────────────────────── -->
    <?php if (count($machines) > 1):
        $globalStmt = $pdo->query("
            SELECT
                COUNT(DISTINCT s.machine_id) as servers_scanned,
                SUM(s.cve_count) as total_cves,
                SUM(s.critical_count) as total_critical,
                SUM(s.high_count) as total_high,
                SUM(s.medium_count) as total_medium
            FROM cve_scans s
            INNER JOIN (SELECT machine_id, MAX(id) as last_id FROM cve_scans WHERE status='completed' GROUP BY machine_id) latest
            ON s.id = latest.last_id
        ");
        $global = $globalStmt->fetch(PDO::FETCH_ASSOC);
    ?>
    <?php if ($global && $global['total_cves'] > 0): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-4 flex flex-wrap items-center gap-4">
        <span class="text-sm font-semibold text-gray-700 dark:text-gray-300"><?= t('cve.fleet_summary') ?></span>
        <span class="text-xs text-gray-500"><?= $global['servers_scanned'] ?> <?= t('cve.servers_scanned') ?></span>
        <div class="flex gap-2">
            <?php if ($global['total_critical'] > 0): ?>
                <span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-600 text-white"><?= $global['total_critical'] ?> CRITICAL</span>
            <?php endif; ?>
            <?php if ($global['total_high'] > 0): ?>
                <span class="px-2 py-0.5 rounded-full text-xs font-bold bg-orange-500 text-white"><?= $global['total_high'] ?> HIGH</span>
            <?php endif; ?>
            <?php if ($global['total_medium'] > 0): ?>
                <span class="px-2 py-0.5 rounded-full text-xs font-bold bg-yellow-500 text-white"><?= $global['total_medium'] ?> MEDIUM</span>
            <?php endif; ?>
            <span class="text-xs text-gray-400"><?= $global['total_cves'] ?> <?= t('cve.total_cves') ?></span>
        </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>

    <!-- ── Scans planifies (admin+) ─────────────────────────────────────── -->
    <?php if ($role >= 2): ?>
    <details class="bg-white dark:bg-gray-800 rounded-xl shadow-sm mb-4">
        <summary class="px-5 py-3 cursor-pointer flex items-center justify-between text-sm font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/30">
            <span class="flex items-center gap-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <?= t('cve.scheduled_scans') ?>
            </span>
            <span id="schedule-count" class="text-xs text-gray-400"></span>
        </summary>
        <div class="px-5 pb-4">
            <div id="schedules-list" class="space-y-2 mb-3"></div>
            <div class="flex flex-wrap items-end gap-3 border-t border-gray-100 dark:border-gray-700 pt-3">
                <div>
                    <label class="text-xs text-gray-500"><?= t('cve.sched_name') ?></label>
                    <input id="sched-name" type="text" placeholder="Scan quotidien 03h" class="block w-44 text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="text-xs text-gray-500"><?= t('cve.sched_cron') ?></label>
                    <input id="sched-cron" type="text" value="0 3 * * *" placeholder="0 3 * * *" class="block w-32 text-sm font-mono border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="text-xs text-gray-500"><?= t('cve.sched_cvss_min') ?></label>
                    <select id="sched-cvss" class="block text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                        <option value="0"><?= t('cve.cvss_all') ?></option>
                        <option value="4"><?= t('cve.cvss_medium') ?></option>
                        <option value="7" selected><?= t('cve.cvss_high') ?></option>
                        <option value="9"><?= t('cve.cvss_critical') ?></option>
                    </select>
                </div>
                <div>
                    <label class="text-xs text-gray-500"><?= t('cve.sched_target') ?></label>
                    <select id="sched-target" class="block text-sm border border-gray-300 dark:border-gray-600 rounded px-2 py-1 bg-white dark:bg-gray-700">
                        <option value="all"><?= t('cve.sched_all_servers') ?></option>
                        <?php
                        $tags = $pdo->query("SELECT DISTINCT tag FROM machine_tags ORDER BY tag")->fetchAll(PDO::FETCH_COLUMN);
                        foreach ($tags as $tag): ?>
                        <option value="tag:<?= htmlspecialchars($tag) ?>">Tag: <?= htmlspecialchars($tag) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button onclick="addSchedule()" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded font-medium">
                    <?= t('cve.sched_add') ?>
                </button>
            </div>
            <p class="text-[10px] text-gray-400 mt-2">
                <?= t('cve.sched_cron_hint') ?>
            </p>
        </div>
    </details>
    <?php endif; ?>

    <!-- ── Cartes serveurs ────────────────────────────────────────────────── -->
    <div class="space-y-4" id="servers-container">
    <?php foreach ($machines as $m): ?>
        <?php
        $env_badge = match($m['environment']) {
            'PROD'  => 'bg-red-100 text-red-700 dark:bg-red-900/60 dark:text-red-300',
            'DEV'   => 'bg-green-100 text-green-700 dark:bg-green-900/60 dark:text-green-300',
            'TEST'  => 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/60 dark:text-yellow-300',
            default => 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
        };
        $crit_badge = $m['criticality'] === 'CRITIQUE'
            ? 'bg-red-600 text-white'
            : 'bg-gray-200 text-gray-600 dark:bg-gray-600 dark:text-gray-200';
        ?>
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden"
             id="server-card-<?= $m['id'] ?>">

            <!-- En-tête serveur -->
            <div class="flex flex-wrap items-center justify-between gap-3 px-5 py-4
                        border-b border-gray-100 dark:border-gray-700">
                <div class="flex items-center gap-3 min-w-0">
                    <div class="w-2.5 h-2.5 rounded-full bg-gray-300 flex-shrink-0"
                         id="status-dot-<?= $m['id'] ?>"></div>
                    <div class="min-w-0">
                        <span class="font-semibold truncate"><?= htmlspecialchars($m['name']) ?></span>
                        <span class="text-sm text-gray-400 ml-2 font-mono"><?= htmlspecialchars($m['ip']) ?></span>
                    </div>
                    <span class="text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0 <?= $env_badge ?>">
                        <?= htmlspecialchars($m['environment']) ?>
                    </span>
                    <span class="text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0 <?= $crit_badge ?>">
                        <?= htmlspecialchars($m['criticality']) ?>
                    </span>
                </div>

                <div class="flex items-center gap-3 flex-shrink-0">
                    <!-- Badges résumé -->
                    <div id="badges-<?= $m['id'] ?>" class="flex gap-1.5 text-xs font-semibold"></div>
                    <!-- Dernier scan -->
                    <span class="text-xs text-gray-400 hidden sm:inline"
                          id="last-scan-<?= $m['id'] ?>"></span>
                    <!-- Seuil par serveur -->
                    <select id="cvss-<?= $m['id'] ?>"
                            class="text-xs border border-gray-300 dark:border-gray-600 rounded px-1.5 py-1
                                   bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-200"
                            title="Seuil CVSS pour ce serveur">
                        <option value="0">0+</option>
                        <option value="4" <?= $default_min_cvss >= 4 && $default_min_cvss < 7 ? 'selected' : '' ?>>4+</option>
                        <option value="7" <?= $default_min_cvss >= 7 && $default_min_cvss < 9 ? 'selected' : '' ?>>7+</option>
                        <option value="9" <?= $default_min_cvss >= 9 ? 'selected' : '' ?>>9+</option>
                    </select>
                    <!-- Bouton scan -->
                    <button onclick="scanServer(<?= $m['id'] ?>)"
                            id="btn-<?= $m['id'] ?>"
                            class="flex items-center gap-1.5 bg-blue-50 hover:bg-blue-100
                                   dark:bg-blue-900/30 dark:hover:bg-blue-900/60
                                   text-blue-700 dark:text-blue-300 text-xs font-medium
                                   px-3 py-1.5 rounded-lg transition-colors
                                   border border-blue-200 dark:border-blue-700
                                   disabled:opacity-50 disabled:cursor-not-allowed">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                        <?= t('cve.btn_scan') ?>
                    </button>
                    <a href="/security/cve_export.php?machine_id=<?= $m['id'] ?>"
                       class="flex items-center gap-1 bg-gray-50 hover:bg-gray-100 dark:bg-gray-700 dark:hover:bg-gray-600
                              text-gray-600 dark:text-gray-300 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors
                              border border-gray-200 dark:border-gray-600" title="Exporter en CSV">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        CSV
                    </a>
                    <button onclick="compareCveScans(<?= $m['id'] ?>)"
                       class="flex items-center gap-1 bg-gray-50 hover:bg-gray-100 dark:bg-gray-700 dark:hover:bg-gray-600
                              text-gray-600 dark:text-gray-300 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors
                              border border-gray-200 dark:border-gray-600" title="Comparer avec le scan precedent">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>
                        </svg>
                        Diff
                    </button>
                </div>
            </div>

            <!-- Barre de progression (cachée par défaut) -->
            <div id="progress-<?= $m['id'] ?>" class="hidden px-5 py-2 bg-blue-50 dark:bg-blue-900/20">
                <div class="flex justify-between text-xs text-blue-600 dark:text-blue-300 mb-1">
                    <span id="progress-label-<?= $m['id'] ?>">Initialisation…</span>
                    <span id="progress-pct-<?= $m['id'] ?>">0 %</span>
                </div>
                <div class="w-full bg-blue-200 dark:bg-blue-800 rounded-full h-1.5">
                    <div id="progress-bar-<?= $m['id'] ?>"
                         class="bg-blue-500 h-1.5 rounded-full transition-all duration-200"
                         style="width:0%"></div>
                </div>
            </div>

            <!-- Résultats (collapsé par défaut, dépliable par clic sur le résumé) -->
            <div id="results-<?= $m['id'] ?>" class="hidden"></div>
            <div id="results-detail-<?= $m['id'] ?>" class="hidden"></div>
        </div>
    <?php endforeach; ?>
    </div>

    <?php endif; ?>
</div>

<script>
// Variables PHP injectees pour le JS externe
window._cveConfig = {
    machineIds: <?= json_encode(array_column($machines, 'id')) ?>,
    username: '<?= htmlspecialchars($_SESSION['username'] ?? 'admin') ?>'
};
</script>
<script src="/security/js/cveScan.js?v=<?= filemtime(__DIR__ . '/js/cveScan.js') ?>"></script>


<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
