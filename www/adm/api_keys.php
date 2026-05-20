<?php
/**
 * api_keys.php - Gestion des cles API (segmentation + scope + rotation).
 *
 * Acces : superadmin avec permission can_manage_api_keys.
 * Actions :
 *   - Lister les cles (prefix, nom, scope, last_used, revoked)
 *   - Creer une cle : genere un secret aleatoire, stocke le SHA256,
 *     affiche la cle UNE SEULE FOIS au createur
 *   - Revoquer une cle (revoked_at = NOW)
 *   - Rotater une cle = revoquer l'ancienne + creer une nouvelle avec meme nom + scope
 */

require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/includes/audit_log.php';

checkAuth([ROLE_SUPERADMIN]);
checkPermission('can_manage_api_keys');

$newKey = null;   // cle affichee une seule fois apres creation
$newKeyConsumerHint = null;  // indice consommateur rappele a cote du newKey
$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCsrfToken();
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $name = trim($_POST['name'] ?? '');
        $scopeRaw = trim($_POST['scope'] ?? '');  // une regex par ligne
        $consumerHint = trim($_POST['consumer_hint'] ?? '');
        if ($consumerHint === '') $consumerHint = null;
        elseif (strlen($consumerHint) > 200) $consumerHint = substr($consumerHint, 0, 200);

        if (!preg_match('/^[a-zA-Z0-9_-]{3,100}$/', $name)) {
            $error = 'Nom invalide (^[a-zA-Z0-9_-]{3,100}$)';
        } else {
            // Parser le scope (1 regex par ligne)
            $scope = null;
            if ($scopeRaw !== '') {
                $patterns = array_filter(array_map('trim', explode("\n", $scopeRaw)));
                // Validate each regex
                foreach ($patterns as $p) {
                    if (@preg_match('#' . str_replace('#', '\\#', $p) . '#', '') === false) {
                        $error = "Regex scope invalide : $p";
                        break;
                    }
                }
                if (!$error) $scope = json_encode(array_values($patterns));
            }

            if (!$error) {
                // Genere une cle : prefix + 40 caracteres random
                $secret = bin2hex(random_bytes(24));  // 48 chars
                $prefix = 'rw_live_' . substr($secret, 0, 6);
                $fullKey = $prefix . '_' . substr($secret, 6);
                $hash = hash('sha256', $fullKey);

                try {
                    $stmt = $pdo->prepare(
                        "INSERT INTO api_keys (name, key_prefix, key_hash, scope_json, consumer_hint, created_by) "
                        . "VALUES (?, ?, ?, ?, ?, ?)"
                    );
                    $stmt->execute([$name, $prefix, $hash, $scope, $consumerHint, (int)$_SESSION['user_id']]);
                    $newKey = $fullKey;
                    $newKeyConsumerHint = $consumerHint;
                    $success = "Cle API '$name' creee. Copiez-la maintenant, elle ne sera plus affichee.";
                    audit_log($pdo, "Creation cle API '$name' prefix=$prefix scope=" . ($scope ?: 'ALL'));

                    // Auto-register la cle legacy Config.API_KEY si pas deja presente.
                    // Cas critique : premiere cle creee par un admin - sans ca le proxy PHP
                    // (qui envoie toujours getenv('API_KEY')) se casse silencieusement parce
                    // que le fallback legacy n'est actif que quand la table est vide (v1.14.4).
                    // On insere une entree `proxy-internal-legacy` scope=NULL taggee
                    // auto_generated=1 - l'admin la voit dans la liste et peut la revoquer
                    // apres avoir rotate srv-docker.env:API_KEY avec une vraie cle scopee.
                    $legacyRaw = getenv('API_KEY') ?: '';
                    if ($legacyRaw !== '') {
                        $legacyHash   = hash('sha256', $legacyRaw);
                        $legacyPrefix = 'legacy_' . substr(hash('sha256', 'proxy-internal-legacy'), 0, 6);
                        $pdo->prepare(
                            "INSERT IGNORE INTO api_keys "
                            . "(name, key_prefix, key_hash, scope_json, created_by, auto_generated) "
                            . "VALUES ('proxy-internal-legacy', ?, ?, NULL, ?, 1)"
                        )->execute([$legacyPrefix, $legacyHash, (int)$_SESSION['user_id']]);
                    }
                } catch (\PDOException $e) {
                    $error = $e->getCode() === '23000' ? 'Une cle avec ce nom existe deja.' : 'Erreur creation';
                    error_log('api_keys create: ' . $e->getMessage());
                }
            }
        }
    } elseif ($action === 'renew') {
        // Renouvelle une cle revoquee : meme scope, nom suffixe -rYYYYMMDD-HHMMSS pour eviter collision UNIQUE.
        // Refuse de renouveler une cle encore active (pour eviter la creation accidentelle de doublons).
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare("SELECT name, scope_json, revoked_at, auto_generated, consumer_hint FROM api_keys WHERE id = ?");
            $stmt->execute([$id]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                $error = "Cle introuvable.";
            } elseif (empty($row['revoked_at'])) {
                $error = "Cette cle est encore active. Revoquez-la d'abord ou creez une nouvelle cle.";
            } elseif (!empty($row['auto_generated'])) {
                $error = "Les cles auto-generees ne se renouvellent pas via ce bouton (regenerees automatiquement).";
            } else {
                // Strip d'un eventuel suffixe -rXXXXXXXX-XXXXXX precedent pour garder un nom de base lisible
                $baseName = preg_replace('/-r\d{8}-\d{6}$/', '', $row['name']);
                $newName = $baseName . '-r' . date('Ymd-His');
                // Securite : doit toujours matcher le pattern accepte
                if (!preg_match('/^[a-zA-Z0-9_-]{3,100}$/', $newName)) {
                    $error = "Impossible de generer un nom valide pour le renouvellement.";
                } else {
                    $secret = bin2hex(random_bytes(24));
                    $prefix = 'rw_live_' . substr($secret, 0, 6);
                    $fullKey = $prefix . '_' . substr($secret, 6);
                    $hash = hash('sha256', $fullKey);
                    try {
                        $pdo->prepare(
                            "INSERT INTO api_keys (name, key_prefix, key_hash, scope_json, consumer_hint, created_by) VALUES (?, ?, ?, ?, ?, ?)"
                        )->execute([$newName, $prefix, $hash, $row['scope_json'], $row['consumer_hint'] ?? null, (int)$_SESSION['user_id']]);
                        $newKey = $fullKey;
                        $newKeyConsumerHint = $row['consumer_hint'] ?? null;
                        $success = "Cle '{$row['name']}' renouvelee en '$newName'. Copiez la nouvelle valeur, elle ne sera plus affichee.";
                        audit_log($pdo, "Renouvellement cle API '{$row['name']}' -> '$newName' prefix=$prefix");
                    } catch (\PDOException $e) {
                        $error = $e->getCode() === '23000' ? 'Une cle avec ce nom de renouvellement existe deja, reessayez.' : 'Erreur renouvellement';
                        error_log('api_keys renew: ' . $e->getMessage());
                    }
                }
            }
        }
    } elseif ($action === 'revoke') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare("SELECT name FROM api_keys WHERE id = ?");
            $stmt->execute([$id]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                $pdo->prepare("UPDATE api_keys SET revoked_at = NOW() WHERE id = ?")->execute([$id]);
                audit_log($pdo, "Revocation cle API '{$row['name']}' (id=$id)");
                $success = "Cle '{$row['name']}' revoquee.";
            }
        }
    }
}

// Liste des cles (masquees)
// Note : la colonne auto_generated n'existe qu'a partir de la migration 040.
// Utilise COALESCE pour retrocompatibilite si la migration n'a pas encore tourne.
// COALESCE pour retrocompatibilite si migrations 040/047 pas encore tournees.
// Sub-SELECT en lieu de colonne pour eviter "Unknown column" en boot sans migration.
$hasConsumerHint = $pdo->query(
    "SELECT COUNT(*) FROM information_schema.COLUMNS "
    . "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'api_keys' AND COLUMN_NAME = 'consumer_hint'"
)->fetchColumn() > 0;
$consumerCol = $hasConsumerHint ? 'consumer_hint' : 'NULL AS consumer_hint';
$keys = $pdo->query(
    "SELECT id, name, key_prefix, scope_json, created_at, revoked_at, last_used_at, last_used_ip, "
    . "COALESCE(auto_generated, 0) AS auto_generated, $consumerCol "
    . "FROM api_keys ORDER BY revoked_at IS NULL DESC, created_at DESC"
)->fetchAll(PDO::FETCH_ASSOC);

// Detecte la cle legacy auto-generee encore active + presence d'une cle scopee
// pour adapter le ton du banner (CTA "creer une cle" vs "rotation maintenant").
$hasLegacyActive = false;
$hasScopedKey = false;
// Anciennete : separe les cles actives en 3 buckets (recent / 90-180j / >=180j)
// Source de date : created_at, pas last_used_at - une cle compromise reste a risque
// meme si elle est utilisee quotidiennement.
$now = time();
$keysWarning = [];   // 90-179 jours
$keysCritical = [];  // >= 180 jours
foreach ($keys as $k) {
    if (empty($k['revoked_at'])) {
        if (!empty($k['auto_generated'])) $hasLegacyActive = true;
        else $hasScopedKey = true;
        if (empty($k['auto_generated']) && !empty($k['created_at'])) {
            $ageDays = max(0, (int)(($now - strtotime($k['created_at'])) / 86400));
            if ($ageDays >= 180)      $keysCritical[] = $k + ['age_days' => $ageDays];
            elseif ($ageDays >= 90)   $keysWarning[]  = $k + ['age_days' => $ageDays];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>API Keys - RootWarden</title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
    <?php require_once __DIR__ . '/../menu.php'; ?>
    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold">API Keys</h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">Cles API segmentees avec scope par regex de route. Rotation + revocation + audit last_used.</p>
            </div>
            <a href="/adm/admin_page.php" class="text-sm px-4 py-2 border rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 dark:border-gray-600">Retour Admin</a>
        </div>

        <?php if ($error): ?>
        <div class="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($hasLegacyActive && $hasScopedKey): ?>
        <div class="mb-4 p-4 bg-red-50 dark:bg-red-900/20 border-2 border-red-400 dark:border-red-700 rounded-lg text-sm">
            <div class="flex items-start gap-3">
                <span class="text-2xl">🛑</span>
                <div class="flex-1">
                    <div class="font-bold text-red-800 dark:text-red-300 mb-1">Rotation requise : <code class="px-1 bg-red-100 dark:bg-red-800/40 rounded">proxy-internal-legacy</code> doit etre revoquee</div>
                    <p class="text-red-700 dark:text-red-300 mb-2">
                        Tu as deja une cle API scopee active. La cle legacy auto-generee (scope=NULL, toutes routes)
                        n'est plus necessaire et represente un risque inutile.
                    </p>
                    <p class="text-red-700 dark:text-red-300">
                        <b>A faire</b> : verifie que <code>srv-docker.env:API_KEY</code> pointe vers ta cle scopee,
                        puis revoque <code>proxy-internal-legacy</code> ci-dessous.
                    </p>
                </div>
            </div>
        </div>
        <?php elseif ($hasLegacyActive): ?>
        <div class="mb-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded-lg text-sm">
            <div class="flex items-start gap-3">
                <span class="text-2xl">⚠</span>
                <div class="flex-1">
                    <div class="font-bold text-yellow-800 dark:text-yellow-300 mb-1">Cle legacy <code class="px-1 bg-yellow-100 dark:bg-yellow-800/40 rounded">proxy-internal-legacy</code> active</div>
                    <p class="text-yellow-700 dark:text-yellow-300 mb-2">
                        Cette cle auto-generee autorise <b>toutes les routes</b> (scope=NULL).
                        Elle existe pour que le proxy PHP (qui envoie <code>srv-docker.env:API_KEY</code>)
                        continue a fonctionner pendant la transition vers les cles segmentees.
                    </p>
                    <p class="text-yellow-700 dark:text-yellow-300">
                        <b>Action recommandee</b> : creez une vraie cle scopee pour le proxy PHP
                        (ex. <code>php-proxy</code> avec scope <code>.*</code> ou regex precises),
                        rotatez <code>srv-docker.env:API_KEY</code> vers cette nouvelle valeur,
                        puis revoquez <code>proxy-internal-legacy</code>.
                    </p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if (!empty($keysCritical) || !empty($keysWarning)): ?>
        <?php $bannerCritical = !empty($keysCritical); ?>
        <div class="mb-4 p-4 <?= $bannerCritical ? 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700' : 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-300 dark:border-yellow-700' ?> border rounded-lg text-sm">
            <div class="flex items-start gap-3">
                <span class="text-2xl"><?= $bannerCritical ? '🔁' : '⏰' ?></span>
                <div class="flex-1">
                    <div class="font-bold <?= $bannerCritical ? 'text-red-800 dark:text-red-300' : 'text-yellow-800 dark:text-yellow-300' ?> mb-1">
                        <?php if ($bannerCritical): ?>
                            Rotation recommandee : <?= count($keysCritical) ?> cle(s) actives depuis plus de 180 jours
                        <?php else: ?>
                            Pense a rotater : <?= count($keysWarning) ?> cle(s) actives depuis plus de 90 jours
                        <?php endif; ?>
                    </div>
                    <p class="<?= $bannerCritical ? 'text-red-700 dark:text-red-300' : 'text-yellow-700 dark:text-yellow-300' ?> mb-2 text-xs">
                        Bonne pratique securite : rotater les credentials a long terme (90j warning, 180j alerte) limite l'impact d'une compromission.
                        Cliquer sur <b>Revoquer</b> puis sur <b>↻ Renouveler</b> sur la ligne (le scope et le consommateur sont recopies).
                    </p>
                    <ul class="text-xs space-y-0.5 mt-2">
                        <?php foreach ($keysCritical as $k): ?>
                        <li class="flex items-center gap-2">
                            <span class="inline-block px-1.5 py-0.5 rounded bg-red-200 dark:bg-red-800/60 text-red-900 dark:text-red-100 text-[10px] font-mono"><?= (int)$k['age_days'] ?>j</span>
                            <code class="font-mono"><?= htmlspecialchars($k['name']) ?></code>
                            <?php if (!empty($k['consumer_hint'])): ?><span class="text-gray-500">→ <?= htmlspecialchars($k['consumer_hint']) ?></span><?php endif; ?>
                        </li>
                        <?php endforeach; ?>
                        <?php foreach ($keysWarning as $k): ?>
                        <li class="flex items-center gap-2">
                            <span class="inline-block px-1.5 py-0.5 rounded bg-yellow-200 dark:bg-yellow-800/60 text-yellow-900 dark:text-yellow-100 text-[10px] font-mono"><?= (int)$k['age_days'] ?>j</span>
                            <code class="font-mono"><?= htmlspecialchars($k['name']) ?></code>
                            <?php if (!empty($k['consumer_hint'])): ?><span class="text-gray-500">→ <?= htmlspecialchars($k['consumer_hint']) ?></span><?php endif; ?>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($newKey): ?>
        <div class="mb-6 p-4 bg-green-50 border-2 border-green-400 rounded-lg dark:bg-green-900/20 dark:border-green-600">
            <div class="font-bold text-green-800 dark:text-green-300 mb-2">✓ <?= htmlspecialchars($success) ?></div>
            <p class="text-xs text-green-700 dark:text-green-400 mb-3">⚠ Cette cle ne sera <b>plus jamais</b> affichee. Copiez-la maintenant.</p>
            <div class="bg-white dark:bg-gray-800 p-3 rounded border border-green-300 font-mono text-sm break-all" id="new-key-value"><?= htmlspecialchars($newKey) ?></div>
            <button onclick="navigator.clipboard.writeText(document.getElementById('new-key-value').textContent).then(() => this.textContent='Copie ✓')"
                    class="mt-2 text-xs px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded">Copier</button>
            <div class="mt-3 pt-3 border-t border-green-300 dark:border-green-700 text-xs text-green-800 dark:text-green-300">
                <div class="font-semibold mb-1">📋 Cette plateforme ne deploie pas la cle automatiquement. A faire manuellement :</div>
                <?php if (!empty($newKeyConsumerHint)): ?>
                <div class="mt-1 p-2 bg-white dark:bg-gray-800 rounded border border-green-300 dark:border-green-700">
                    <span class="text-gray-500">Coller dans :</span>
                    <code class="font-mono"><?= htmlspecialchars($newKeyConsumerHint) ?></code>
                </div>
                <?php else: ?>
                <ul class="list-disc list-inside space-y-0.5 mt-1">
                    <li>Mettre a jour <code>srv-docker.env:API_KEY</code> si c'est la cle du proxy PHP</li>
                    <li>Mettre a jour les jobs CI/CD, secrets k8s, ansible-vault qui consomment la cle</li>
                    <li>Redemarrer les conteneurs ou recharger la config concernes</li>
                </ul>
                <p class="text-[10px] text-gray-500 mt-1">Astuce : renseigner le champ "Ou sera utilisee cette cle ?" a la creation pour que ce rappel soit personnalise au renouvellement.</p>
                <?php endif; ?>
            </div>
        </div>
        <?php elseif ($success): ?>
        <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <!-- Formulaire creation - redesign UX : modeles + checklist modules -->
        <details class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6" open>
            <summary class="cursor-pointer font-bold text-sm">+ Creer une nouvelle cle API</summary>
            <form method="POST" class="mt-4 space-y-4" id="apikey-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="create">

                <div>
                    <label class="block text-xs font-medium mb-1">Nom <span class="text-gray-400">(ex: php-proxy, cve-scanner, ci-deploy)</span></label>
                    <input type="text" name="name" id="ak-name" required pattern="[a-zA-Z0-9_-]{3,100}"
                           class="w-full px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                           placeholder="ex: ci-deploy">
                </div>

                <div>
                    <label class="block text-xs font-medium mb-1">
                        Ou sera utilisee cette cle ? <span class="text-gray-400">(rappel affiche au renouvellement)</span>
                    </label>
                    <input type="text" name="consumer_hint" id="ak-consumer-hint" maxlength="200"
                           class="w-full px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                           placeholder="ex: srv-docker.env:API_KEY, GitLab CI variable PROD_API_KEY, ansible-vault secrets.yml">
                    <p class="text-[10px] text-gray-500 mt-1">Indice libre, stocke tel quel. Pas de credential, juste un memo pour savoir ou recoller la cle quand on la renouvelle.</p>
                </div>

                <!-- Modeles rapides : 1 clic pre-remplit nom + scope -->
                <div>
                    <label class="block text-xs font-medium mb-1.5">Modeles rapides</label>
                    <div class="flex flex-wrap gap-1.5">
                        <button type="button" onclick="akPreset('all')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Tout (legacy)</button>
                        <button type="button" onclick="akPreset('readonly')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Lecture seule</button>
                        <button type="button" onclick="akPreset('cve')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Scan CVE</button>
                        <button type="button" onclick="akPreset('deploy')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Deploiement SSH</button>
                        <button type="button" onclick="akPreset('updates')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Maj APT</button>
                        <button type="button" onclick="akPreset('audit')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Audit SSH</button>
                        <button type="button" onclick="akPreset('monitoring')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-blue-50 dark:hover:bg-blue-900/30">Monitoring</button>
                        <button type="button" onclick="akPreset('clear')" class="text-xs px-2.5 py-1 rounded-full border border-gray-300 dark:border-gray-600 hover:bg-red-50 dark:hover:bg-red-900/30 text-red-600 dark:text-red-400">Vider</button>
                    </div>
                </div>

                <!-- Modules autorises : checkboxes auto-generent le scope -->
                <div>
                    <label class="block text-xs font-medium mb-1.5">Modules autorises <span class="text-gray-400">(cocher pour ajouter les routes correspondantes au scope)</span></label>
                    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-1.5 p-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800/50">
                        <?php
                        // Modules <-> liste de regex (alignees sur les blueprints Flask)
                        $modules = [
                            'monitoring' => ['label' => 'Monitoring (status, list)',    'regexes' => ['^/list_machines$', '^/server_status$', '^/linux_version$', '^/last_reboot$', '^/filter_servers$', '^/cve_trends$']],
                            'cve'        => ['label' => 'CVE (scan + results)',        'regexes' => ['^/cve_']],
                            'ssh'        => ['label' => 'SSH (deploy + keys)',         'regexes' => ['^/deploy', '^/preflight_check$', '^/platform_key$', '^/test_platform_key$', '^/scan_server_users$', '^/server_user_']],
                            'updates'    => ['label' => 'Maj APT',                     'regexes' => ['^/apt_', '^/update', '^/security_updates$', '^/dpkg_repair$', '^/custom_update$', '^/dry_run_update$', '^/pending_packages$', '^/schedule_']],
                            'iptables'   => ['label' => 'Iptables',                    'regexes' => ['^/iptables']],
                            'fail2ban'   => ['label' => 'Fail2ban',                    'regexes' => ['^/fail2ban/']],
                            'services'   => ['label' => 'Services systemd',            'regexes' => ['^/services/']],
                            'ssh_audit'  => ['label' => 'Audit SSH',                   'regexes' => ['^/ssh-audit/']],
                            'supervision'=> ['label' => 'Supervision',                 'regexes' => ['^/supervision/']],
                            'bashrc'     => ['label' => 'Bashrc',                      'regexes' => ['^/bashrc/']],
                            'graylog'    => ['label' => 'Graylog',                     'regexes' => ['^/graylog/']],
                            'wazuh'      => ['label' => 'Wazuh',                       'regexes' => ['^/wazuh/']],
                            'admin'      => ['label' => 'Admin (backups, perms)',      'regexes' => ['^/admin/', '^/server_lifecycle$', '^/exclude_user$']],
                            'reboot'     => ['label' => 'Reboot serveur',              'regexes' => ['^/reboot_server$']],
                            'logs'       => ['label' => 'Logs streaming (SSE)',        'regexes' => ['^/logs$', '^/update-logs$', '^/iptables-logs$']],
                        ];
                        foreach ($modules as $key => $mod):
                        ?>
                        <label class="flex items-center gap-2 text-xs px-2 py-1 rounded hover:bg-white dark:hover:bg-gray-700 cursor-pointer">
                            <input type="checkbox" class="ak-mod" data-regexes='<?= htmlspecialchars(json_encode($mod['regexes']), ENT_QUOTES) ?>' onchange="akModulesChange()">
                            <span><?= htmlspecialchars($mod['label']) ?></span>
                        </label>
                        <?php endforeach; ?>
                    </div>
                </div>

                <!-- Scope avance (textarea, edition manuelle pour les pros) -->
                <details class="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                    <summary class="text-xs text-gray-600 dark:text-gray-400 cursor-pointer">Avance : editer les regex manuellement</summary>
                    <textarea name="scope" id="ak-scope" rows="5"
                              placeholder="Exemples (1 regex par ligne) :&#10;^/cve_&#10;^/list_machines$&#10;^/wazuh/(install|detect)$"
                              class="w-full mt-2 px-3 py-2 text-xs font-mono border rounded-lg dark:bg-gray-700 dark:border-gray-600"></textarea>
                    <p class="text-[10px] text-gray-500 mt-1">Les routes matchees par au moins une regex sont autorisees. Vide = ALL (compat legacy).</p>
                </details>

                <button type="submit" class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg">Creer la cle</button>
            </form>
        </details>

        <script>
        // Presets rapides : pre-remplit nom (si vide) + scope (textarea + checkboxes)
        const AK_PRESETS = {
            all:        {name_hint: 'php-proxy',      regexes: []},  // vide = ALL
            readonly:   {name_hint: 'readonly-dash',  regexes: ['^/list_machines$', '^/server_status$', '^/cve_results$', '^/cve_history$', '^/cve_trends$', '^/last_reboot$', '^/linux_version$']},
            cve:        {name_hint: 'cve-scanner',    regexes: ['^/cve_']},
            deploy:     {name_hint: 'deploy-bot',     regexes: ['^/deploy', '^/preflight_check$', '^/platform_key$', '^/test_platform_key$']},
            updates:    {name_hint: 'apt-runner',     regexes: ['^/apt_', '^/update', '^/security_updates$', '^/dpkg_repair$', '^/pending_packages$']},
            audit:      {name_hint: 'ssh-auditor',    regexes: ['^/ssh-audit/']},
            monitoring: {name_hint: 'monitor-probe',  regexes: ['^/list_machines$', '^/server_status$', '^/linux_version$', '^/last_reboot$', '^/filter_servers$']},
            clear:      {name_hint: '',               regexes: []},
        };
        function akPreset(key) {
            const p = AK_PRESETS[key]; if (!p) return;
            // Nom : suggere si vide
            const nameInput = document.getElementById('ak-name');
            if (!nameInput.value.trim() && p.name_hint) {
                const datePart = new Date().toISOString().slice(0, 10);
                nameInput.value = `${p.name_hint}-${datePart}`;
            }
            // Decoche tout puis coche les modules correspondants au preset
            document.querySelectorAll('.ak-mod').forEach(cb => cb.checked = false);
            const ta = document.getElementById('ak-scope');
            if (key === 'clear') {
                ta.value = '';
                nameInput.value = '';
                return;
            }
            ta.value = p.regexes.join('\n');
            // Coche les modules dont au moins une regex est dans le preset
            document.querySelectorAll('.ak-mod').forEach(cb => {
                try {
                    const mod_re = JSON.parse(cb.getAttribute('data-regexes') || '[]');
                    if (mod_re.some(r => p.regexes.includes(r))) cb.checked = true;
                } catch (_) {}
            });
        }
        // Quand on coche/decoche un module, on regenere le textarea (union des regex coches)
        function akModulesChange() {
            const all = new Set();
            document.querySelectorAll('.ak-mod:checked').forEach(cb => {
                try {
                    JSON.parse(cb.getAttribute('data-regexes') || '[]').forEach(r => all.add(r));
                } catch (_) {}
            });
            document.getElementById('ak-scope').value = [...all].join('\n');
        }
        </script>

        <!-- Liste des cles -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50">
                    <tr>
                        <th class="text-left px-3 py-2">Nom</th>
                        <th class="text-left px-3 py-2">Prefixe</th>
                        <th class="text-left px-3 py-2">Scope</th>
                        <th class="text-left px-3 py-2">Consommateur</th>
                        <th class="text-left px-3 py-2">Creee</th>
                        <th class="text-left px-3 py-2">Dernier usage</th>
                        <th class="text-left px-3 py-2">Statut</th>
                        <th class="text-left px-3 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($keys as $k): ?>
                    <tr>
                        <td class="px-3 py-2 font-medium">
                            <?= htmlspecialchars($k['name']) ?>
                            <?php if (!empty($k['auto_generated'])): ?>
                                <span class="ml-1 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-yellow-100 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-300" title="Cle auto-generee par la plateforme">AUTO</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-3 py-2 font-mono text-xs"><?= htmlspecialchars($k['key_prefix']) ?>…</td>
                        <td class="px-3 py-2 text-xs">
                            <?php if ($k['scope_json']): ?>
                                <?php $patterns = json_decode($k['scope_json'], true) ?: []; ?>
                                <code class="text-[10px]"><?= htmlspecialchars(implode(' | ', array_slice($patterns, 0, 3))) ?><?= count($patterns) > 3 ? '…' : '' ?></code>
                            <?php else: ?>
                                <span class="text-gray-400">ALL (compat)</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-3 py-2 text-xs">
                            <?php if (!empty($k['consumer_hint'])): ?>
                                <code class="text-[10px]" title="<?= htmlspecialchars($k['consumer_hint']) ?>"><?= htmlspecialchars(mb_strimwidth($k['consumer_hint'], 0, 32, '…')) ?></code>
                            <?php else: ?>
                                <span class="text-gray-400 text-[10px]">—</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-3 py-2 text-xs"><?= htmlspecialchars($k['created_at']) ?></td>
                        <td class="px-3 py-2 text-xs">
                            <?php if ($k['last_used_at']): ?>
                                <?= htmlspecialchars($k['last_used_at']) ?><br>
                                <span class="text-[10px] text-gray-400"><?= htmlspecialchars($k['last_used_ip'] ?? '') ?></span>
                            <?php else: ?>
                                <span class="text-gray-400">jamais</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-3 py-2">
                            <?php if ($k['revoked_at']): ?>
                                <span class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/40">Revoquee <?= htmlspecialchars($k['revoked_at']) ?></span>
                            <?php else: ?>
                                <span class="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40">Active</span>
                            <?php endif; ?>
                        </td>
                        <td class="px-3 py-2">
                            <?php if (!$k['revoked_at']): ?>
                            <form method="POST" class="inline" onsubmit="return confirm('Revoquer definitivement la cle \'<?= htmlspecialchars(addslashes($k['name'])) ?>\' ?')">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="action" value="revoke">
                                <input type="hidden" name="id" value="<?= (int)$k['id'] ?>">
                                <button type="submit" class="text-xs text-red-600 hover:text-red-800">Revoquer</button>
                            </form>
                            <?php elseif (empty($k['auto_generated'])): ?>
                            <form method="POST" class="inline" onsubmit="return confirm('Renouveler la cle \'<?= htmlspecialchars(addslashes($k['name'])) ?>\' avec le meme scope ? Une nouvelle valeur sera generee.')">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="action" value="renew">
                                <input type="hidden" name="id" value="<?= (int)$k['id'] ?>">
                                <button type="submit" class="text-xs text-blue-600 hover:text-blue-800" title="Cree une nouvelle cle avec le meme scope">↻ Renouveler</button>
                            </form>
                            <?php else: ?>
                                <span class="text-[10px] text-gray-400">-</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php if (empty($keys)): ?>
            <div class="p-6 text-center text-sm text-gray-500">Aucune cle API. La clef legacy <code>API_KEY</code> de l'env reste active tant que cette table est vide.</div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
