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
$error = null;
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCsrfToken();
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $name = trim($_POST['name'] ?? '');
        $scopeRaw = trim($_POST['scope'] ?? '');  // une regex par ligne

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
                        "INSERT INTO api_keys (name, key_prefix, key_hash, scope_json, created_by) "
                        . "VALUES (?, ?, ?, ?, ?)"
                    );
                    $stmt->execute([$name, $prefix, $hash, $scope, (int)$_SESSION['user_id']]);
                    $newKey = $fullKey;
                    $success = "Cle API '$name' creee. Copiez-la maintenant, elle ne sera plus affichee.";
                    audit_log($pdo, "Creation cle API '$name' prefix=$prefix scope=" . ($scope ?: 'ALL'));
                } catch (\PDOException $e) {
                    $error = $e->getCode() === '23000' ? 'Une cle avec ce nom existe deja.' : 'Erreur creation';
                    error_log('api_keys create: ' . $e->getMessage());
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
$keys = $pdo->query(
    "SELECT id, name, key_prefix, scope_json, created_at, revoked_at, last_used_at, last_used_ip "
    . "FROM api_keys ORDER BY revoked_at IS NULL DESC, created_at DESC"
)->fetchAll(PDO::FETCH_ASSOC);
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

        <?php if ($newKey): ?>
        <div class="mb-6 p-4 bg-green-50 border-2 border-green-400 rounded-lg dark:bg-green-900/20 dark:border-green-600">
            <div class="font-bold text-green-800 dark:text-green-300 mb-2">✓ <?= htmlspecialchars($success) ?></div>
            <p class="text-xs text-green-700 dark:text-green-400 mb-3">⚠ Cette cle ne sera <b>plus jamais</b> affichee. Copiez-la maintenant.</p>
            <div class="bg-white dark:bg-gray-800 p-3 rounded border border-green-300 font-mono text-sm break-all" id="new-key-value"><?= htmlspecialchars($newKey) ?></div>
            <button onclick="navigator.clipboard.writeText(document.getElementById('new-key-value').textContent).then(() => this.textContent='Copie ✓')"
                    class="mt-2 text-xs px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded">Copier</button>
        </div>
        <?php elseif ($success): ?>
        <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <!-- Formulaire creation -->
        <details class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6">
            <summary class="cursor-pointer font-bold text-sm">+ Creer une nouvelle cle API</summary>
            <form method="POST" class="mt-4 space-y-3">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="create">
                <div>
                    <label class="block text-xs font-medium mb-1">Nom (ex: php-proxy, cve-scanner)</label>
                    <input type="text" name="name" required pattern="[a-zA-Z0-9_-]{3,100}"
                           class="w-full px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600">
                </div>
                <div>
                    <label class="block text-xs font-medium mb-1">Scope (1 regex de route par ligne, vide = ALL)</label>
                    <textarea name="scope" rows="4" placeholder="Exemples:&#10;^/cve/&#10;^/list_machines$"
                              class="w-full px-3 py-2 text-xs font-mono border rounded-lg dark:bg-gray-700 dark:border-gray-600"></textarea>
                    <p class="text-[10px] text-gray-500 mt-1">Les routes matchees par au moins une regex sont autorisees. Vide = ALL (compat legacy).</p>
                </div>
                <button type="submit" class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg">Creer la cle</button>
            </form>
        </details>

        <!-- Liste des cles -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50">
                    <tr>
                        <th class="text-left px-3 py-2">Nom</th>
                        <th class="text-left px-3 py-2">Prefixe</th>
                        <th class="text-left px-3 py-2">Scope</th>
                        <th class="text-left px-3 py-2">Creee</th>
                        <th class="text-left px-3 py-2">Dernier usage</th>
                        <th class="text-left px-3 py-2">Statut</th>
                        <th class="text-left px-3 py-2">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($keys as $k): ?>
                    <tr>
                        <td class="px-3 py-2 font-medium"><?= htmlspecialchars($k['name']) ?></td>
                        <td class="px-3 py-2 font-mono text-xs"><?= htmlspecialchars($k['key_prefix']) ?>…</td>
                        <td class="px-3 py-2 text-xs">
                            <?php if ($k['scope_json']): ?>
                                <?php $patterns = json_decode($k['scope_json'], true) ?: []; ?>
                                <code class="text-[10px]"><?= htmlspecialchars(implode(' | ', array_slice($patterns, 0, 3))) ?><?= count($patterns) > 3 ? '…' : '' ?></code>
                            <?php else: ?>
                                <span class="text-gray-400">ALL (compat)</span>
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
