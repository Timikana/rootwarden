<?php
/**
 * adm/audit_log.php - Journal d'activite complet
 *
 * Affiche toutes les actions loguees dans user_logs avec filtres.
 * Acces : superadmin + admin avec can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

$filterUser   = trim((string)($_GET['user'] ?? ''));
$filterAction = trim((string)($_GET['action'] ?? ''));
$filterFrom   = trim((string)($_GET['from'] ?? ''));
$filterTo     = trim((string)($_GET['to'] ?? ''));
$page         = max(1, (int)($_GET['page'] ?? 1));
$perPage      = 50;
$offset       = ($page - 1) * $perPage;

// Valide le format YYYY-MM-DD pour les dates (sinon on ignore le filtre)
$isValidDate = fn($d) => $d !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $d);

// ── Construction des filtres (WHERE + params reutilises pour count/select/export)
$where = [];
$params = [];
if ($filterUser) {
    $where[] = "u.name LIKE ?";
    $params[] = "%$filterUser%";
}
if ($filterAction) {
    $where[] = "l.action LIKE ?";
    $params[] = "%$filterAction%";
}
if ($isValidDate($filterFrom)) {
    $where[] = "l.created_at >= ?";
    $params[] = $filterFrom . ' 00:00:00';
}
if ($isValidDate($filterTo)) {
    $where[] = "l.created_at <= ?";
    $params[] = $filterTo . ' 23:59:59';
}
$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

// ── Export CSV (AVANT le count/select pagine : exporte TOUS les resultats filtres)
// Bug historique : l'export ne prenait que les 50 rows de la page courante.
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $stmtAll = $pdo->prepare("
        SELECT l.id, l.action, l.created_at, u.name AS username
        FROM user_logs l
        JOIN users u ON l.user_id = u.id
        $whereSQL
        ORDER BY l.created_at DESC
    ");
    $stmtAll->execute($params);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="audit_log_' . date('Y-m-d') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");  // BOM UTF-8 pour Excel
    fputcsv($out, ['ID', 'Date', 'Utilisateur', 'Action']);
    while ($row = $stmtAll->fetch(PDO::FETCH_ASSOC)) {
        fputcsv($out, [$row['id'], $row['created_at'], $row['username'], $row['action']]);
    }
    fclose($out);
    exit;
}

// ── Compte total filtre + select pagine
$countStmt = $pdo->prepare("SELECT COUNT(*) FROM user_logs l JOIN users u ON l.user_id = u.id $whereSQL");
$countStmt->execute($params);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
if ($page > $totalPages) { $page = $totalPages; $offset = ($page - 1) * $perPage; }

$stmt = $pdo->prepare("
    SELECT l.id, l.action, l.created_at, u.name AS username
    FROM user_logs l
    JOIN users u ON l.user_id = u.id
    $whereSQL
    ORDER BY l.created_at DESC
    LIMIT " . (int)$offset . ", " . (int)$perPage
);
$stmt->execute($params);
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// URL helper : preserve les filtres + page
$buildUrl = function(array $override = []) use ($filterUser, $filterAction, $filterFrom, $filterTo, $page) {
    $q = array_filter([
        'user'   => $filterUser,
        'action' => $filterAction,
        'from'   => $filterFrom,
        'to'     => $filterTo,
        'page'   => $page,
    ], fn($v) => $v !== '' && $v !== 0);
    foreach ($override as $k => $v) {
        if ($v === null || $v === '') unset($q[$k]);
        else $q[$k] = $v;
    }
    return 'audit_log.php' . ($q ? '?' . http_build_query($q) : '');
};

// Highlight visuel du prefixe tag dans l'action ([security], [rgpd], [bashrc]...)
$formatAction = function(string $action): string {
    if (preg_match('/^\[([a-z_-]+)\]\s*(.*)$/i', $action, $m)) {
        $tag = strtolower($m[1]);
        $rest = $m[2];
        $color = match ($tag) {
            'security', 'audit' => 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
            'rgpd'              => 'bg-pink-100 dark:bg-pink-900/30 text-pink-700 dark:text-pink-300',
            'graylog', 'wazuh'  => 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300',
            'bashrc'            => 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
            default             => 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
        };
        return '<span class="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded mr-2 ' . $color . '">'
             . htmlspecialchars($tag) . '</span>' . htmlspecialchars($rest);
    }
    return htmlspecialchars($action);
};
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('audit.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('audit.title') ?></span>
</nav>

<div class="px-6 py-6">
    <div class="flex flex-wrap items-start justify-between gap-3 mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('audit.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('audit.desc') ?></p>
            <p class="text-sm text-gray-500 dark:text-gray-400">
                <?= number_format($total, 0, ',', ' ') ?> <?= t('audit.entries_total') ?>
                <?php if ($where): ?><span class="text-xs text-blue-500 ml-1">(<?= t('audit.filtered') ?>)</span><?php endif; ?>
            </p>
        </div>
        <div class="flex flex-wrap gap-2">
            <?php if ((int)($_SESSION['role_id'] ?? 0) === 3): ?>
            <button onclick="auditVerifyIntegrity()" id="btn-verify-audit"
                    class="inline-flex items-center gap-1 text-sm px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white rounded-lg transition-colors"
                    title="<?= t('audit.btn_verify_tip') ?>">
                🔒 <?= t('audit.btn_verify') ?>
            </button>
            <button onclick="auditSealOrphans()" id="btn-seal-audit"
                    class="inline-flex items-center gap-1 text-sm px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-white rounded-lg transition-colors"
                    title="<?= t('audit.btn_seal_tip') ?>">
                🖋 <?= t('audit.btn_seal') ?>
            </button>
            <?php endif; ?>
            <a href="<?= htmlspecialchars($buildUrl(['export' => 'csv', 'page' => null])) ?>"
               class="inline-flex items-center gap-1 text-sm px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
               title="<?= t('audit.export_hint') ?>">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                <?= t('audit.btn_export_csv') ?>
            </a>
            <a href="/adm/admin_page.php" class="text-sm px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('audit.btn_back_admin') ?></a>
        </div>
    </div>

    <div id="audit-verify-result" class="hidden mb-4 p-3 rounded-lg text-sm"></div>

    <script>
    const _auditCsrf = '<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>';

    function _setAuditStatus(html, kind) {
        const el = document.getElementById('audit-verify-result');
        const palettes = {
            pending: 'border border-gray-300 bg-gray-50 text-gray-600 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300',
            ok:      'border border-green-300 bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-300',
            error:   'border border-red-300 bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
            warn:    'border border-yellow-300 bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300',
        };
        el.className = 'mb-4 p-3 rounded-lg text-sm ' + (palettes[kind] || palettes.pending);
        el.innerHTML = html;
    }

    async function auditVerifyIntegrity() {
        const btn = document.getElementById('btn-verify-audit');
        btn.disabled = true;
        _setAuditStatus('⏳ Verification de la chaine de hash en cours...', 'pending');
        try {
            const r = await fetch('/adm/api/audit_verify.php');
            const d = await r.json();
            if (d.integrity === 'OK') {
                _setAuditStatus(
                    `✅ Chaine intacte - <b>${d.sealed}</b> lignes scellees, <b>${d.unsealed}</b> non scellees, tete=<code>${d.chain_head || 'aucune'}</code>`,
                    'ok'
                );
            } else {
                const brokenId = d.error?.id ?? '?';
                _setAuditStatus(
                    `❌ <b>INCOHERENCE DETECTEE</b> - type=<code>${d.error?.type}</code> a la ligne <a href="?id=${brokenId}" class="underline font-bold">#${brokenId}</a><br><small>${d.error?.message || ''}</small>`,
                    'error'
                );
            }
        } catch (e) {
            _setAuditStatus('✗ Erreur : ' + e.message, 'error');
        } finally {
            btn.disabled = false;
        }
    }

    async function auditSealOrphans() {
        if (!confirm("Sceller les lignes orphelines dans la hash chain ?")) return;
        const btn = document.getElementById('btn-seal-audit');
        btn.disabled = true;
        _setAuditStatus('⏳ Scellement des lignes orphelines...', 'pending');
        try {
            const r = await fetch('/adm/api/audit_seal.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': _auditCsrf },
                body: JSON.stringify({ csrf_token: _auditCsrf })
            });
            const d = await r.json();
            _setAuditStatus(
                `🖋 Scelle : <b>${d.sealed ?? 0}</b> lignes sur ${d.unsealed_count ?? 0} orphelines. Tete=<code>${d.latest_hash || 'aucune'}</code>`,
                'warn'
            );
        } catch (e) {
            _setAuditStatus('✗ Erreur : ' + e.message, 'error');
        } finally {
            btn.disabled = false;
        }
    }
    </script>

    <!-- Filtres -->
    <form method="get" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6 grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
        <div>
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_user') ?></label>
            <input type="text" name="user" value="<?= htmlspecialchars($filterUser) ?>" placeholder="<?= t('audit.placeholder_name') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
        </div>
        <div>
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_action') ?></label>
            <input type="text" name="action" value="<?= htmlspecialchars($filterAction) ?>" placeholder="<?= t('audit.placeholder_action') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
        </div>
        <div>
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_from') ?></label>
            <input type="date" name="from" value="<?= htmlspecialchars($filterFrom) ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
        </div>
        <div>
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_to') ?></label>
            <input type="date" name="to" value="<?= htmlspecialchars($filterTo) ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
        </div>
        <div class="flex gap-2">
            <button type="submit" class="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"><?= t('audit.btn_filter') ?></button>
            <a href="audit_log.php" class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('audit.btn_reset') ?></a>
        </div>
    </form>

    <!-- Tableau -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-100 dark:bg-gray-700 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    <th class="px-4 py-3 w-16"><?= t('audit.th_id') ?></th>
                    <th class="px-4 py-3 w-44"><?= t('audit.th_date') ?></th>
                    <th class="px-4 py-3 w-40"><?= t('audit.th_user') ?></th>
                    <th class="px-4 py-3"><?= t('audit.th_action') ?></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                <?php foreach ($logs as $log): ?>
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td class="px-4 py-3 text-xs text-gray-400 font-mono">#<?= (int)$log['id'] ?></td>
                    <td class="px-4 py-3 text-xs text-gray-500 dark:text-gray-400 font-mono whitespace-nowrap"><?= htmlspecialchars($log['created_at']) ?></td>
                    <td class="px-4 py-3 font-medium text-gray-700 dark:text-gray-300"><?= htmlspecialchars($log['username']) ?></td>
                    <td class="px-4 py-3 text-gray-600 dark:text-gray-400"><?= $formatAction($log['action']) ?></td>
                </tr>
                <?php endforeach; ?>
                <?php if (empty($logs)): ?>
                <tr><td colspan="4" class="px-4 py-12 text-center text-gray-400"><?= t('audit.no_entries') ?></td></tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination windowed : «  < 1 .. 4 [5] 6 .. 20 >  » -->
    <?php if ($totalPages > 1): ?>
    <?php
        $window = 2;  // nb de pages autour de la courante
        $pages = [];
        for ($p = 1; $p <= $totalPages; $p++) {
            if ($p === 1 || $p === $totalPages || abs($p - $page) <= $window) {
                $pages[] = $p;
            } elseif (end($pages) !== '...') {
                $pages[] = '...';
            }
        }
    ?>
    <div class="flex flex-wrap justify-center items-center gap-1 mt-4 text-sm">
        <?php if ($page > 1): ?>
            <a href="<?= htmlspecialchars($buildUrl(['page' => 1])) ?>" class="px-2 py-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Premiere">«</a>
            <a href="<?= htmlspecialchars($buildUrl(['page' => $page - 1])) ?>" class="px-2 py-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Precedente">‹</a>
        <?php endif; ?>
        <?php foreach ($pages as $p): ?>
            <?php if ($p === '...'): ?>
                <span class="px-2 py-1 text-gray-400">…</span>
            <?php elseif ($p === $page): ?>
                <span class="px-3 py-1 rounded bg-blue-600 text-white font-bold"><?= $p ?></span>
            <?php else: ?>
                <a href="<?= htmlspecialchars($buildUrl(['page' => $p])) ?>" class="px-3 py-1 rounded border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700"><?= $p ?></a>
            <?php endif; ?>
        <?php endforeach; ?>
        <?php if ($page < $totalPages): ?>
            <a href="<?= htmlspecialchars($buildUrl(['page' => $page + 1])) ?>" class="px-2 py-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Suivante">›</a>
            <a href="<?= htmlspecialchars($buildUrl(['page' => $totalPages])) ?>" class="px-2 py-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700" title="Derniere">»</a>
        <?php endif; ?>
    </div>
    <p class="text-center text-xs text-gray-400 mt-2">
        <?= t('audit.page_of', ['current' => $page, 'total' => $totalPages]) ?>
    </p>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
