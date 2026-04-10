<?php
/**
 * adm/audit_log.php — Journal d'activité complet
 *
 * Affiche toutes les actions loguées dans user_logs avec filtres.
 * Accès : superadmin uniquement.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
checkAuth([1, 2, 3]);
checkPermission('can_admin_portal');

$filterUser   = $_GET['user'] ?? '';
$filterAction = $_GET['action'] ?? '';
$page         = max(1, (int)($_GET['page'] ?? 1));
$perPage      = 50;
$offset       = ($page - 1) * $perPage;

// Requête avec filtres
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
$whereSQL = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$countStmt = $pdo->prepare("SELECT COUNT(*) FROM user_logs l JOIN users u ON l.user_id = u.id $whereSQL");
$countStmt->execute($params);
$total = (int)$countStmt->fetchColumn();
$totalPages = max(1, ceil($total / $perPage));

$stmt = $pdo->prepare("
    SELECT l.id, l.action, l.created_at, u.name as username
    FROM user_logs l
    JOIN users u ON l.user_id = u.id
    $whereSQL
    ORDER BY l.created_at DESC
    LIMIT $offset, $perPage
");
$stmt->execute($params);
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Export CSV
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="audit_log_' . date('Y-m-d') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['Date', 'Utilisateur', 'Action']);
    foreach ($logs as $log) {
        fputcsv($out, [$log['created_at'], $log['username'], $log['action']]);
    }
    fclose($out);
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
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
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('audit.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('audit.desc') ?></p>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= $total ?> <?= t('audit.entries_total') ?></p>
        </div>
        <div class="flex gap-2">
            <a href="?export=csv&user=<?= urlencode($filterUser) ?>&action=<?= urlencode($filterAction) ?>"
               class="inline-flex items-center gap-1 text-sm px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                <?= t('audit.btn_export_csv') ?>
            </a>
            <a href="/adm/admin_page.php" class="text-sm px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('audit.btn_back_admin') ?></a>
        </div>
    </div>

    <!-- Filtres -->
    <form class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-6 flex items-end gap-4">
        <div class="flex-1">
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_user') ?></label>
            <input type="text" name="user" value="<?= htmlspecialchars($filterUser) ?>" placeholder="<?= t('audit.placeholder_name') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
        </div>
        <div class="flex-1">
            <label class="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1"><?= t('audit.filter_action') ?></label>
            <input type="text" name="action" value="<?= htmlspecialchars($filterAction) ?>" placeholder="<?= t('audit.placeholder_action') ?>" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 focus:ring-2 focus:ring-blue-500">
        </div>
        <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"><?= t('audit.btn_filter') ?></button>
        <a href="audit_log.php" class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('audit.btn_reset') ?></a>
    </form>

    <!-- Tableau -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-100 dark:bg-gray-700 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    <th class="px-4 py-3"><?= t('audit.th_date') ?></th>
                    <th class="px-4 py-3"><?= t('audit.th_user') ?></th>
                    <th class="px-4 py-3"><?= t('audit.th_action') ?></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                <?php foreach ($logs as $log): ?>
                <tr class="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td class="px-4 py-3 text-xs text-gray-400 font-mono whitespace-nowrap"><?= htmlspecialchars($log['created_at']) ?></td>
                    <td class="px-4 py-3 font-medium text-gray-700 dark:text-gray-300"><?= htmlspecialchars($log['username']) ?></td>
                    <td class="px-4 py-3 text-gray-600 dark:text-gray-400"><?= htmlspecialchars($log['action']) ?></td>
                </tr>
                <?php endforeach; ?>
                <?php if (empty($logs)): ?>
                <tr><td colspan="3" class="px-4 py-8 text-center text-gray-400"><?= t('audit.no_entries') ?></td></tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <?php if ($totalPages > 1): ?>
    <div class="flex justify-center gap-2 mt-4">
        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
            <a href="?page=<?= $p ?>&user=<?= urlencode($filterUser) ?>&action=<?= urlencode($filterAction) ?>"
               class="px-3 py-1 text-sm rounded-lg <?= $p === $page ? 'bg-blue-600 text-white' : 'bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 hover:bg-gray-50' ?>"><?= $p ?></a>
        <?php endfor; ?>
    </div>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
