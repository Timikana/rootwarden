<?php
/**
 * notifications.php - Historique complet des notifications in-app
 */
require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/db.php';
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

$pageTitle = "Notifications";
$userId = (int)($_SESSION['user_id'] ?? 0);
$roleId = (int)($_SESSION['role_id'] ?? 0);

$whereUser = $roleId >= 2
    ? "(n.user_id = ? OR n.user_id = 0)"
    : "n.user_id = ?";

// Filtres
$filterType = $_GET['type'] ?? '';
$filterStatus = $_GET['status'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 20;
$offset = ($page - 1) * $perPage;

// Construction WHERE
$where = $whereUser;
$params = [$userId];
if ($filterType) { $where .= " AND n.type = ?"; $params[] = $filterType; }
if ($filterStatus === 'unread') { $where .= " AND n.read_at IS NULL"; }
if ($filterStatus === 'read') { $where .= " AND n.read_at IS NOT NULL"; }

// Count
$countStmt = $pdo->prepare("SELECT COUNT(*) FROM notifications n WHERE {$where}");
$countStmt->execute($params);
$total = (int)$countStmt->fetchColumn();
$pages = (int)ceil($total / $perPage);

// Fetch
$stmt = $pdo->prepare("SELECT n.* FROM notifications n WHERE {$where} ORDER BY n.created_at DESC LIMIT {$perPage} OFFSET {$offset}");
$stmt->execute($params);
$notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Unread count
$unreadStmt = $pdo->prepare("SELECT COUNT(*) FROM notifications n WHERE {$whereUser} AND n.read_at IS NULL");
$unreadStmt->execute([$userId]);
$unreadCount = (int)$unreadStmt->fetchColumn();

$typeLabels = [
    'cve_critical' => ['CVE critique', 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'],
    'server_offline' => ['Serveur offline', 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'],
    'perm_granted' => ['Permission', 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'],
    'perm_expired' => ['Perm. expiree', 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'],
    'password_expiry' => ['Mot de passe', 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'],
    'info' => ['Info', 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400'],
];
?>
<!DOCTYPE html>
<html lang="fr" class="">
<head>
    <title><?= $pageTitle ?> - <?= htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden') ?></title>
    <?php require_once 'head.php'; ?>
</head>
<body class="bg-gray-50 dark:bg-gray-900 min-h-screen">
    <?php require_once 'menu.php'; ?>

    <main class="lg:ml-56 p-6">
        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100">Notifications</h1>
                <p class="text-sm text-gray-500"><?= $unreadCount ?> non lue<?= $unreadCount > 1 ? 's' : '' ?> sur <?= $total ?> total</p>
<?php $tipId = 'notifications'; $tipTitle = t('tip.notif_title'); $tipSteps = [t('tip.notif_step1'), t('tip.notif_step2'), t('tip.notif_step3')]; require __DIR__ . '/includes/howto_tip.php'; ?>
            </div>
            <?php if ($unreadCount > 0): ?>
            <button hx-post="/adm/api/notifications.php" hx-vals='{"action":"read_all"}' hx-swap="none"
                    onclick="setTimeout(() => location.reload(), 300)"
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
                Tout marquer comme lu
            </button>
            <?php endif; ?>
        </div>

        <!-- Filtres -->
        <div class="flex items-center gap-3 mb-4">
            <form method="GET" class="flex items-center gap-2">
                <select name="type" class="text-xs px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200">
                    <option value="">Tous les types</option>
                    <?php foreach ($typeLabels as $k => $v): ?>
                    <option value="<?= $k ?>" <?= $filterType === $k ? 'selected' : '' ?>><?= $v[0] ?></option>
                    <?php endforeach; ?>
                </select>
                <select name="status" class="text-xs px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200">
                    <option value="" <?= !$filterStatus ? 'selected' : '' ?>>Toutes</option>
                    <option value="unread" <?= $filterStatus === 'unread' ? 'selected' : '' ?>>Non lues</option>
                    <option value="read" <?= $filterStatus === 'read' ? 'selected' : '' ?>>Lues</option>
                </select>
                <button type="submit" class="text-xs px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">Filtrer</button>
                <?php if ($filterType || $filterStatus): ?>
                <a href="/notifications.php" class="text-xs text-gray-500 hover:text-gray-700">Reset</a>
                <?php endif; ?>
            </form>
        </div>

        <!-- Liste -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm divide-y divide-gray-100 dark:divide-gray-700">
            <?php if (empty($notifications)): ?>
                <div class="px-6 py-12 text-center text-gray-400">
                    <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
                    Aucune notification
                </div>
            <?php else: ?>
                <?php foreach ($notifications as $n):
                    $unread = !$n['read_at'];
                    $info = $typeLabels[$n['type']] ?? ['Autre', 'bg-gray-100 text-gray-600'];
                    $date = date('d/m/Y H:i', strtotime($n['created_at']));
                ?>
                <div class="flex items-start gap-4 px-5 py-4 <?= $unread ? 'bg-blue-50/50 dark:bg-blue-900/10' : '' ?> hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors">
                    <!-- Type badge -->
                    <span class="text-[10px] px-2 py-0.5 rounded-full <?= $info[1] ?> whitespace-nowrap mt-0.5"><?= $info[0] ?></span>
                    <!-- Content -->
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <span class="text-sm font-medium text-gray-800 dark:text-gray-200 <?= $unread ? 'font-bold' : '' ?>"><?= htmlspecialchars($n['title']) ?></span>
                            <?php if ($unread): ?><span class="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0"></span><?php endif; ?>
                        </div>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5"><?= htmlspecialchars($n['message']) ?></p>
                        <span class="text-[10px] text-gray-400 mt-1"><?= $date ?></span>
                    </div>
                    <!-- Actions -->
                    <div class="flex items-center gap-1 flex-shrink-0">
                        <?php if ($n['link']): ?>
                        <a href="<?= htmlspecialchars($n['link']) ?>" class="text-[10px] px-2 py-1 border border-gray-300 dark:border-gray-600 rounded text-gray-500 hover:text-blue-600 hover:border-blue-300 transition-colors">Voir</a>
                        <?php endif; ?>
                        <?php if ($unread): ?>
                        <button hx-post="/adm/api/notifications.php" hx-vals='{"action":"read","id":<?= $n['id'] ?>}' hx-swap="none"
                                onclick="this.closest('div.flex').parentElement.classList.remove('bg-blue-50/50','dark:bg-blue-900/10'); this.remove();"
                                class="text-[10px] px-2 py-1 border border-blue-300 dark:border-blue-700 rounded text-blue-500 hover:bg-blue-50 transition-colors">Marquer lu</button>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ($pages > 1): ?>
        <div class="flex items-center justify-center gap-2 mt-4">
            <?php for ($i = 1; $i <= $pages; $i++):
                $qs = http_build_query(array_filter(['type' => $filterType, 'status' => $filterStatus, 'page' => $i]));
                $active = $i === $page;
            ?>
            <a href="?<?= $qs ?>" class="text-xs px-3 py-1.5 rounded-lg <?= $active ? 'bg-blue-600 text-white' : 'border border-gray-300 dark:border-gray-600 text-gray-600 hover:bg-gray-50' ?> transition-colors"><?= $i ?></a>
            <?php endfor; ?>
        </div>
        <?php endif; ?>
    </main>

    <?php require_once 'footer.php'; ?>
</body>
</html>
