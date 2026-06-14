<?php
/**
 * tickets/index.php - Ticketing ITSM (GLPI / Jira / ServiceNow / generique).
 *
 * Liste les tickets crees depuis RootWarden (dont les CVE -> ticket) et permet
 * une creation manuelle. La cible reelle (Jira/GLPI/...) est configuree par env ;
 * si desactivee, les tickets restent 'local'.
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

$machines = [];
try {
    $machines = $pdo->query("SELECT id, name FROM machines ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('tickets.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('tickets.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('tickets.desc') ?></p>
            </div>
            <button id="new-ticket-btn" class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                <span><?= t('tickets.btn_new') ?></span>
            </button>
        </div>

        <div id="tickets-status" class="mb-4 text-sm"></div>

        <!-- Formulaire creation manuelle -->
        <div id="ticket-form" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6 space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('tickets.f_summary') ?></label>
                    <input id="t-summary" type="text" maxlength="255" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('tickets.f_machine') ?></label>
                    <select id="t-machine" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value=""><?= t('tickets.no_machine') ?></option>
                        <?php foreach ($machines as $m): ?>
                        <option value="<?= (int)$m['id'] ?>"><?= htmlspecialchars($m['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-xs text-gray-500 mb-1"><?= t('tickets.f_desc') ?></label>
                <textarea id="t-desc" rows="3" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"></textarea>
            </div>
            <div class="flex gap-2">
                <button id="t-save" class="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-2 rounded-lg"><?= t('tickets.btn_create') ?></button>
                <button id="t-cancel" class="bg-gray-200 dark:bg-gray-700 text-sm px-4 py-2 rounded-lg"><?= t('tickets.btn_cancel') ?></button>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700/50 text-gray-600 dark:text-gray-300">
                    <tr>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_when') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_source') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_summary') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_machine') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_provider') ?></th>
                        <th class="text-left px-4 py-3"><?= t('tickets.col_ref') ?></th>
                    </tr>
                </thead>
                <tbody id="tickets-tbody">
                    <tr><td colspan="6" class="px-4 py-6 text-center text-gray-400"><?= t('tickets.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/tickets/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
