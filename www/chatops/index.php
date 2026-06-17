<?php
/**
 * chatops/index.php - Configuration du ChatOps bidirectionnel.
 *
 * Gere le mapping identifiant chat (Slack/Teams) -> utilisateur RootWarden et
 * affiche les instructions de configuration (URL du webhook entrant, secret).
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

$users = [];
try {
    $users = $pdo->query("SELECT id, name FROM users WHERE active = 1 ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {}
$webhookUrl = (isset($_SERVER['HTTP_HOST']) ? ('https://' . $_SERVER['HTTP_HOST']) : '') . '/chatops/webhook.php';
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('chatops.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">
        <div class="mb-6">
            <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('chatops.title') ?></h1>
            <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('chatops.desc') ?></p>
        </div>

        <div id="chatops-status" class="mb-4 text-sm"></div>

        <!-- Instructions -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6">
            <h2 class="font-semibold mb-2"><?= t('chatops.setup_title') ?></h2>
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-2"><?= t('chatops.setup_url') ?></p>
            <code class="block bg-gray-100 dark:bg-gray-900 rounded px-3 py-2 text-xs break-all mb-3"><?= htmlspecialchars($webhookUrl) ?></code>
            <ul class="list-disc list-inside text-sm text-gray-500 dark:text-gray-400 space-y-1">
                <li><?= t('chatops.setup_slack') ?></li>
                <li><?= t('chatops.setup_token') ?></li>
                <li><?= t('chatops.setup_commands') ?> : <code>status</code>, <code>approvals</code>, <code>approve &lt;id&gt;</code>, <code>reject &lt;id&gt;</code>, <code>help</code></li>
            </ul>
        </div>

        <!-- Mapping -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5">
            <h2 class="font-semibold mb-3"><?= t('chatops.mappings_title') ?></h2>
            <div class="flex flex-wrap items-end gap-3 mb-4">
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('chatops.f_platform') ?></label>
                    <select id="m-platform" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value="slack">Slack</option>
                        <option value="teams">Teams</option>
                        <option value="generic">Generic</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('chatops.f_chat_id') ?></label>
                    <input id="m-chatid" type="text" placeholder="U012ABCDEF" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('chatops.f_user') ?></label>
                    <select id="m-user" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <?php foreach ($users as $u): ?>
                        <option value="<?= (int)$u['id'] ?>"><?= htmlspecialchars($u['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label class="block text-xs text-gray-500 mb-1"><?= t('chatops.f_label') ?></label>
                    <input id="m-label" type="text" class="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <button id="m-add" title="<?= t('chatops.tip_add') ?>" class="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-2 rounded-lg"><?= t('chatops.btn_add') ?></button>
            </div>

            <table class="w-full text-sm">
                <thead class="text-gray-500 dark:text-gray-400 text-left border-b border-gray-200 dark:border-gray-700">
                    <tr>
                        <th class="py-2"><?= t('chatops.col_platform') ?></th>
                        <th class="py-2"><?= t('chatops.col_chat_id') ?></th>
                        <th class="py-2"><?= t('chatops.col_user') ?></th>
                        <th class="py-2"><?= t('chatops.col_label') ?></th>
                        <th class="py-2"></th>
                    </tr>
                </thead>
                <tbody id="chatops-tbody">
                    <tr><td colspan="5" class="py-4 text-center text-gray-400"><?= t('chatops.loading') ?></td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/chatops/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
