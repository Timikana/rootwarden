<?php
/**
 * privacy.php — Politique de confidentialite + droits RGPD
 *
 * @package RootWarden
 */
require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/db.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$contactEmail = htmlspecialchars(getenv('SERVER_ADMIN') ?: 'admin@localhost');
$gdprMessage = null;
$gdprType = null;
$gdprData = null;

// ── Actions RGPD (POST) ─────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCsrfToken();

    if (isset($_POST['request_data'])) {
        $stmt = $pdo->prepare(
            "SELECT u.name, u.email, r.name AS role, u.ssh_key, u.created_at,
                    u.password_updated_at, u.active, u.sudo
             FROM users u
             JOIN roles r ON u.role_id = r.id
             WHERE u.id = ?"
        );
        $stmt->execute([$_SESSION['user_id']]);
        $gdprData = $stmt->fetch(PDO::FETCH_ASSOC);
        $gdprType = 'info';
    }

    if (isset($_POST['delete_data'])) {
        $roleId = getUserRole((int) $_SESSION['user_id']);
        if ($roleId === 3) {
            $saCount = (int) $pdo->query("SELECT COUNT(*) FROM users WHERE role_id = 3 AND active = 1")->fetchColumn();
            if ($saCount <= 1) {
                $gdprMessage = t('privacy.error_last_sa');
                $gdprType = 'error';
                goto render;
            }
        }
        // Suppression cascade
        $uid = (int) $_SESSION['user_id'];
        $pdo->prepare("DELETE FROM permissions WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM user_machine_access WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM active_sessions WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM temporary_permissions WHERE user_id = ?")->execute([$uid]);
        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$uid]);

        session_unset();
        session_destroy();
        header("Location: /auth/login.php");
        exit();
    }
}
render:
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title><?= t('privacy.page_title') ?> — <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/menu.php'; ?>

<div class="max-w-4xl mx-auto px-6 py-8">
    <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-2 text-center"><?= t('privacy.page_title') ?></h1>
    <p class="text-xs text-gray-400 text-center mb-2"><?= t('privacy.last_updated') ?> 2026-04-11</p>
    <p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6 max-w-2xl mx-auto"><?= t('privacy.intro') ?></p>

    <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-8 text-sm leading-relaxed text-gray-600 dark:text-gray-300 space-y-6">

        <!-- 1. Donnees collectees -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s1_title') ?></h2>

            <h3 class="text-sm font-medium text-gray-700 dark:text-gray-200 mt-3 mb-1"><?= t('privacy.s1_sub1') ?></h3>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s1_sub1_l1') ?></li>
                <li><?= t('privacy.s1_sub1_l2') ?></li>
                <li><?= t('privacy.s1_sub1_l3') ?></li>
            </ul>

            <h3 class="text-sm font-medium text-gray-700 dark:text-gray-200 mt-3 mb-1"><?= t('privacy.s1_sub2') ?></h3>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s1_sub2_l1') ?></li>
                <li><?= t('privacy.s1_sub2_l2') ?></li>
                <li><?= t('privacy.s1_sub2_l3') ?></li>
            </ul>

            <h3 class="text-sm font-medium text-gray-700 dark:text-gray-200 mt-3 mb-1"><?= t('privacy.s1_sub3') ?></h3>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s1_sub3_l1') ?></li>
                <li><?= t('privacy.s1_sub3_l2') ?></li>
            </ul>
        </section>

        <!-- 2. Finalites -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s2_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s2_l1') ?></li>
                <li><?= t('privacy.s2_l2') ?></li>
                <li><?= t('privacy.s2_l3') ?></li>
                <li><?= t('privacy.s2_l4') ?></li>
            </ul>
        </section>

        <!-- 3. Stockage et securite -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s3_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s3_l1') ?></li>
                <li><?= t('privacy.s3_l2') ?></li>
                <li><?= t('privacy.s3_l3') ?></li>
                <li><?= t('privacy.s3_l4') ?></li>
                <li><?= t('privacy.s3_l5') ?></li>
                <li><?= t('privacy.s3_l6') ?></li>
            </ul>
        </section>

        <!-- 4. Conservation -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s4_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s4_l1') ?></li>
                <li><?= t('privacy.s4_l2') ?></li>
                <li><?= t('privacy.s4_l3') ?></li>
                <li><?= t('privacy.s4_l4') ?></li>
            </ul>
        </section>

        <!-- 5. Partage -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s5_title') ?></h2>
            <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <p class="text-green-700 dark:text-green-300"><?= t('privacy.s5_p1') ?></p>
            </div>
        </section>

        <!-- 6. Droits -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s6_title') ?></h2>
            <p class="mb-2"><?= t('privacy.s6_p1') ?></p>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('privacy.s6_l1') ?></li>
                <li><?= t('privacy.s6_l2') ?></li>
                <li><?= t('privacy.s6_l3') ?></li>
                <li><?= t('privacy.s6_l4') ?></li>
            </ul>
            <p class="mt-2 text-xs text-gray-400"><?= t('privacy.s6_exercise') ?></p>
        </section>

        <!-- 7. Contact -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('privacy.s7_title') ?></h2>
            <p><?= t('privacy.s7_p1') ?></p>
            <p class="mt-2">
                <a href="mailto:<?= $contactEmail ?>" class="text-blue-600 dark:text-blue-400 hover:underline"><?= $contactEmail ?></a>
            </p>
        </section>

        <!-- Support -->
        <section class="pt-4 border-t border-gray-200 dark:border-gray-700">
            <div class="flex items-center gap-3">
                <span class="text-2xl">&#9749;</span>
                <div>
                    <p class="text-sm font-medium text-gray-700 dark:text-gray-200"><?= t('terms.support_title') ?></p>
                    <p class="text-xs text-gray-500 dark:text-gray-400"><?= t('terms.support_desc') ?></p>
                    <a href="https://buymeacoffee.com/timikana" target="_blank" rel="noopener"
                       class="inline-block mt-2 text-xs px-4 py-1.5 bg-yellow-400 hover:bg-yellow-500 text-yellow-900 font-semibold rounded-lg transition-colors">
                        Buy me a coffee
                    </a>
                </div>
            </div>
        </section>
    </div>

    <!-- RGPD Actions -->
    <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-6 mt-6">
        <h2 class="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-1"><?= t('privacy.gdpr_title') ?></h2>
        <p class="text-xs text-gray-500 dark:text-gray-400 mb-4"><?= t('privacy.gdpr_desc') ?></p>

        <?php if ($gdprType === 'error'): ?>
        <div class="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300 text-sm">
            <?= htmlspecialchars($gdprMessage) ?>
        </div>
        <?php endif; ?>

        <?php if ($gdprData): ?>
        <div class="mb-4">
            <h3 class="text-sm font-medium text-gray-700 dark:text-gray-200 mb-2"><?= t('privacy.data_title') ?></h3>
            <div class="bg-gray-50 dark:bg-gray-700/30 rounded-lg p-4 overflow-x-auto">
                <table class="text-xs w-full">
                    <?php foreach ($gdprData as $key => $val): ?>
                    <tr class="border-b border-gray-200 dark:border-gray-600">
                        <td class="py-1.5 pr-4 font-medium text-gray-500 dark:text-gray-400 whitespace-nowrap"><?= htmlspecialchars($key) ?></td>
                        <td class="py-1.5 text-gray-700 dark:text-gray-300 break-all"><?= htmlspecialchars($val ?? '-') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>
            </div>
        </div>
        <?php endif; ?>

        <form method="POST" class="flex flex-wrap gap-3">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
            <button type="submit" name="request_data"
                    class="text-sm px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">
                <?= t('privacy.btn_request') ?>
            </button>
            <button type="submit" name="delete_data"
                    onclick="return confirm('<?= t('privacy.confirm_delete') ?>')"
                    class="text-sm px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors">
                <?= t('privacy.btn_delete') ?>
            </button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
