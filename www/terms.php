<?php
/**
 * terms.php - Conditions Generales d'Utilisation (CGU)
 *
 * @package RootWarden
 */
require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/db.php';

checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accept_terms'])) {
    $_SESSION['terms_accepted'] = true;
    header("Location: index.php");
    exit();
}

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$contactEmail = htmlspecialchars(getenv('SERVER_ADMIN') ?: 'admin@localhost');
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/head.php'; ?>
    <title><?= t('terms.page_title') ?> - <?= $appName ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/menu.php'; ?>

<div class="max-w-4xl mx-auto px-6 py-8">
    <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100 mb-2 text-center"><?= t('terms.page_title') ?></h1>
    <p class="text-xs text-gray-400 text-center mb-6"><?= t('terms.last_updated') ?> 2026-04-11</p>

    <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-8 text-sm leading-relaxed text-gray-600 dark:text-gray-300 space-y-6">

        <!-- 1. Objet -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s1_title') ?></h2>
            <p><?= t('terms.s1_p1') ?></p>
            <p class="mt-2"><?= t('terms.s1_p2') ?></p>
        </section>

        <!-- 2. Acces et authentification -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s2_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('terms.s2_l1') ?></li>
                <li><?= t('terms.s2_l2') ?></li>
                <li><?= t('terms.s2_l3') ?></li>
                <li><?= t('terms.s2_l4') ?></li>
                <li><?= t('terms.s2_l5') ?></li>
            </ul>
        </section>

        <!-- 3. Responsabilites -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s3_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('terms.s3_l1') ?></li>
                <li><?= t('terms.s3_l2') ?></li>
                <li><?= t('terms.s3_l3') ?></li>
                <li><?= t('terms.s3_l4') ?></li>
            </ul>
        </section>

        <!-- 4. Activites interdites -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s4_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('terms.s4_l1') ?></li>
                <li><?= t('terms.s4_l2') ?></li>
                <li><?= t('terms.s4_l3') ?></li>
                <li><?= t('terms.s4_l4') ?></li>
                <li><?= t('terms.s4_l5') ?></li>
            </ul>
        </section>

        <!-- 5. Tracabilite -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s5_title') ?></h2>
            <p><?= t('terms.s5_p1') ?></p>
            <p class="mt-2"><?= t('terms.s5_p2') ?></p>
        </section>

        <!-- 6. Limites -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s6_title') ?></h2>
            <ul class="list-disc pl-6 space-y-1">
                <li><?= t('terms.s6_l1') ?></li>
                <li><?= t('terms.s6_l2') ?></li>
                <li><?= t('terms.s6_l3') ?></li>
            </ul>
        </section>

        <!-- 7. Modifications -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s7_title') ?></h2>
            <p><?= t('terms.s7_p1') ?></p>
        </section>

        <!-- 8. Contact -->
        <section>
            <h2 class="text-base font-semibold text-gray-800 dark:text-gray-100 mb-2"><?= t('terms.s8_title') ?></h2>
            <p><?= t('terms.s8_p1') ?></p>
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

    <div class="text-center mt-6">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
            <button type="submit" name="accept_terms"
                    class="bg-blue-600 hover:bg-blue-700 text-white px-8 py-2.5 rounded-lg font-medium transition-colors">
                <?= t('terms.accept') ?>
            </button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/footer.php'; ?>
</body>
</html>
