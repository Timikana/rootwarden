<?php
/**
 * groups/index.php - Groupes de machines (dynamiques / statiques) + actions de masse.
 *
 * Un groupe regroupe des serveurs par regle dynamique (filtre environnement /
 * criticite / reseau / cycle de vie / tags) ou par liste statique. On y declenche
 * des operations de masse (scan de derive, scan CVE) suivies dans le centre de taches.
 *
 * Permissions : admin (2) / superadmin (3) + can_admin_portal.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../includes/lang.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

// Liste des machines (pour les groupes statiques) + tags distincts (suggestions)
$machines = [];
$tags = [];
try {
    $stmt = $pdo->query("SELECT id, name, environment, criticality FROM machines ORDER BY name");
    $machines = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $tstmt = $pdo->query("SELECT DISTINCT tag FROM machine_tags ORDER BY tag");
    $tags = array_column($tstmt->fetchAll(PDO::FETCH_ASSOC), 'tag');
} catch (Throwable $e) { /* tables presentes apres migration 055 */ }
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('groups.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <div class="mb-6 flex items-start justify-between gap-4 flex-wrap">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('groups.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('groups.desc') ?></p>
            </div>
            <button id="new-group-btn"
                    class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded-lg transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                <span><?= t('groups.btn_new') ?></span>
            </button>
        </div>

        <!-- Formulaire de creation (masque par defaut) -->
        <div id="group-form" class="hidden bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6 space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('groups.f_name') ?></label>
                    <input id="g-name" type="text" maxlength="100" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('groups.f_desc') ?></label>
                    <input id="g-desc" type="text" maxlength="255" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                </div>
            </div>

            <div class="flex gap-4 text-sm">
                <label class="inline-flex items-center gap-2"><input type="radio" name="g-type" value="dynamic" checked> <?= t('groups.type_dynamic') ?></label>
                <label class="inline-flex items-center gap-2"><input type="radio" name="g-type" value="static"> <?= t('groups.type_static') ?></label>
            </div>

            <!-- Filtres dynamiques -->
            <div id="g-dynamic" class="space-y-3">
                <p class="text-xs text-gray-400"><?= t('groups.dynamic_hint') ?></p>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                        <div class="font-medium text-xs text-gray-500 mb-1"><?= t('groups.f_environment') ?></div>
                        <?php foreach (['PROD','DEV','TEST','OTHER'] as $v): ?>
                        <label class="block"><input type="checkbox" class="gf" data-col="environment" value="<?= $v ?>"> <?= $v ?></label>
                        <?php endforeach; ?>
                    </div>
                    <div>
                        <div class="font-medium text-xs text-gray-500 mb-1"><?= t('groups.f_criticality') ?></div>
                        <?php foreach (['CRITIQUE','NON CRITIQUE'] as $v): ?>
                        <label class="block"><input type="checkbox" class="gf" data-col="criticality" value="<?= $v ?>"> <?= $v ?></label>
                        <?php endforeach; ?>
                    </div>
                    <div>
                        <div class="font-medium text-xs text-gray-500 mb-1"><?= t('groups.f_network') ?></div>
                        <?php foreach (['INTERNE','EXTERNE'] as $v): ?>
                        <label class="block"><input type="checkbox" class="gf" data-col="network_type" value="<?= $v ?>"> <?= $v ?></label>
                        <?php endforeach; ?>
                    </div>
                    <div>
                        <div class="font-medium text-xs text-gray-500 mb-1"><?= t('groups.f_lifecycle') ?></div>
                        <?php foreach (['active','retiring','archived'] as $v): ?>
                        <label class="block"><input type="checkbox" class="gf" data-col="lifecycle_status" value="<?= $v ?>"> <?= $v ?></label>
                        <?php endforeach; ?>
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-medium text-gray-500 mb-1"><?= t('groups.f_tags') ?></label>
                    <input id="g-tags" type="text" placeholder="<?= t('groups.tags_placeholder') ?>" class="w-full sm:w-96 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    <?php if ($tags): ?><div class="text-[11px] text-gray-400 mt-1"><?= t('groups.tags_known') ?> : <?= htmlspecialchars(implode(', ', $tags)) ?></div><?php endif; ?>
                </div>
            </div>

            <!-- Membres statiques -->
            <div id="g-static" class="hidden">
                <div class="font-medium text-xs text-gray-500 mb-1"><?= t('groups.f_members') ?></div>
                <div class="max-h-48 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg p-2 grid grid-cols-1 sm:grid-cols-2 gap-1 text-sm">
                    <?php foreach ($machines as $m): ?>
                    <label class="block"><input type="checkbox" class="gm" value="<?= (int)$m['id'] ?>"> <?= htmlspecialchars($m['name']) ?>
                        <span class="text-[10px] text-gray-400"><?= htmlspecialchars($m['environment'] ?? '') ?></span></label>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="flex gap-2">
                <button id="g-save" class="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-2 rounded-lg"><?= t('groups.btn_save') ?></button>
                <button id="g-cancel" class="bg-gray-200 dark:bg-gray-700 text-sm px-4 py-2 rounded-lg"><?= t('groups.btn_cancel') ?></button>
            </div>
        </div>

        <!-- Liste des groupes -->
        <div id="groups-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div class="col-span-full text-center text-gray-400 py-8"><?= t('groups.loading') ?></div>
        </div>
    </div>

    <?php require_once __DIR__ . '/../footer.php'; ?>
    <script src="/groups/js/main.js?v=<?= @filemtime(__DIR__ . '/js/main.js') ?>"></script>
</body>
</html>
