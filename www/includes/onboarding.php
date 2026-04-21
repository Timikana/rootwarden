<?php
/**
 * onboarding.php - Wizard de setup initial affiche sur le dashboard.
 *
 * S'affiche tant que l'user n'a pas clique "Masquer" (users.onboarding_dismissed_at).
 * Chaque etape est auto-detectee (pas de checkbox manuelle). L'user clique
 * sur le CTA de chaque etape non-completee pour aller a la page concernee.
 *
 * Inclus depuis www/index.php si $_SESSION['role_id'] >= ROLE_ADMIN.
 */

if (!defined('ROLE_ADMIN')) {
    require_once __DIR__ . '/../auth/verify.php';
}

$uid = (int)($_SESSION['user_id'] ?? 0);
if ($uid === 0) return;

try {
    // Check onboarding_dismissed_at. Tolere absence de colonne (migration 042
    // pas encore appliquee) : ne rien afficher dans ce cas.
    $stmt = $pdo->prepare("SELECT onboarding_dismissed_at FROM users WHERE id = ?");
    $stmt->execute([$uid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row === false) return;
    if (!empty($row['onboarding_dismissed_at'])) return;
} catch (\PDOException $e) {
    return;  // colonne absente ou autre, on cache silencieusement
}

// ── Auto-detection des etapes ────────────────────────────────────────────
$steps = [];

// 1. 1er serveur ajoute
$nbMachines = (int)$pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn();
$steps[] = [
    'key'   => 'servers',
    'done'  => $nbMachines > 0,
    'title' => t('onboarding.step_servers_title'),
    'desc'  => t('onboarding.step_servers_desc'),
    'cta'   => t('onboarding.step_servers_cta'),
    'url'   => '/adm/admin_page.php#servers',
];

// 2. Au moins 1 admin hors superadmin initial
$nbAdmins = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role_id IN (2,3) AND active = 1")->fetchColumn();
$steps[] = [
    'key'   => 'users',
    'done'  => $nbAdmins > 1,
    'title' => t('onboarding.step_users_title'),
    'desc'  => t('onboarding.step_users_desc'),
    'cta'   => t('onboarding.step_users_cta'),
    'url'   => '/adm/admin_page.php#users',
];

// 3. 2FA active sur le compte courant
$stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
$stmt->execute([$uid]);
$has2fa = !empty($stmt->fetchColumn());
$steps[] = [
    'key'   => '2fa',
    'done'  => $has2fa,
    'title' => t('onboarding.step_2fa_title'),
    'desc'  => t('onboarding.step_2fa_desc'),
    'cta'   => t('onboarding.step_2fa_cta'),
    'url'   => '/auth/enable_2fa.php',
];

// 4. Keypair plateforme deployee
$nbKeypair = 0;
try {
    $nbKeypair = (int)$pdo->query("SELECT COUNT(*) FROM platform_keypair")->fetchColumn();
} catch (\PDOException $e) {}
$steps[] = [
    'key'   => 'keypair',
    'done'  => $nbKeypair > 0,
    'title' => t('onboarding.step_keypair_title'),
    'desc'  => t('onboarding.step_keypair_desc'),
    'cta'   => t('onboarding.step_keypair_cta'),
    'url'   => '/adm/platform_keys.php',
];

// 5. Mots de passe BDD supprimes (une fois keypair OK)
$nbWithPassword = (int)$pdo->query(
    "SELECT COUNT(*) FROM machines WHERE password IS NOT NULL AND password != ''"
)->fetchColumn();
$steps[] = [
    'key'   => 'remove_passwords',
    'done'  => $nbMachines > 0 && $nbWithPassword === 0,
    'title' => t('onboarding.step_remove_pwd_title'),
    'desc'  => t('onboarding.step_remove_pwd_desc'),
    'cta'   => t('onboarding.step_remove_pwd_cta'),
    'url'   => '/adm/platform_keys.php',
    'warn'  => $nbKeypair === 0,  // deconseille sans keypair
];

// 6. Cle API scopee (non auto-generee)
$nbScoped = 0;
try {
    $nbScoped = (int)$pdo->query(
        "SELECT COUNT(*) FROM api_keys WHERE COALESCE(auto_generated,0)=0 AND revoked_at IS NULL"
    )->fetchColumn();
} catch (\PDOException $e) {}
$steps[] = [
    'key'   => 'api_key',
    'done'  => $nbScoped > 0,
    'title' => t('onboarding.step_api_title'),
    'desc'  => t('onboarding.step_api_desc'),
    'cta'   => t('onboarding.step_api_cta'),
    'url'   => '/adm/api_keys.php',
];

// 7. 1er scan lance
$nbScans = 0;
try {
    $nbScans = (int)$pdo->query("SELECT COUNT(*) FROM ssh_audit_results")->fetchColumn()
             + (int)$pdo->query("SELECT COUNT(*) FROM cve_scans")->fetchColumn();
} catch (\PDOException $e) {}
$steps[] = [
    'key'   => 'first_scan',
    'done'  => $nbScans > 0,
    'title' => t('onboarding.step_scan_title'),
    'desc'  => t('onboarding.step_scan_desc'),
    'cta'   => t('onboarding.step_scan_cta'),
    'url'   => '/ssh-audit/',
];

$nbDone   = count(array_filter($steps, fn($s) => $s['done']));
$nbTotal  = count($steps);
$progress = $nbTotal > 0 ? (int) round(($nbDone / $nbTotal) * 100) : 0;
?>
<div id="onboarding-banner" class="mb-6 bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-blue-200 dark:border-blue-800/50 overflow-hidden">
    <div class="p-5 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between gap-3">
        <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
                <span class="text-lg">🚀</span>
                <h2 class="text-lg font-bold text-gray-800 dark:text-gray-100"><?= t('onboarding.title') ?></h2>
                <span class="ml-auto text-xs px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-semibold">
                    <?= $nbDone ?>/<?= $nbTotal ?>
                </span>
            </div>
            <p class="text-xs text-gray-500 dark:text-gray-400"><?= t('onboarding.subtitle') ?></p>
            <div class="mt-2 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div class="h-full bg-gradient-to-r from-blue-500 to-green-500 transition-all duration-500" style="width:<?= $progress ?>%"></div>
            </div>
        </div>
        <button type="button" onclick="dismissOnboarding()"
                class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700 whitespace-nowrap">
            <?= t('onboarding.dismiss') ?>
        </button>
    </div>

    <ol class="divide-y divide-gray-100 dark:divide-gray-700">
        <?php foreach ($steps as $i => $s): ?>
        <li class="p-4 flex items-start gap-3 <?= $s['done'] ? 'opacity-60' : '' ?>">
            <div class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm <?= $s['done']
                ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                : 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400' ?>">
                <?= $s['done'] ? '✓' : ($i + 1) ?>
            </div>
            <div class="flex-1 min-w-0">
                <div class="font-semibold text-sm <?= $s['done'] ? 'line-through text-gray-500' : 'text-gray-800 dark:text-gray-100' ?>">
                    <?= htmlspecialchars($s['title']) ?>
                    <?php if (!empty($s['warn']) && !$s['done']): ?>
                        <span class="ml-1 text-xs text-amber-600 dark:text-amber-400">⚠ <?= t('onboarding.warn_keypair_first') ?></span>
                    <?php endif; ?>
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-0.5"><?= htmlspecialchars($s['desc']) ?></div>
            </div>
            <?php if (!$s['done']): ?>
                <a href="<?= htmlspecialchars($s['url']) ?>"
                   class="flex-shrink-0 text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white whitespace-nowrap">
                    <?= htmlspecialchars($s['cta']) ?> →
                </a>
            <?php endif; ?>
        </li>
        <?php endforeach; ?>
    </ol>
</div>
<script>
async function dismissOnboarding() {
    try {
        const r = await fetch('/adm/api/dismiss_onboarding.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-TOKEN': '<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>',
            },
        });
        if (r.ok) document.getElementById('onboarding-banner').remove();
    } catch (e) { console.error(e); }
}
</script>
