<?php
/**
 * index.php — Page d'accueil post-authentification (portail principal)
 *
 * Rôle       : Point d'entrée principal après connexion. Affiche un message de
 *              bienvenue personnalisé et un raccourci vers la documentation.
 *              La navigation conditionnelle (SSH, iptables, admin…) est gérée
 *              dans menu.php en fonction des permissions stockées en session.
 *
 * Dépendances :
 *   - auth/verify.php   : checkAuth() — vérifie l'authentification et les rôles
 *   - auth/functions.php: initializeUserSession() — réhydrate la session depuis BDD
 *   - db.php            : $pdo — connexion PDO MySQL
 *   - head.php          : balises <head> communes (Tailwind CDN, variables JS)
 *   - menu.php          : barre de navigation sticky avec liens conditionnels
 *   - footer.php        : pied de page avec logos et liens légaux
 *
 * Permissions requises : rôles 1 (user), 2 (admin), 3 (superadmin)
 *
 * Flux :
 *   1. Vérification de l'authentification (checkAuth)
 *   2. Redirection vers login si username absent de la session
 *   3. Restauration de session via cookie "remember_token" si user_id absent
 *   4. Affichage de la page d'accueil avec nom d'utilisateur et rôle
 */

require_once __DIR__ . '/auth/verify.php';
require_once __DIR__ . '/auth/functions.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/includes/lang.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Vérifie que l'utilisateur a l'un des rôles autorisés (1=user, 2=admin, 3=superadmin)
checkAuth(['1','2', '3']);

// Sécurité : si le username n'est plus en session, renvoyer vers le login
if (!isset($_SESSION['username'])) {
    header("Location: auth/login.php");
    exit();
}

// ── Restauration de session via cookie "Se souvenir de moi" ──────────────────
// Ce bloc s'exécute uniquement si user_id est absent (session expirée) mais
// qu'un cookie remember_token valide est présent.
if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_token'])) {
    // Le cookie est au format "user_id:token_en_clair"
    list($user_id, $token) = explode(':', $_COOKIE['remember_token']);

    // Récupère le hash stocké en BDD pour ce user_id, uniquement si non expiré
    $stmt = $pdo->prepare("SELECT token_hash FROM remember_tokens WHERE user_id = ? AND expires_at > NOW()");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    // Vérifie le token en clair contre le hash bcrypt stocké
    if ($result && password_verify($token, $result['token_hash'])) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Réhydrate toutes les variables de session (permissions, rôle, etc.)
            initializeUserSession($user);
        }
    }
}

// Échappement des données de session avant affichage (prévention XSS)
$username = htmlspecialchars($_SESSION['username']);
$roleNames = [1 => t('dashboard.role_user'), 2 => t('dashboard.role_admin'), 3 => t('dashboard.role_super')];
$roleName = htmlspecialchars($roleNames[(int)($_SESSION['role_id'] ?? 0)] ?? 'Inconnu');
$roleId = (int)($_SESSION['role_id'] ?? 0);

// ── Stats rapides pour le dashboard ─────────────────────────────────────────
$nbMachines = $pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn();
$nbUsers    = $pdo->query("SELECT COUNT(*) FROM users WHERE active = 1")->fetchColumn();
$nbOnline   = $pdo->query("SELECT COUNT(*) FROM machines WHERE online_status = 'Online'")->fetchColumn();
$lastScan   = $pdo->query("SELECT scan_date FROM cve_scans ORDER BY scan_date DESC LIMIT 1")->fetchColumn();
$lastCveCount = $pdo->query("SELECT cve_count FROM cve_scans ORDER BY scan_date DESC LIMIT 1")->fetchColumn();
$permissions = $_SESSION['permissions'] ?? [];
$nbKeypair = 0;
try { $nbKeypair = (int)$pdo->query("SELECT COUNT(*) FROM machines WHERE platform_key_deployed = 1")->fetchColumn(); } catch (\Exception $e) {}

// Alertes sécurité
$alerts = [];

// Users sans 2FA
$no2fa = $pdo->query("SELECT COUNT(*) FROM users WHERE active = 1 AND (totp_secret IS NULL OR totp_secret = '')")->fetchColumn();
if ($no2fa > 0) $alerts[] = ['type' => 'warning', 'msg' => t('dashboard.alert_no_2fa', ['count' => $no2fa])];

// Users sans clé SSH
$noKey = $pdo->query("SELECT COUNT(*) FROM users WHERE active = 1 AND (ssh_key IS NULL OR ssh_key = '')")->fetchColumn();
if ($noKey > 0) $alerts[] = ['type' => 'info', 'msg' => t('dashboard.alert_no_key', ['count' => $noKey])];

// Serveurs offline
$nbOffline = $pdo->query("SELECT COUNT(*) FROM machines WHERE online_status != 'ONLINE'")->fetchColumn();
if ($nbOffline > 0) $alerts[] = ['type' => 'error', 'msg' => t('dashboard.alert_offline', ['count' => $nbOffline])];

// CVE critiques non résolues
$critCves = $pdo->query("
    SELECT SUM(s.critical_count) FROM cve_scans s
    INNER JOIN (SELECT machine_id, MAX(id) as last_id FROM cve_scans WHERE status='completed' GROUP BY machine_id) latest ON s.id = latest.last_id
")->fetchColumn();
if ($critCves > 0) $alerts[] = ['type' => 'error', 'msg' => t('dashboard.alert_cve_crit', ['count' => $critCves])];

// Dernière MàJ il y a plus de 30 jours
$oldUpdate = $pdo->query("SELECT COUNT(*) FROM machines WHERE last_checked IS NOT NULL AND last_checked < DATE_SUB(NOW(), INTERVAL 30 DAY)")->fetchColumn();
if ($oldUpdate > 0) $alerts[] = ['type' => 'warning', 'msg' => t('dashboard.alert_old_check', ['count' => $oldUpdate])];

// Serveurs encore en auth password (pas de keypair)
try {
    $nbPasswordAuth = $pdo->query("SELECT COUNT(*) FROM machines WHERE platform_key_deployed = 0 OR platform_key_deployed IS NULL")->fetchColumn();
    if ($nbPasswordAuth > 0) $alerts[] = ['type' => 'warning', 'msg' => t('dashboard.alert_password', ['count' => $nbPasswordAuth]), 'link' => '/adm/platform_keys.php'];
} catch (\Exception $e) {}

// Clés SSH anciennes (> 90 jours) — avec noms pour l'alerte actionnable
$oldKeysStmt = $pdo->query("SELECT name, DATEDIFF(NOW(), ssh_key_updated_at) as age_days FROM users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key != '' AND ssh_key_updated_at IS NOT NULL AND ssh_key_updated_at < DATE_SUB(NOW(), INTERVAL 90 DAY) ORDER BY ssh_key_updated_at LIMIT 5");
$oldKeysData = $oldKeysStmt->fetchAll(PDO::FETCH_ASSOC);
$oldKeys = count($oldKeysData);
if ($oldKeys > 0) {
    $names = implode(', ', array_map(fn($u) => $u['name'] . ' (' . $u['age_days'] . 'j)', $oldKeysData));
    $alerts[] = ['type' => 'error', 'msg' => t('dashboard.alert_old_keys', ['count' => $oldKeys]) . " : $names", 'link' => '/adm/admin_page.php#tab-users'];
}

// Fail2ban alerts (calculees apres le query dashboard)
// Seront evaluees plus bas apres les queries fail2ban_status
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once 'head.php'; ?>
    <title>Portail Principal</title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200 min-h-screen flex flex-col">
    <?php require_once 'menu.php'; ?>

    <main class="flex-grow p-8 max-w-screen-2xl mx-auto w-full">
        <!-- ── En-tête + alertes ──────────────────────────────────────── -->
        <div class="flex items-center justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('dashboard.greeting', ['name' => $username]) ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= $roleName ?></p>
            </div>
            <?php if (!empty($alerts)): ?>
            <span class="text-xs px-2 py-1 rounded-full bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 font-medium"><?= count($alerts) ?> <?= getLang() === 'en' ? (count($alerts) > 1 ? 'alerts' : 'alert') : (count($alerts) > 1 ? 'alertes' : 'alerte') ?></span>
            <?php endif; ?>
        </div>

        <?php if (!empty($alerts)): ?>
        <div class="bg-white dark:bg-gray-800 shadow-sm rounded-xl p-4 mb-6">
            <div class="space-y-1.5">
                <?php foreach ($alerts as $a):
                    $cls = match($a['type']) {
                        'error'   => 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
                        'warning' => 'text-yellow-700 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800',
                        default   => 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800',
                    };
                    $icon = match($a['type']) {
                        'error'   => '&#10007;',
                        'warning' => '&#9888;',
                        default   => '&#8505;',
                    };
                ?>
                <<?= isset($a['link']) ? 'a href="' . htmlspecialchars($a['link']) . '"' : 'div' ?> title="<?= htmlspecialchars($a['msg']) ?>" class="flex items-center gap-2 text-xs px-3 py-2 rounded-lg border <?= $cls ?> <?= isset($a['link']) ? 'hover:opacity-80 transition-opacity' : '' ?>">
                    <span><?= $icon ?></span>
                    <span><?= htmlspecialchars($a['msg']) ?></span>
                    <?php if (isset($a['link'])): ?><span class="ml-auto text-[10px] opacity-60"><?= getLang() === 'en' ? 'View' : 'Voir' ?> &rarr;</span><?php endif; ?>
                </<?= isset($a['link']) ? 'a' : 'div' ?>>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- ── Cartes statistiques ────────────────────────────────────── -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center" title="<?= t('dashboard.tip_servers') ?>">
                <div class="text-2xl font-bold text-blue-600 dark:text-blue-400"><?= $nbOnline ?><span class="text-sm font-normal text-gray-400">/<?= $nbMachines ?></span></div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= t('dashboard.servers_online') ?></div>
                <?php if ($nbKeypair < $nbMachines): ?><div class="text-[10px] text-orange-400 mt-0.5"><?= $nbKeypair ?>/<?= $nbMachines ?> keypair</div><?php endif; ?>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center" title="<?= t('dashboard.tip_users') ?>">
                <div class="text-2xl font-bold text-purple-600 dark:text-purple-400"><?= $nbUsers ?></div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= t('dashboard.users_active') ?></div>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center" title="<?= t('dashboard.tip_cve') ?>">
                <div class="text-2xl font-bold <?= ($lastCveCount ?? 0) > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' ?>"><?= $lastCveCount ?? '—' ?></div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= t('dashboard.cve_detected') ?></div>
                <?php if ($lastScan): ?><div class="text-[10px] text-gray-400 mt-0.5">Scan <?= date('d/m H:i', strtotime($lastScan)) ?></div><?php endif; ?>
            </div>
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center" title="<?= t('dashboard.tip_remed') ?>">
                <?php
                $remTotal = ($remStats['open'] ?? 0) + ($remStats['in_progress'] ?? 0);
                ?>
                <div class="text-2xl font-bold <?= $remTotal > 0 ? 'text-orange-500' : 'text-green-600 dark:text-green-400' ?>"><?= $remTotal ?></div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= t('dashboard.remediations') ?></div>
                <?php if ($remStats['overdue'] ?? 0 > 0): ?><div class="text-[10px] text-red-500 mt-0.5"><?= $remStats['overdue'] ?> <?= t('dashboard.overdue') ?></div><?php endif; ?>
            </div>
        </div>

        <?php
        // Fail2ban stats (dashboard widget)
        $f2bBanned = 0;
        $f2bMissing = 0;
        try {
            $f2bBanned = (int) $pdo->query("SELECT COALESCE(SUM(total_banned), 0) FROM fail2ban_status WHERE running = 1")->fetchColumn();
            $f2bMissing = (int) $pdo->query("SELECT COUNT(*) FROM machines m LEFT JOIN fail2ban_status f ON m.id = f.server_id WHERE (f.installed IS NULL OR f.installed = 0) AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')")->fetchColumn();
        } catch (\Exception $e) {}
        ?>

        <?php
        // Stats de remediation (utilisees dans la stat card)
        $remStats = ['open' => 0, 'in_progress' => 0, 'resolved' => 0, 'overdue' => 0];
        if ($roleId >= 2) {
            try {
                $rs = $pdo->query("SELECT status, COUNT(*) as cnt FROM cve_remediation GROUP BY status");
                foreach ($rs->fetchAll(PDO::FETCH_ASSOC) as $r) $remStats[$r['status']] = $r['cnt'];
                $remStats['overdue'] = (int)$pdo->query("SELECT COUNT(*) FROM cve_remediation WHERE deadline < CURDATE() AND status IN ('open','in_progress')")->fetchColumn();
            } catch (\Exception $e) {}
        }
        ?>

        <!-- ── Tendances CVE (30 derniers jours) ─────────────────────── -->
        <?php if ($roleId >= 2): ?>
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-5 mb-6" id="cve-trends-card">
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('dashboard.cve_trends') ?></h2>
                <span id="trend-summary" class="text-xs text-gray-400"></span>
            </div>
            <div class="flex items-end gap-px h-16" id="trend-bars">
                <div class="text-xs text-gray-400 flex items-center justify-center w-full h-full"><?= t('common.loading') ?></div>
            </div>
            <div class="flex justify-between text-[10px] text-gray-400 mt-1">
                <span id="trend-start"></span>
                <span id="trend-end"></span>
            </div>
        </div>
        <script>
        (async function loadTrends() {
            try {
                const r = await fetch(`${window.API_URL}/cve_trends`);
                const d = await r.json();
                if (!d.success || !d.trends.length) {
                    document.getElementById('trend-bars').innerHTML = '<span class="text-xs text-gray-400 flex items-center justify-center w-full">' + (window.LANG === 'en' ? 'No scan data' : 'Pas de donnees de scan') + '</span>';
                    return;
                }
                const trends = d.trends;
                const maxVal = Math.max(...trends.map(t => t.total), 1);
                const barsEl = document.getElementById('trend-bars');
                barsEl.innerHTML = '';

                // Remplir les jours manquants pour avoir 30 barres
                const dayMap = {};
                trends.forEach(t => { dayMap[t.day] = t; });
                const bars = [];
                const today = new Date();
                for (let i = 29; i >= 0; i--) {
                    const d = new Date(today);
                    d.setDate(d.getDate() - i);
                    const key = d.toISOString().split('T')[0];
                    bars.push(dayMap[key] || {day: key, total: 0, critical: 0, high: 0, medium: 0});
                }

                bars.forEach(t => {
                    const pct = Math.max((t.total / maxVal) * 100, 2);
                    const bar = document.createElement('div');
                    bar.className = 'flex-1 rounded-t cursor-pointer transition-all hover:opacity-80';
                    bar.style.height = pct + '%';
                    bar.title = `${t.day}: ${t.total} CVE (${t.critical} crit, ${t.high} high)`;
                    if (t.critical > 0) bar.className += ' bg-red-500';
                    else if (t.high > 0) bar.className += ' bg-orange-400';
                    else if (t.total > 0) bar.className += ' bg-yellow-400';
                    else bar.className += ' bg-gray-200 dark:bg-gray-700';
                    barsEl.appendChild(bar);
                });

                document.getElementById('trend-start').textContent = bars[0].day.slice(5);
                document.getElementById('trend-end').textContent = bars[bars.length-1].day.slice(5);

                // Calcul tendance
                const first = bars.slice(0, 7).reduce((s, t) => s + t.total, 0);
                const last = bars.slice(-7).reduce((s, t) => s + t.total, 0);
                const diff = last - first;
                const arrow = diff > 0 ? '\u2191' : diff < 0 ? '\u2193' : '\u2192';
                const color = diff > 0 ? 'text-red-500' : diff < 0 ? 'text-green-500' : 'text-gray-400';
                document.getElementById('trend-summary').innerHTML = `<span class="${color}">${arrow} ${Math.abs(diff)} CVE</span> ` + (window.LANG === 'en' ? 'vs previous week' : 'vs semaine precedente');
            } catch(e) {
                console.error('loadTrends:', e);
            }
        })();
        </script>
        <?php endif; ?>

        <!-- ── Accès rapides ──────────────────────────────────────────── -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 mb-6">
            <?php
            $shortcuts = [];
            if ($permissions['can_deploy_keys'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/ssh/ssh_management.php', 'label' => t('dashboard.sc_ssh_keys'), 'desc' => t('dashboard.sc_ssh_desc')];
            if ($permissions['can_update_linux'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/update/linux_updates.php', 'label' => t('dashboard.sc_updates'), 'desc' => t('dashboard.sc_updates_desc')];
            if ($permissions['can_manage_iptables'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/iptables/iptables_manager.php', 'label' => t('dashboard.sc_iptables'), 'desc' => t('dashboard.sc_iptables_desc')];
            if ($permissions['can_scan_cve'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/security/cve_scan.php', 'label' => t('dashboard.sc_cve'), 'desc' => t('dashboard.sc_cve_desc')];
            if ($permissions['can_admin_portal'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/adm/admin_page.php', 'label' => t('dashboard.sc_admin'), 'desc' => t('dashboard.sc_admin_desc')];
            if ($permissions['can_view_compliance'] ?? false || $roleId >= 3)
                $shortcuts[] = ['url' => '/security/compliance_report.php', 'label' => t('dashboard.sc_compliance'), 'desc' => t('dashboard.sc_compliance_desc')];
            $shortcuts[] = ['url' => '/documentation.php', 'label' => t('dashboard.sc_docs'), 'desc' => t('dashboard.sc_docs_desc')];
            foreach ($shortcuts as $sc): ?>
            <a href="<?= $sc['url'] ?>" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 hover:ring-2 hover:ring-blue-400 hover:shadow-md transition-all group">
                <div class="text-sm font-semibold text-gray-800 dark:text-gray-200 group-hover:text-blue-500"><?= $sc['label'] ?></div>
                <p class="text-xs text-gray-400 mt-0.5"><?= $sc['desc'] ?></p>
            </a>
            <?php endforeach; ?>
        </div>

        <?php if ($roleId >= 2):
            // Récupère tous les serveurs avec leur dernier scan CVE
            $serversStmt = $pdo->query("
                SELECT m.id, m.name, m.ip, m.port, m.online_status, m.linux_version, m.environment, m.criticality, m.last_checked,
                       m.platform_key_deployed,
                       s.cve_count, s.critical_count, s.high_count, s.scan_date
                FROM machines m
                LEFT JOIN (
                    SELECT s1.* FROM cve_scans s1
                    INNER JOIN (SELECT machine_id, MAX(id) as last_id FROM cve_scans WHERE status='completed' GROUP BY machine_id) s2
                    ON s1.id = s2.last_id
                ) s ON m.id = s.machine_id
                ORDER BY m.name
            ");
            $servers = $serversStmt->fetchAll(PDO::FETCH_ASSOC);
        ?>
        <?php if (!empty($servers)): ?>
        <!-- ── Etat du parc ──────────────────────────────────────── -->
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
            <div class="px-4 py-3 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('dashboard.park_status') ?></h2>
                <span class="text-xs text-gray-400"><?= count($servers) ?> <?= getLang() === 'en' ? (count($servers) > 1 ? 'servers' : 'server') : (count($servers) > 1 ? 'serveurs' : 'serveur') ?></span>
            </div>
            <div class="divide-y divide-gray-100 dark:divide-gray-700">
                <?php foreach ($servers as $srv):
                    $isOnline = strtolower($srv['online_status'] ?? '') === 'online';
                    $hasCrit = ($srv['critical_count'] ?? 0) > 0;
                    $hasHigh = ($srv['high_count'] ?? 0) > 0;
                ?>
                <div class="flex items-center gap-4 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors">
                    <span class="w-2 h-2 rounded-full flex-shrink-0 <?= $isOnline ? 'bg-green-500' : 'bg-red-500' ?>"></span>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <span class="text-sm font-medium text-gray-800 dark:text-gray-200 truncate"><?= htmlspecialchars($srv['name']) ?></span>
                            <span class="text-xs text-gray-400 font-mono"><?= htmlspecialchars($srv['ip']) ?></span>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500"><?= htmlspecialchars($srv['environment'] ?? '') ?></span>
                            <?php if ($srv['platform_key_deployed'] ?? false): ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-green-100 dark:bg-green-900/40 text-green-600 dark:text-green-400">keypair</span>
                            <?php endif; ?>
                        </div>
                        <div class="text-xs text-gray-400 mt-0.5">
                            <?= htmlspecialchars($srv['linux_version'] ?? t('dashboard.version_unknown')) ?>
                            <?php if ($srv['last_checked']): ?> · <?= getLang() === 'en' ? 'Checked' : 'Verifie' ?> <?= date('d/m H:i', strtotime($srv['last_checked'])) ?><?php endif; ?>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 flex-shrink-0">
                        <?php if ($hasCrit): ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-red-600 text-white font-bold"><?= $srv['critical_count'] ?> CRIT</span>
                        <?php endif; ?>
                        <?php if ($hasHigh): ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500 text-white font-bold"><?= $srv['high_count'] ?> HIGH</span>
                        <?php endif; ?>
                        <?php if ($srv['cve_count'] && !$hasCrit && !$hasHigh): ?>
                            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-yellow-500 text-white"><?= $srv['cve_count'] ?> CVE</span>
                        <?php endif; ?>
                        <?php if (!$srv['cve_count'] && !$srv['scan_date']): ?>
                            <span class="text-[10px] text-gray-400"><?= t('dashboard.not_scanned') ?></span>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
        <?php endif; ?>
    </main>

    <?php if ($roleId >= 2): ?>
    <script>
    // Auto-refresh des statuts serveurs toutes les 60s
    (function autoRefreshStatus() {
        const REFRESH_INTERVAL = 60000;
        async function refreshStatus() {
            try {
                const r = await fetch(`${window.API_URL}/list_machines`);
                const d = await r.json();
                if (!d.success && !Array.isArray(d)) return;
                const machines = d.machines || d;
                machines.forEach(m => {
                    // Trouver le dot de statut dans le tableau "Etat du parc"
                    const rows = document.querySelectorAll('[class*="flex items-center gap-4 px-4 py-3"]');
                    rows.forEach(row => {
                        const ipEl = row.querySelector('.font-mono');
                        if (ipEl && ipEl.textContent.trim() === m.ip) {
                            const dot = row.querySelector('.rounded-full');
                            if (dot) {
                                const isOnline = (m.online_status || '').toLowerCase() === 'online';
                                dot.className = dot.className.replace(/bg-(green|red|gray)-500/g, '');
                                dot.classList.add(isOnline ? 'bg-green-500' : 'bg-red-500');
                            }
                        }
                    });
                });
            } catch(e) { /* silently fail */ }
        }
        setInterval(refreshStatus, REFRESH_INTERVAL);
    })();
    </script>
    <?php endif; ?>

    <?php require_once 'footer.php'; ?>
</body>
</html>
