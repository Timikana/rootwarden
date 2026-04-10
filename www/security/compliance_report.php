<?php
/**
 * compliance_report.php — Rapport de conformite securite du parc
 *
 * Genere un rapport complet HTML (imprimable) ou CSV couvrant :
 * - Etat des vulnerabilites CVE
 * - Etat des cles SSH (age, rotation)
 * - Authentification (2FA, mots de passe)
 * - Pare-feu (derniere modification)
 * - Mises a jour (derniere MaJ par serveur)
 * - Remediation (Open/In Progress/Resolved)
 *
 * Acces : admin (2) et superadmin (3)
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../db.php';

if (session_status() === PHP_SESSION_NONE) session_start();
checkAuth([1, 2, 3]);
checkPermission('can_view_compliance');

$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$generatedBy = htmlspecialchars($_SESSION['username'] ?? 'admin');
$date = date('d/m/Y H:i');

// ── Collecte des donnees ──────────────────────────────────────────────────

// 1. Serveurs
$servers = $pdo->query("SELECT m.*,
    (SELECT scan_date FROM cve_scans WHERE machine_id = m.id AND status='completed' ORDER BY scan_date DESC LIMIT 1) as last_scan,
    (SELECT cve_count FROM cve_scans WHERE machine_id = m.id AND status='completed' ORDER BY scan_date DESC LIMIT 1) as cve_count,
    (SELECT critical_count FROM cve_scans WHERE machine_id = m.id AND status='completed' ORDER BY scan_date DESC LIMIT 1) as critical_count,
    (SELECT high_count FROM cve_scans WHERE machine_id = m.id AND status='completed' ORDER BY scan_date DESC LIMIT 1) as high_count
    FROM machines m ORDER BY m.name")->fetchAll(PDO::FETCH_ASSOC);

// 2. Utilisateurs
$users = $pdo->query("SELECT u.name, u.email, u.active, u.sudo, u.ssh_key, u.ssh_key_updated_at, u.totp_secret, u.password_updated_at, u.created_at, r.name as role_name
    FROM users u JOIN roles r ON u.role_id = r.id ORDER BY u.name")->fetchAll(PDO::FETCH_ASSOC);

// 3. Remediation stats
$remStats = ['open' => 0, 'in_progress' => 0, 'resolved' => 0, 'accepted' => 0, 'wont_fix' => 0, 'overdue' => 0];
try {
    $rs = $pdo->query("SELECT status, COUNT(*) as cnt FROM cve_remediation GROUP BY status");
    foreach ($rs->fetchAll(PDO::FETCH_ASSOC) as $r) $remStats[$r['status']] = $r['cnt'];
    $remStats['overdue'] = (int)$pdo->query("SELECT COUNT(*) FROM cve_remediation WHERE deadline < CURDATE() AND status IN ('open','in_progress')")->fetchColumn();
} catch (\Exception $e) {}

// 4. Iptables - dernieres modifications
$iptHistory = [];
try {
    $iptHistory = $pdo->query("SELECT h.server_id, m.name, h.changed_by, h.created_at FROM iptables_history h JOIN machines m ON h.server_id = m.id ORDER BY h.created_at DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
} catch (\Exception $e) {}

// 5. Stats globales
$nbServers = count($servers);
$nbOnline = count(array_filter($servers, fn($s) => strtolower($s['online_status'] ?? '') === 'online'));
$nbUsers = count($users);
$nbActive2FA = count(array_filter($users, fn($u) => !empty($u['totp_secret']) && $u['active']));
$nbActiveUsers = count(array_filter($users, fn($u) => $u['active']));
$nbOldKeys = count(array_filter($users, fn($u) => $u['active'] && $u['ssh_key'] && $u['ssh_key_updated_at'] && strtotime($u['ssh_key_updated_at']) < strtotime('-90 days')));

// Hash du rapport pour preuve d'integrite
$reportData = json_encode(compact('servers', 'users', 'remStats', 'date'));
$reportHash = hash('sha256', $reportData);

// ── Export CSV ────────────────────────────────────────────────────────────
if (isset($_GET['format']) && $_GET['format'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="rapport_conformite_' . date('Y-m-d') . '.csv"');
    $out = fopen('php://output', 'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF)); // BOM UTF-8
    fputcsv($out, ['Rapport de conformite - ' . $appName . ' - ' . $date]);
    fputcsv($out, []);
    fputcsv($out, ['=== RESUME ===']);
    fputcsv($out, ['Serveurs', $nbServers, 'En ligne', $nbOnline]);
    fputcsv($out, ['Utilisateurs actifs', $nbActiveUsers, '2FA actif', $nbActive2FA]);
    fputcsv($out, ['Cles SSH > 90j', $nbOldKeys]);
    fputcsv($out, []);
    fputcsv($out, ['=== SERVEURS ===']);
    fputcsv($out, ['Nom', 'IP', 'Statut', 'Environnement', 'CVE Total', 'CVE Critical', 'CVE High', 'Dernier scan', 'Derniere MaJ']);
    foreach ($servers as $s) {
        fputcsv($out, [$s['name'], $s['ip'], $s['online_status'] ?? '', $s['environment'] ?? '', $s['cve_count'] ?? 0, $s['critical_count'] ?? 0, $s['high_count'] ?? 0, $s['last_scan'] ?? '', $s['last_checked'] ?? '']);
    }
    fputcsv($out, []);
    fputcsv($out, ['=== UTILISATEURS ===']);
    fputcsv($out, ['Nom', 'Role', 'Actif', '2FA', 'Cle SSH', 'Age cle (jours)', 'Dernier MdP']);
    foreach ($users as $u) {
        $keyAge = ($u['ssh_key'] && $u['ssh_key_updated_at']) ? (int)((time() - strtotime($u['ssh_key_updated_at'])) / 86400) : '';
        fputcsv($out, [$u['name'], $u['role_name'], $u['active'] ? 'Oui' : 'Non', !empty($u['totp_secret']) ? 'Oui' : 'Non', $u['ssh_key'] ? 'Oui' : 'Non', $keyAge, $u['password_updated_at'] ?? '']);
    }
    fputcsv($out, []);
    fputcsv($out, ['SHA-256', $reportHash]);
    fclose($out);
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title>Rapport de conformite — <?= $appName ?></title>
    <style>
        @media print {
            nav, .no-print, #toast-container { display: none !important; }
            body { background: white !important; color: black !important; }
            .print-break { page-break-before: always; }
        }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">
<?php require_once __DIR__ . '/../menu.php'; ?>

<div class="px-6 py-6 max-w-screen-xl mx-auto">

    <!-- En-tete -->
    <div class="bg-gradient-to-r from-blue-600 to-blue-800 text-white rounded-xl p-6 mb-6 flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold"><?= t('compliance.title') ?></h1>
            <p class="text-xs text-blue-100/70 mt-0.5"><?= t('compliance.desc') ?></p>
            <p class="text-blue-200 text-sm mt-1"><?= $appName ?> — <?= t('compliance.generated_by') ?> <?= $date ?> — <?= $generatedBy ?></p>
        </div>
        <div class="flex gap-2 no-print">
            <button onclick="window.print()" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg text-sm font-medium"><?= t('compliance.btn_print') ?></button>
            <a href="?format=csv" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg text-sm font-medium"><?= t('compliance.btn_csv') ?></a>
        </div>
    </div>

    <!-- 1. Resume executif -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_summary') ?></h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div class="text-center p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20">
                <div class="text-2xl font-bold text-blue-600"><?= $nbServers ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.servers') ?> (<?= $nbOnline ?> <?= t('compliance.online') ?>)</div>
            </div>
            <div class="text-center p-3 rounded-lg <?= $nbActive2FA < $nbActiveUsers ? 'bg-red-50 dark:bg-red-900/20' : 'bg-green-50 dark:bg-green-900/20' ?>">
                <div class="text-2xl font-bold <?= $nbActive2FA < $nbActiveUsers ? 'text-red-600' : 'text-green-600' ?>"><?= $nbActive2FA ?>/<?= $nbActiveUsers ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.2fa_active') ?></div>
            </div>
            <div class="text-center p-3 rounded-lg <?= $nbOldKeys > 0 ? 'bg-yellow-50 dark:bg-yellow-900/20' : 'bg-green-50 dark:bg-green-900/20' ?>">
                <div class="text-2xl font-bold <?= $nbOldKeys > 0 ? 'text-yellow-600' : 'text-green-600' ?>"><?= $nbOldKeys ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.old_ssh_keys') ?></div>
            </div>
            <div class="text-center p-3 rounded-lg <?= $remStats['overdue'] > 0 ? 'bg-red-50 dark:bg-red-900/20' : 'bg-green-50 dark:bg-green-900/20' ?>">
                <div class="text-2xl font-bold <?= $remStats['overdue'] > 0 ? 'text-red-600' : 'text-green-600' ?>"><?= $remStats['overdue'] ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.overdue_deadlines') ?></div>
            </div>
        </div>
    </div>

    <!-- 2. Vulnerabilites CVE -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_cve') ?></h2>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_server') ?></th>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_ip') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_critical') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_high') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_total') ?></th>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_last_scan') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($servers as $s): ?>
                    <tr>
                        <td class="px-3 py-2 font-medium"><?= htmlspecialchars($s['name']) ?></td>
                        <td class="px-3 py-2 font-mono text-xs text-gray-500"><?= htmlspecialchars($s['ip']) ?></td>
                        <td class="px-3 py-2 text-center <?= ($s['critical_count'] ?? 0) > 0 ? 'text-red-600 font-bold' : 'text-gray-400' ?>"><?= $s['critical_count'] ?? 0 ?></td>
                        <td class="px-3 py-2 text-center <?= ($s['high_count'] ?? 0) > 0 ? 'text-orange-500 font-bold' : 'text-gray-400' ?>"><?= $s['high_count'] ?? 0 ?></td>
                        <td class="px-3 py-2 text-center"><?= $s['cve_count'] ?? 0 ?></td>
                        <td class="px-3 py-2 text-xs text-gray-400"><?= $s['last_scan'] ? date('d/m/Y H:i', strtotime($s['last_scan'])) : t('compliance.never') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 3. Remediation -->
    <?php if (array_sum($remStats) > 0): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_remediation') ?></h2>
        <div class="grid grid-cols-5 gap-3 text-center">
            <div class="p-3 rounded-lg bg-red-50 dark:bg-red-900/20"><div class="text-xl font-bold text-red-600"><?= $remStats['open'] ?></div><div class="text-[10px] text-gray-500"><?= t('compliance.rem_open') ?></div></div>
            <div class="p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20"><div class="text-xl font-bold text-yellow-600"><?= $remStats['in_progress'] ?></div><div class="text-[10px] text-gray-500"><?= t('compliance.rem_in_progress') ?></div></div>
            <div class="p-3 rounded-lg bg-green-50 dark:bg-green-900/20"><div class="text-xl font-bold text-green-600"><?= $remStats['resolved'] ?></div><div class="text-[10px] text-gray-500"><?= t('compliance.rem_resolved') ?></div></div>
            <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-700"><div class="text-xl font-bold text-gray-600"><?= $remStats['accepted'] ?></div><div class="text-[10px] text-gray-500"><?= t('compliance.rem_accepted') ?></div></div>
            <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-700"><div class="text-xl font-bold text-gray-600"><?= $remStats['wont_fix'] ?></div><div class="text-[10px] text-gray-500"><?= t('compliance.rem_wont_fix') ?></div></div>
        </div>
    </div>
    <?php endif; ?>

    <!-- 4. Authentification -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6 print-break">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_auth') ?></h2>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_user') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_role') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_2fa') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_ssh_key') ?></th>
                        <th class="px-3 py-2 text-center"><?= t('compliance.th_key_age') ?></th>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_last_pwd') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($users as $u):
                        if (!$u['active']) continue;
                        $keyAge = ($u['ssh_key'] && $u['ssh_key_updated_at']) ? (int)((time() - strtotime($u['ssh_key_updated_at'])) / 86400) : null;
                    ?>
                    <tr>
                        <td class="px-3 py-2 font-medium"><?= htmlspecialchars($u['name']) ?></td>
                        <td class="px-3 py-2 text-center text-xs"><?= htmlspecialchars($u['role_name']) ?></td>
                        <td class="px-3 py-2 text-center"><?= !empty($u['totp_secret']) ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-red-500">&#10007;</span>' ?></td>
                        <td class="px-3 py-2 text-center"><?= $u['ssh_key'] ? '<span class="text-green-500">&#10003;</span>' : '<span class="text-gray-400">—</span>' ?></td>
                        <td class="px-3 py-2 text-center text-xs <?= $keyAge !== null && $keyAge > 90 ? 'text-red-600 font-bold' : 'text-gray-500' ?>"><?= $keyAge !== null ? "{$keyAge}j" : '—' ?></td>
                        <td class="px-3 py-2 text-xs text-gray-400"><?= $u['password_updated_at'] ? date('d/m/Y', strtotime($u['password_updated_at'])) : '—' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 5. Pare-feu -->
    <?php if (!empty($iptHistory)): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_firewall') ?></h2>
        <div class="space-y-1">
            <?php foreach ($iptHistory as $h): ?>
            <div class="flex items-center gap-3 text-sm px-3 py-1.5 rounded bg-gray-50 dark:bg-gray-700/30">
                <span class="text-xs text-gray-400 font-mono"><?= date('d/m/Y H:i', strtotime($h['created_at'])) ?></span>
                <span class="font-medium"><?= htmlspecialchars($h['name']) ?></span>
                <span class="text-xs text-gray-500"><?= t('compliance.by') ?> <?= htmlspecialchars($h['changed_by'] ?? 'admin') ?></span>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Footer avec hash -->
    <div class="text-center text-xs text-gray-400 mb-8">
        <p><?= t('compliance.footer_generated') ?> <?= $date ?> — <?= $appName ?></p>
        <p class="font-mono mt-1">SHA-256 : <?= $reportHash ?></p>
    </div>
</div>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
