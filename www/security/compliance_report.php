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
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
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

// 6. SSH Audit — derniers scores
$sshAuditResults = [];
try {
    $sshAuditResults = $pdo->query("
        SELECT r.machine_id, m.name, m.ip, r.score, r.grade, r.critical_count, r.high_count, r.audited_at
        FROM ssh_audit_results r
        INNER JOIN machines m ON r.machine_id = m.id
        WHERE r.id = (SELECT MAX(r2.id) FROM ssh_audit_results r2 WHERE r2.machine_id = r.machine_id)
        ORDER BY r.score ASC
    ")->fetchAll(PDO::FETCH_ASSOC);
} catch (\Exception $e) {}

// 7. Supervision — agents deployes
$supervisionAgents = [];
try {
    $supervisionAgents = $pdo->query("
        SELECT sa.machine_id, m.name, m.ip, sa.platform, sa.agent_version, sa.config_deployed
        FROM supervision_agents sa
        INNER JOIN machines m ON sa.machine_id = m.id
        ORDER BY m.name, sa.platform
    ")->fetchAll(PDO::FETCH_ASSOC);
} catch (\Exception $e) {}

$nbWithAgent = count(array_unique(array_column($supervisionAgents, 'machine_id')));
$sshAuditAvg = count($sshAuditResults) > 0 ? (int)(array_sum(array_column($sshAuditResults, 'score')) / count($sshAuditResults)) : 0;

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

// ── Export PDF (dompdf) ──────────────────────────────────────────────────
if (isset($_GET['format']) && $_GET['format'] === 'pdf') {
    $dompdfAutoload = __DIR__ . '/../vendor/autoload.php';
    if (!file_exists($dompdfAutoload)) {
        http_response_code(500);
        die('PDF: dependance dompdf manquante. Executez composer install.');
    }
    require_once $dompdfAutoload;

    // Capturer le HTML du rapport
    ob_start();
    // On inclut la meme page en mode "render" pour capturer le HTML
    $_GET['_pdf_render'] = true;
    // On va generer un HTML simplifie pour le PDF
    $pdfHtml = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body { font-family: DejaVu Sans, sans-serif; font-size: 11px; color: #333; margin: 20px; }
        h1 { font-size: 20px; color: #1e40af; margin-bottom: 5px; }
        h2 { font-size: 14px; color: #374151; margin: 15px 0 8px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
        table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 10px; }
        th { background: #f3f4f6; text-align: left; padding: 4px 6px; border: 1px solid #e5e7eb; font-weight: bold; }
        td { padding: 4px 6px; border: 1px solid #e5e7eb; }
        .stat-box { display: inline-block; width: 22%; text-align: center; padding: 8px; margin: 4px 1%; border: 1px solid #e5e7eb; border-radius: 4px; }
        .stat-num { font-size: 18px; font-weight: bold; }
        .critical { color: #dc2626; } .high { color: #ea580c; } .green { color: #16a34a; } .blue { color: #2563eb; }
        .footer { margin-top: 20px; text-align: center; font-size: 9px; color: #9ca3af; }
    </style></head><body>';
    $pdfHtml .= "<h1>{$appName} — Rapport de Conformite</h1>";
    $pdfHtml .= "<p>Genere le {$date} par {$generatedBy}</p>";

    // Resume
    $pdfHtml .= '<h2>Resume</h2>';
    $pdfHtml .= "<div class='stat-box'><div class='stat-num blue'>{$nbServers}</div><div>Serveurs ({$nbOnline} en ligne)</div></div>";
    $pdfHtml .= "<div class='stat-box'><div class='stat-num'>{$nbActive2FA}/{$nbActiveUsers}</div><div>2FA actif</div></div>";
    $pdfHtml .= "<div class='stat-box'><div class='stat-num'>{$nbOldKeys}</div><div>Cles SSH &gt; 90j</div></div>";
    $pdfHtml .= "<div class='stat-box'><div class='stat-num'>" . $remStats['overdue'] . "</div><div>Deadlines depassees</div></div>";

    // Serveurs
    $pdfHtml .= '<h2>Vulnerabilites CVE par serveur</h2><table><tr><th>Serveur</th><th>IP</th><th>Statut</th><th>Env</th><th>CVE</th><th>Crit</th><th>High</th><th>Dernier scan</th></tr>';
    foreach ($servers as $s) {
        $critCls = ($s['critical_count'] ?? 0) > 0 ? ' class="critical"' : '';
        $pdfHtml .= '<tr><td>' . htmlspecialchars($s['name']) . '</td><td>' . htmlspecialchars($s['ip']) . '</td>';
        $pdfHtml .= '<td>' . htmlspecialchars($s['online_status'] ?? '') . '</td><td>' . htmlspecialchars($s['environment'] ?? '') . '</td>';
        $pdfHtml .= '<td>' . ($s['cve_count'] ?? 0) . '</td><td' . $critCls . '>' . ($s['critical_count'] ?? 0) . '</td>';
        $pdfHtml .= '<td>' . ($s['high_count'] ?? 0) . '</td><td>' . ($s['last_scan'] ?? '-') . '</td></tr>';
    }
    $pdfHtml .= '</table>';

    // Utilisateurs
    $pdfHtml .= '<h2>Comptes utilisateurs</h2><table><tr><th>Nom</th><th>Role</th><th>Actif</th><th>2FA</th><th>Cle SSH</th></tr>';
    foreach ($users as $u) {
        $pdfHtml .= '<tr><td>' . htmlspecialchars($u['name']) . '</td><td>' . htmlspecialchars($u['role_name']) . '</td>';
        $pdfHtml .= '<td>' . ($u['active'] ? 'Oui' : 'Non') . '</td>';
        $pdfHtml .= '<td>' . (!empty($u['totp_secret']) ? 'Oui' : 'Non') . '</td>';
        $pdfHtml .= '<td>' . ($u['ssh_key'] ? 'Oui' : 'Non') . '</td></tr>';
    }
    $pdfHtml .= '</table>';

    // SSH Audit
    if (!empty($sshAuditResults)) {
        $pdfHtml .= '<h2>Audit SSH — Scores</h2><table><tr><th>Serveur</th><th>Score</th><th>Note</th><th>Critical</th><th>High</th></tr>';
        foreach ($sshAuditResults as $sa) {
            $pdfHtml .= '<tr><td>' . htmlspecialchars($sa['name']) . '</td><td>' . $sa['score'] . '</td>';
            $pdfHtml .= '<td><strong>' . $sa['grade'] . '</strong></td>';
            $pdfHtml .= '<td>' . ($sa['critical_count'] ?? 0) . '</td><td>' . ($sa['high_count'] ?? 0) . '</td></tr>';
        }
        $pdfHtml .= '</table>';
    }

    // Supervision
    if (!empty($supervisionAgents)) {
        $pdfHtml .= '<h2>Supervision — Agents deployes</h2><table><tr><th>Serveur</th><th>Agents</th></tr>';
        $agByM = [];
        foreach ($supervisionAgents as $a) { $agByM[$a['name']][] = strtoupper(substr($a['platform'],0,1)) . ' ' . ($a['agent_version'] ?? ''); }
        foreach ($agByM as $name => $agents) {
            $pdfHtml .= '<tr><td>' . htmlspecialchars($name) . '</td><td>' . htmlspecialchars(implode(', ', $agents)) . '</td></tr>';
        }
        $pdfHtml .= '</table>';
    }

    $pdfHtml .= "<div class='footer'>SHA-256 : {$reportHash}<br>{$appName} — {$date}</div>";
    $pdfHtml .= '</body></html>';

    $dompdf = new \Dompdf\Dompdf(['isRemoteEnabled' => false, 'defaultFont' => 'sans-serif']);
    $dompdf->loadHtml($pdfHtml);
    $dompdf->setPaper('A4', 'landscape');
    $dompdf->render();
    $dompdf->stream('rapport_conformite_' . date('Y-m-d') . '.pdf', ['Attachment' => true]);
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
            <a href="?format=pdf" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg text-sm font-medium"><?= t('compliance.btn_pdf') ?></a>
            <a href="?format=csv" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg text-sm font-medium"><?= t('compliance.btn_csv') ?></a>
        </div>
    </div>

    <!-- 1. Resume executif -->
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_summary') ?></h2>
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
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
            <div class="text-center p-3 rounded-lg <?= $sshAuditAvg >= 75 ? 'bg-green-50 dark:bg-green-900/20' : ($sshAuditAvg >= 50 ? 'bg-yellow-50 dark:bg-yellow-900/20' : 'bg-red-50 dark:bg-red-900/20') ?>">
                <div class="text-2xl font-bold <?= $sshAuditAvg >= 75 ? 'text-green-600' : ($sshAuditAvg >= 50 ? 'text-yellow-600' : 'text-red-600') ?>"><?= count($sshAuditResults) > 0 ? $sshAuditAvg . '/100' : '—' ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.ssh_audit_avg') ?></div>
            </div>
            <div class="text-center p-3 rounded-lg bg-indigo-50 dark:bg-indigo-900/20">
                <div class="text-2xl font-bold text-indigo-600"><?= $nbWithAgent ?>/<?= $nbServers ?></div>
                <div class="text-xs text-gray-500"><?= t('compliance.supervision_coverage') ?></div>
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

    <!-- 6. SSH Audit -->
    <?php if (!empty($sshAuditResults)): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6 print-break">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_ssh_audit') ?></h2>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_server') ?></th>
                        <th class="px-3 py-2"><?= t('compliance.th_score') ?></th>
                        <th class="px-3 py-2"><?= t('compliance.th_grade') ?></th>
                        <th class="px-3 py-2">Critical</th>
                        <th class="px-3 py-2">High</th>
                        <th class="px-3 py-2"><?= t('compliance.th_date') ?></th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($sshAuditResults as $sa):
                        $gradeColor = match($sa['grade']) { 'A' => 'text-green-600', 'B' => 'text-blue-600', 'C' => 'text-yellow-600', default => 'text-red-600' };
                    ?>
                    <tr>
                        <td class="px-3 py-2 font-medium"><?= htmlspecialchars($sa['name']) ?> <span class="text-xs text-gray-400 font-mono"><?= htmlspecialchars($sa['ip']) ?></span></td>
                        <td class="px-3 py-2 text-center font-bold"><?= $sa['score'] ?></td>
                        <td class="px-3 py-2 text-center font-extrabold text-lg <?= $gradeColor ?>"><?= $sa['grade'] ?></td>
                        <td class="px-3 py-2 text-center <?= ($sa['critical_count'] ?? 0) > 0 ? 'text-red-600 font-bold' : '' ?>"><?= $sa['critical_count'] ?? 0 ?></td>
                        <td class="px-3 py-2 text-center <?= ($sa['high_count'] ?? 0) > 0 ? 'text-orange-500 font-bold' : '' ?>"><?= $sa['high_count'] ?? 0 ?></td>
                        <td class="px-3 py-2 text-center text-xs text-gray-400"><?= $sa['audited_at'] ? date('d/m/Y H:i', strtotime($sa['audited_at'])) : '—' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>

    <!-- 7. Supervision agents -->
    <?php if (!empty($supervisionAgents)): ?>
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
        <h2 class="text-lg font-bold text-gray-800 dark:text-gray-200 mb-4"><?= t('compliance.section_supervision') ?></h2>
        <?php
        $badgeColors = [
            'zabbix' => 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
            'centreon' => 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
            'prometheus' => 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
            'telegraf' => 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
        ];
        $agentsByMachine = [];
        foreach ($supervisionAgents as $a) { $agentsByMachine[$a['machine_id']]['name'] = $a['name']; $agentsByMachine[$a['machine_id']]['ip'] = $a['ip']; $agentsByMachine[$a['machine_id']]['agents'][] = $a; }
        ?>
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500">
                    <tr>
                        <th class="px-3 py-2 text-left"><?= t('compliance.th_server') ?></th>
                        <th class="px-3 py-2">Agents</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
                    <?php foreach ($agentsByMachine as $mid => $info): ?>
                    <tr>
                        <td class="px-3 py-2 font-medium"><?= htmlspecialchars($info['name']) ?> <span class="text-xs text-gray-400 font-mono"><?= htmlspecialchars($info['ip']) ?></span></td>
                        <td class="px-3 py-2">
                            <div class="flex flex-wrap gap-1">
                                <?php foreach ($info['agents'] as $ag): ?>
                                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold <?= $badgeColors[$ag['platform']] ?? 'bg-gray-100 text-gray-600' ?>">
                                    <?= strtoupper(substr($ag['platform'], 0, 1)) ?> <?= htmlspecialchars($ag['agent_version'] ?? '') ?>
                                    <?= $ag['config_deployed'] ? '' : ' <span class="text-[9px] opacity-60">(no cfg)</span>' ?>
                                </span>
                                <?php endforeach; ?>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
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
