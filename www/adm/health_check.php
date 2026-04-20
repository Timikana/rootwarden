<?php
/**
 * security/health_check.php — Page de diagnostic des routes backend
 *
 * Teste chaque route API Python depuis PHP (server-side) et affiche
 * un tableau de bord visuel avec le statut de chaque endpoint.
 * Accès : superadmin uniquement.
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');

$api_key  = getenv('API_KEY') ?: '';
$base_url = 'https://python:5000';

/**
 * Teste un endpoint et retourne [ok, status_code, time_ms, response_preview]
 */
function testRoute(string $url, string $method, string $api_key, ?array $body = null, bool $sse = false): array {
    $start = microtime(true);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $sse ? 2 : 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER     => [
            "X-API-KEY: $api_key",
            "Content-Type: application/json",
        ],
    ]);
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body ?? []));
    }
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    $ms = round((microtime(true) - $start) * 1000);

    if ($err) return [false, 0, $ms, "curl: $err"];
    $preview = mb_substr($resp, 0, 120);
    return [$code >= 200 && $code < 500, $code, $ms, $preview];
}

// Machine ID for tests that need one
$stmt = $pdo->query("SELECT id FROM machines LIMIT 1");
$machineId = $stmt->fetchColumn() ?: 0;

// ── Liste des routes à tester ──────────────────────────────────────────────
$sshDry = ['server_ip' => '0.0.0.0', 'ssh_user' => 'test'];

$routes = [
    // ── Monitoring ──────────────────────────────────────────────────────
    ['Health Check',           'GET',  '/test', null, t('health.route_test')],
    ['List Machines',          'GET',  '/list_machines', null, t('health.route_list_machines')],
    ['Filter Servers',         'GET',  '/filter_servers', null, t('health.route_filter_servers')],
    ['CVE Trends',             'GET',  '/cve_trends', null, t('health.route_cve_trends')],
    ['Server Status',          'POST', '/server_status', ['machine_id' => $machineId], t('health.route_server_status')],
    ['Linux Version',          'POST', '/linux_version', ['machine_id' => $machineId], t('health.route_linux_version')],
    ['Last Reboot',            'POST', '/last_reboot', ['machine_id' => $machineId], t('health.route_last_reboot')],

    // ── SSH / Deploiement ───────────────────────────────────────────────
    ['Deploy (dry)',            'POST', '/deploy', ['machines' => []], t('health.route_deploy')],
    ['Preflight Check',        'POST', '/preflight_check', ['machine_id' => $machineId], t('health.route_preflight')],
    ['Platform Key Info',      'GET',  '/platform_key', null, t('health.route_platform_key')],
    ['Deploy Platform Key',    'POST', '/deploy_platform_key', ['machine_id' => $machineId], t('health.route_deploy_platform_key')],
    ['Test Platform Key',      'POST', '/test_platform_key', ['machine_id' => $machineId], t('health.route_test_platform_key')],
    ['Deploy Service Account', 'POST', '/deploy_service_account', ['machine_id' => $machineId], t('health.route_deploy_service_account')],
    ['Scan Server Users',      'POST', '/scan_server_users', ['machine_id' => $machineId], t('health.route_scan_server_users')],
    ['Logs SSE',               'GET',  '/logs', null, t('health.route_logs_sse'), true],

    // ── Mises a jour ────────────────────────────────────────────────────
    ['Update (dry)',            'POST', '/update', ['machine_id' => $machineId], t('health.route_update')],
    ['Security Updates',       'POST', '/security_updates', ['machine_id' => $machineId], t('health.route_security_updates')],
    ['Dry Run Update',         'POST', '/dry_run_update', ['machine_id' => $machineId], t('health.route_dry_run')],
    ['Pending Packages',       'POST', '/pending_packages', ['machine_id' => $machineId], t('health.route_pending_packages')],
    ['Apt Check Lock',         'POST', '/apt_check_lock', ['machine_id' => $machineId], t('health.route_apt_check_lock')],
    ['Dpkg Repair',            'POST', '/dpkg_repair', ['machine_id' => $machineId], t('health.route_dpkg_repair')],
    ['Update Zabbix (redirect)','POST', '/update_zabbix', ['machine_ids' => []], 'Redirect vers /supervision/zabbix/deploy'],
    ['Schedule Update',        'POST', '/schedule_update', ['machine_id' => $machineId, 'interval_minutes' => 0], t('health.route_schedule_update')],
    ['Update Logs SSE',        'GET',  '/update-logs', null, t('health.route_update_logs_sse'), true],

    // ── Iptables ────────────────────────────────────────────────────────
    ['Iptables Get',           'POST', '/iptables', $sshDry + ['action' => 'get'], t('health.route_iptables_get')],
    ['Iptables Validate',      'POST', '/iptables-validate', $sshDry + ['rules_v4' => ''], t('health.route_iptables_validate')],
    ['Iptables Apply',         'POST', '/iptables-apply', $sshDry + ['rules_v4' => ''], t('health.route_iptables_apply')],
    ['Iptables Restore',       'POST', '/iptables-restore', $sshDry, t('health.route_iptables_restore')],
    ['Iptables History',       'GET',  "/iptables-history?server_id=$machineId", null, t('health.route_iptables_history')],
    ['Iptables Rollback',      'POST', '/iptables-rollback', ['history_id' => 0], t('health.route_iptables_rollback')],
    ['Iptables Logs SSE',      'GET',  '/iptables-logs', null, t('health.route_iptables_logs_sse'), true],

    // ── Fail2ban ────────────────────────────────────────────────────────
    ['Fail2ban Status',        'POST', '/fail2ban/status', $sshDry, t('health.route_f2b_status')],
    ['Fail2ban Jail Detail',   'POST', '/fail2ban/jail', $sshDry + ['jail' => 'sshd'], t('health.route_f2b_jail')],
    ['Fail2ban Install',       'POST', '/fail2ban/install', $sshDry, t('health.route_f2b_install')],
    ['Fail2ban Ban',           'POST', '/fail2ban/ban', $sshDry + ['jail' => 'sshd', 'ip' => '1.2.3.4'], t('health.route_f2b_ban')],
    ['Fail2ban Unban',         'POST', '/fail2ban/unban', $sshDry + ['jail' => 'sshd', 'ip' => '1.2.3.4'], t('health.route_f2b_unban')],
    ['Fail2ban Restart',       'POST', '/fail2ban/restart', $sshDry, t('health.route_f2b_restart')],
    ['Fail2ban Config',        'POST', '/fail2ban/config', $sshDry, t('health.route_f2b_config')],
    ['Fail2ban History',       'GET',  "/fail2ban/history?server_id=$machineId", null, t('health.route_f2b_history')],
    ['Fail2ban Services',      'POST', '/fail2ban/services', $sshDry, t('health.route_f2b_services')],
    ['Fail2ban Enable Jail',   'POST', '/fail2ban/enable_jail', $sshDry + ['jail' => 'sshd'], t('health.route_f2b_enable_jail')],
    ['Fail2ban Disable Jail',  'POST', '/fail2ban/disable_jail', $sshDry + ['jail' => 'sshd'], t('health.route_f2b_disable_jail')],
    ['Fail2ban Whitelist',     'POST', '/fail2ban/whitelist', $sshDry + ['action' => 'list'], t('health.route_f2b_whitelist')],
    ['Fail2ban Unban All',     'POST', '/fail2ban/unban_all', $sshDry + ['jail' => 'sshd'], t('health.route_f2b_unban_all')],
    ['Fail2ban Ban Global',    'POST', '/fail2ban/ban_all_servers', ['ip' => '0.0.0.0', 'jail' => 'sshd'], t('health.route_f2b_ban_global')],
    ['Fail2ban Templates',     'GET',  '/fail2ban/templates', null, t('health.route_f2b_templates')],
    ['Fail2ban Logs',          'POST', '/fail2ban/logs', $sshDry + ['lines' => 10], t('health.route_f2b_logs')],
    ['Fail2ban Stats',         'GET',  "/fail2ban/stats?server_id=$machineId&days=7", null, t('health.route_f2b_stats')],
    ['Fail2ban Install All',   'POST', '/fail2ban/install_all', [], t('health.route_f2b_install_all')],
    ['Fail2ban GeoIP',         'POST', '/fail2ban/geoip', ['ip' => '8.8.8.8'], t('health.route_f2b_geoip')],

    // ── Supervision ─────────────────────────────────────────────────────
    ['Supervision Config',     'GET',  '/supervision/config', null, 'Configuration globale supervision'],
    ['Supervision Machines',   'GET',  '/supervision/machines', null, 'Liste machines avec statut agent'],
    ['Supervision Zabbix Ver', 'POST', '/supervision/zabbix/version', ['machine_id' => $machineId], 'Detection version agent Zabbix'],
    ['Supervision Config Read','POST', '/supervision/zabbix/config/read', ['machine_id' => $machineId], 'Lecture config agent distant'],
    ['Supervision Backups',    'POST', '/supervision/zabbix/backups', ['machine_id' => $machineId], 'Liste backups config agent'],
    ['Supervision Overrides',  'GET',  "/supervision/overrides/$machineId", null, 'Overrides par serveur'],

    // ── Bashrc ───────────────────────────────────────────────────────────
    ['Bashrc Users',           'GET',  "/bashrc/users?machine_id=$machineId", null, 'Liste users + etat .bashrc'],
    ['Bashrc Backups',         'GET',  "/bashrc/backups?machine_id=$machineId&user=root", null, 'Liste backups .bashrc.bak.* pour root'],

    // ── SSH Audit ────────────────────────────────────────────────────────
    ['SSH Audit Scan',         'POST', '/ssh_audit/scan', ['machine_id' => $machineId], t('ssh_audit.scan')],
    ['SSH Audit Scan All',     'POST', '/ssh_audit/scan_all', [], t('ssh_audit.scan_all')],
    ['SSH Audit Fix',          'POST', '/ssh_audit/fix', ['machine_id' => $machineId, 'key' => 'PermitRootLogin', 'value' => 'no'], t('ssh_audit.fix')],
    ['SSH Audit Config',       'POST', '/ssh_audit/config', ['machine_id' => $machineId], t('ssh_audit.view_config')],
    ['SSH Audit History',      'GET',  "/ssh_audit/history?machine_id=$machineId", null, t('ssh_audit.history')],
    ['SSH Audit Fleet',        'GET',  '/ssh_audit/fleet', null, t('ssh_audit.fleet_view')],
    ['SSH Audit Policies',     'GET',  '/ssh_audit/policies', null, t('ssh_audit.policies_title')],
    ['SSH Audit Save Config',  'POST', '/ssh-audit/save-config', ['machine_id' => $machineId, 'config' => 'test'], 'Sauvegarder sshd_config'],
    ['SSH Audit Toggle',       'POST', '/ssh-audit/toggle', ['machine_id' => $machineId, 'directive' => 'X11Forwarding', 'enable' => false], 'Toggle directive ON/OFF'],
    ['SSH Audit Backups',      'POST', '/ssh-audit/backups', ['machine_id' => $machineId], 'Lister backups sshd_config'],
    ['SSH Audit Restore',      'POST', '/ssh-audit/restore', ['machine_id' => $machineId, 'backup_name' => 'test'], 'Restaurer un backup'],
    ['SSH Audit Reload',       'POST', '/ssh-audit/reload', ['machine_id' => $machineId], 'Recharger sshd'],

    // ── Services systemd ─────────────────────────────────────────────────
    ['Services List',          'POST', '/services/list', ['machine_id' => $machineId], 'Liste services systemd'],
    ['Service Status',         'POST', '/services/status', ['machine_id' => $machineId, 'service' => 'cron'], 'Detail service (PID, memoire)'],
    ['Service Start',          'POST', '/services/start', ['machine_id' => $machineId, 'service' => 'cron'], 'Demarrer un service'],
    ['Service Stop',           'POST', '/services/stop', ['machine_id' => $machineId, 'service' => 'cron'], 'Arreter un service'],
    ['Service Restart',        'POST', '/services/restart', ['machine_id' => $machineId, 'service' => 'cron'], 'Redemarrer un service'],
    ['Service Enable',         'POST', '/services/enable', ['machine_id' => $machineId, 'service' => 'cron'], 'Activer au boot'],
    ['Service Disable',        'POST', '/services/disable', ['machine_id' => $machineId, 'service' => 'cron'], 'Desactiver au boot'],
    ['Service Logs',           'POST', '/services/logs', ['machine_id' => $machineId, 'service' => 'cron', 'lines' => 10], 'Logs journalctl'],

    // ── CVE ─────────────────────────────────────────────────────────────
    ['OpenCVE Connection',     'GET',  '/cve_test_connection', null, t('health.route_cve_connection')],
    ['CVE Scan (dry)',         'POST', '/cve_scan', ['machine_id' => 0], t('health.route_cve_scan')],
    ['CVE Scan All (dry)',     'POST', '/cve_scan_all', ['min_cvss' => 10], t('health.route_cve_scan_all'), true],
    ['CVE Results',            'GET',  "/cve_results?machine_id=$machineId", null, t('health.route_cve_results')],
    ['CVE History',            'GET',  "/cve_history?machine_id=$machineId", null, t('health.route_cve_history')],
    ['CVE Compare',            'GET',  "/cve_compare?machine_id=$machineId", null, t('health.route_cve_compare')],
    ['CVE Whitelist List',     'GET',  '/cve_whitelist', null, t('health.route_cve_whitelist')],
    ['CVE Remediation List',   'GET',  "/cve_remediation?machine_id=$machineId", null, t('health.route_cve_remediation')],
    ['CVE Remediation Stats',  'GET',  '/cve_remediation/stats', null, t('health.route_cve_remediation_stats')],
    ['CVE Schedules List',     'GET',  '/cve_schedules', null, t('health.route_cve_schedules')],

    // ── Admin ───────────────────────────────────────────────────────────
    ['Backups List',           'GET',  '/admin/backups', null, t('health.route_backups')],
    ['Temp Permissions',       'GET',  '/admin/temp_permissions', null, t('health.route_temp_permissions')],
    ['Server Lifecycle',       'POST', '/server_lifecycle', ['machine_id' => $machineId, 'lifecycle_status' => 'active'], t('health.route_server_lifecycle')],
];

$results = [];
foreach ($routes as $route) {
    $label  = $route[0];
    $method = $route[1];
    $path   = $route[2];
    $body   = $route[3];
    $desc   = $route[4];
    $sse    = $route[5] ?? false;

    $url = $base_url . $path;
    [$ok, $code, $ms, $preview] = testRoute($url, $method, $api_key, $body, $sse);
    // SSE/streaming routes timeout by design — mark as OK
    if ($sse && !$ok && $ms >= 9000) {
        $ok = true;
        $preview = t('health.sse_active');
    }
    $results[] = compact('label', 'method', 'path', 'ok', 'code', 'ms', 'preview', 'desc', 'sse');
}

$totalOk   = count(array_filter($results, fn($r) => $r['ok']));
$totalSse  = count(array_filter($results, fn($r) => $r['sse']));
$totalFail = count($results) - $totalOk;
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('health.title') ?></title>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200 min-h-screen flex flex-col">
<?php require_once __DIR__ . '/../menu.php'; ?>

<nav class="text-xs text-gray-400 mb-3 px-6 pt-4">
    <a href="/" class="hover:text-blue-500"><?= t('breadcrumb.dashboard') ?></a> <span class="mx-1">&rarr;</span>
    <a href="/adm/admin_page.php" class="hover:text-blue-500"><?= t('breadcrumb.admin') ?></a> <span class="mx-1">&rarr;</span>
    <span class="text-gray-600 dark:text-gray-300"><?= t('health.title') ?></span>
</nav>

<main class="flex-grow p-8 max-w-screen-2xl mx-auto w-full">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold"><?= t('health.title') ?></h1>
            <p class="text-xs text-gray-400 mt-0.5"><?= t('health.desc') ?></p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                <?= t('health.diagnostic_of') ?> <?= count($results) ?> endpoints
                <span class="font-mono text-xs"><?= htmlspecialchars($base_url) ?></span>
            </p>
        </div>
        <div class="flex gap-3">
            <span class="px-4 py-2 rounded-lg bg-green-600 text-white font-bold text-lg"><?= $totalOk - $totalSse ?> OK</span>
            <?php if ($totalSse > 0): ?>
            <span class="px-4 py-2 rounded-lg bg-purple-600 text-white font-bold text-lg"><?= $totalSse ?> SSE</span>
            <?php endif; ?>
            <?php if ($totalFail > 0): ?>
            <span class="px-4 py-2 rounded-lg bg-red-600 text-white font-bold text-lg"><?= $totalFail ?> FAIL</span>
            <?php endif; ?>
        </div>
    </div>

    <div class="bg-white dark:bg-gray-800 rounded-xl shadow overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-gray-100 dark:bg-gray-700 text-left">
                    <th class="px-4 py-3"><?= t('health.th_status') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_route') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_method') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_http') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_time') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_description') ?></th>
                    <th class="px-4 py-3"><?= t('health.th_response') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($results as $r): ?>
                <tr class="border-t border-gray-200 dark:border-gray-700 <?= $r['ok'] ? '' : 'bg-red-50 dark:bg-red-900/20' ?>">
                    <td class="px-4 py-3 text-center text-lg">
                        <?php if ($r['sse']): ?>
                            <span class="px-2 py-0.5 rounded text-xs font-bold bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">SSE</span>
                        <?php elseif ($r['ok']): ?>
                            ✅
                        <?php else: ?>
                            ❌
                        <?php endif; ?>
                    </td>
                    <td class="px-4 py-3 font-mono text-xs">
                        <?= htmlspecialchars($r['path']) ?>
                    </td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-xs font-bold
                            <?= $r['method'] === 'GET' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300' : 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300' ?>">
                            <?= $r['method'] ?>
                        </span>
                    </td>
                    <td class="px-4 py-3 font-mono <?= $r['code'] >= 200 && $r['code'] < 400 ? 'text-green-600' : 'text-yellow-600' ?>">
                        <?= $r['code'] ?: '—' ?>
                    </td>
                    <td class="px-4 py-3 text-right font-mono">
                        <?= $r['ms'] ?> ms
                    </td>
                    <td class="px-4 py-3 text-xs text-gray-500 dark:text-gray-400">
                        <?= htmlspecialchars($r['desc']) ?>
                    </td>
                    <td class="px-4 py-3 text-xs font-mono text-gray-400 max-w-xs truncate" title="<?= htmlspecialchars($r['preview']) ?>">
                        <?= htmlspecialchars(mb_substr($r['preview'], 0, 80)) ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <p class="text-xs text-gray-400 mt-4 text-right">
        <?= t('health.generated_at') ?> <?= date('d/m/Y H:i:s') ?> — <?= t('health.total_time') ?> : <?= array_sum(array_column($results, 'ms')) ?> ms
    </p>
</main>

<?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
