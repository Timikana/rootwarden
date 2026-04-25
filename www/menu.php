<?php
/**
 * menu.php - Sidebar de navigation verticale
 * Fixe a gauche sur desktop, drawer sur mobile.
 */
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require_once __DIR__ . '/includes/lang.php';
require_once __DIR__ . '/includes/feature_flags.php';

if (!isset($_SESSION['permissions'])) {
    $_SESSION['permissions'] = defined('DEFAULT_PERMISSIONS') ? DEFAULT_PERMISSIONS : [
        'can_deploy_keys' => 0, 'can_update_linux' => 0, 'can_manage_iptables' => 0,
        'can_admin_portal' => 0, 'can_scan_cve' => 0, 'can_manage_remote_users' => 0,
        'can_manage_platform_key' => 0, 'can_view_compliance' => 0, 'can_manage_backups' => 0,
        'can_schedule_cve' => 0, 'can_manage_fail2ban' => 0, 'can_manage_services' => 0,
        'can_audit_ssh' => 0, 'can_manage_supervision' => 0, 'can_manage_bashrc' => 0,
        'can_manage_graylog' => 0, 'can_manage_wazuh' => 0,
    ];
}

$roleId = (int) ($_SESSION['role_id'] ?? 0);
$_roleLabels = [1 => 'user', 2 => 'admin', 3 => 'superadmin'];
$roleLabel = $_roleLabels[$roleId] ?? 'guest';
$username = htmlspecialchars($_SESSION['username'] ?? 'Anonyme');
$appName = htmlspecialchars(getenv('APP_NAME') ?: 'RootWarden');
$appCompany = htmlspecialchars(getenv('APP_COMPANY') ?: '');
$currentPath = $_SERVER['SCRIPT_NAME'];
$version_file = $_SERVER['DOCUMENT_ROOT'] . '/version.txt';
$version = file_exists($version_file) ? trim(file_get_contents($version_file)) : '';
$perms = $_SESSION['permissions'];
// isSA base sur le role_id numerique (pas sur le string label)
$isSA = ($roleId === 3);
$isAdmin = ($roleId === 2);

$sideLink = function(string $href, string $svg, string $label, string $title = '') use ($currentPath) {
    $active = $currentPath === $href;
    $cls = $active
        ? 'bg-blue-600 dark:bg-blue-700 text-white shadow-sm'
        : 'text-gray-400 hover:bg-gray-800 hover:text-white';
    $titleAttr = $title ? " title=\"$title\"" : '';
    return "<a href=\"$href\"$titleAttr class=\"flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors $cls\">$svg<span class=\"sidebar-label\">$label</span></a>";
};
?>

<!-- Sidebar desktop -->
<aside id="sidebar" class="fixed left-0 top-0 h-full w-56 bg-gray-900 dark:bg-gray-950 border-r border-gray-800 z-50 flex flex-col transition-all duration-200 hidden lg:flex">
    <!-- Logo -->
    <div class="px-4 py-4 border-b border-gray-800">
        <a href="/index.php" class="flex items-center gap-2">
            <span class="text-lg font-extrabold text-white"><?= $appName ?></span>
            <?php if ($version): ?><span class="text-[10px] text-gray-500 font-mono">v<?= $version ?></span><?php endif; ?>
        </a>
        <?php if ($appCompany): ?><div class="text-[10px] text-gray-500 mt-0.5"><?= $appCompany ?></div><?php endif; ?>
    </div>

    <!-- Search -->
    <div class="px-3 py-3">
        <div class="relative">
            <input type="text" id="global-search" placeholder="<?= t('nav.search') ?>"
                   class="w-full text-xs px-3 py-1.5 pl-8 rounded-lg bg-gray-800 text-gray-300 placeholder-gray-500 border border-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                   oninput="globalSearch(this.value)" autocomplete="off">
            <svg class="w-3.5 h-3.5 absolute left-2.5 top-2 text-gray-500 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
            <div id="search-results" class="hidden absolute top-full left-0 mt-1 w-72 max-h-80 overflow-y-auto bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 z-50"></div>
        </div>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 px-3 space-y-1 overflow-y-auto">
        <div class="text-[10px] text-gray-500 uppercase tracking-wider px-3 py-2"><?= t('nav.section_navigation') ?></div>
        <?= $sideLink('/index.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>', t('nav.dashboard'), t('nav.tip_dashboard')) ?>

        <?php if (($perms['can_deploy_keys'] ?? false) || $isSA): ?>
        <?= $sideLink('/ssh/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>', t('nav.ssh_keys'), t('nav.tip_ssh_keys')) ?>
        <?php endif; ?>

        <?php if (($perms['can_update_linux'] ?? false) || $isSA): ?>
        <?= $sideLink('/update/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>', t('nav.updates'), t('nav.tip_updates')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_iptables'] ?? false) || $isSA): ?>
        <?= $sideLink('/iptables/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>', t('nav.iptables'), t('nav.tip_iptables')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_fail2ban'] ?? false) || $isSA): ?>
        <?= $sideLink('/fail2ban/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>', t('nav.fail2ban'), t('nav.tip_fail2ban')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_services'] ?? false) || $isSA): ?>
        <?= $sideLink('/services/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>', t('nav.services'), t('nav.tip_services')) ?>
        <?php endif; ?>

        <?php if (($perms['can_audit_ssh'] ?? false) || $isSA): ?>
        <?= $sideLink('/ssh-audit/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>', t('nav.ssh_audit'), t('nav.tip_ssh_audit')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_supervision'] ?? false) || $isSA): ?>
        <?= $sideLink('/supervision/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>', t('nav.supervision'), t('nav.tip_supervision')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_bashrc'] ?? false) || $isSA): ?>
        <?= $sideLink('/bashrc/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>', t('nav.bashrc'), t('nav.tip_bashrc')) ?>
        <?php endif; ?>

        <?php if (($perms['can_manage_graylog'] ?? false) || $isSA): ?>
        <?= $sideLink('/graylog/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h10M4 18h10"/></svg>', t('nav.graylog'), t('nav.tip_graylog')) ?>
        <?php endif; ?>

        <?php if (feature_enabled('wazuh') && (($perms['can_manage_wazuh'] ?? false) || $isSA)): ?>
        <?= $sideLink('/wazuh/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 2L3 7v6c0 5.25 3.75 9.75 9 11 5.25-1.25 9-5.75 9-11V7l-9-5z"/></svg>', t('nav.wazuh'), t('nav.tip_wazuh')) ?>
        <?php endif; ?>

        <?php if (($perms['can_scan_cve'] ?? false) || $isSA): ?>
        <?= $sideLink('/security/', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>', t('nav.cve_scan'), t('nav.tip_cve_scan')) ?>
        <?php endif; ?>

        <?php
        $hasAdminSection = ($perms['can_admin_portal'] ?? false) || ($perms['can_manage_remote_users'] ?? false) || ($perms['can_manage_platform_key'] ?? false) || ($perms['can_view_compliance'] ?? false) || $isSA;
        if ($hasAdminSection): ?>
        <div class="text-[10px] text-gray-500 uppercase tracking-wider px-3 py-2 mt-3"><?= t('nav.section_admin') ?></div>
        <?php if (($perms['can_admin_portal'] ?? false) || $isSA): ?>
        <?= $sideLink('/adm/admin_page.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>', t('nav.admin'), t('nav.tip_admin')) ?>
        <?php endif; ?>
        <?php if (($perms['can_manage_remote_users'] ?? false) || $isSA): ?>
        <?= $sideLink('/adm/server_users.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>', t('nav.remote_users'), t('nav.tip_remote_users')) ?>
        <?php endif; ?>
        <?php if (($perms['can_manage_platform_key'] ?? false) || $isSA): ?>
        <?= $sideLink('/adm/platform_keys.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>', t('nav.platform_key'), t('nav.tip_platform_key')) ?>
        <?php endif; ?>
        <?php if (($perms['can_view_compliance'] ?? false) || $isSA): ?>
        <?= $sideLink('/security/compliance_report.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>', t('nav.compliance'), t('nav.tip_compliance')) ?>
        <?php endif; ?>
        <?php endif; ?>

        <div class="text-[10px] text-gray-500 uppercase tracking-wider px-3 py-2 mt-3"><?= t('nav.section_other') ?></div>
        <?= $sideLink('/documentation.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>', t('nav.documentation'), t('nav.tip_documentation')) ?>
        <?php if ($isSA): ?>
        <?= $sideLink('/api/docs.php', '<svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>', t('nav.api_docs'), t('nav.tip_api_docs')) ?>
        <?php endif; ?>
    </nav>

    <!-- Notifications bell -->
    <div class="px-3 py-2 border-t border-gray-800 relative" id="notif-wrapper">
        <button onclick="toggleNotifDropdown()" title="<?= t('nav.tip_notifications') ?>" class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-gray-800 hover:text-white transition-colors w-full">
            <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>
            <span class="sidebar-label"><?= t('nav.notifications') ?></span>
            <span id="notif-badge" class="ml-auto text-[10px] px-1.5 py-0.5 rounded-full bg-red-500 text-white font-bold hidden">0</span>
        </button>
        <!-- Dropdown -->
        <div id="notif-dropdown" class="hidden absolute bottom-full left-3 right-3 mb-1 max-h-96 overflow-y-auto bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 z-50">
            <div class="flex items-center justify-between px-3 py-2 border-b border-gray-100 dark:border-gray-700">
                <span class="text-xs font-bold text-gray-700 dark:text-gray-200">Notifications</span>
                <div class="flex gap-1">
                    <button hx-post="/adm/api/notifications.php" hx-vals='{"action":"read_all"}' hx-swap="none"
                            class="text-[10px] text-blue-500 hover:text-blue-700">Tout lire</button>
                    <a href="/notifications.php" class="text-[10px] text-gray-400 hover:text-gray-600 ml-2">Voir tout</a>
                </div>
            </div>
            <div id="notif-list" class="divide-y divide-gray-100 dark:divide-gray-700">
                <div class="px-3 py-4 text-center text-xs text-gray-400">Chargement...</div>
            </div>
        </div>
    </div>

    <!-- User footer -->
    <div class="px-3 py-3 border-t border-gray-800">
        <a href="/profile.php" class="flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-800 transition-colors">
            <div class="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0"><?= strtoupper(substr($username, 0, 1)) ?></div>
            <div class="flex-1 min-w-0">
                <div class="text-sm font-medium text-white truncate"><?= $username ?></div>
                <div class="text-[10px] text-gray-500"><?= $roleLabel ?></div>
            </div>
        </a>
        <div class="flex items-center gap-1 mt-2 px-3">
            <button id="theme-toggle" class="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors" title="Theme">
                <svg id="theme-icon-sun" class="w-3.5 h-3.5 text-yellow-300 hidden" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd"/></svg>
                <svg id="theme-icon-moon" class="w-3.5 h-3.5 text-gray-400 hidden" fill="currentColor" viewBox="0 0 20 20"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/></svg>
            </button>
            <a href="/auth/logout.php" class="flex-1 text-center text-xs text-red-400 hover:text-red-300 hover:bg-red-900/30 px-2 py-1.5 rounded-lg transition-colors"><?= t('nav.logout') ?></a>
        </div>
        <div class="flex items-center gap-1 px-4 py-1">
            <a href="?lang=fr" class="text-xs px-2 py-0.5 rounded <?= getLang()==='fr' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200' ?>">FR</a>
            <a href="?lang=en" class="text-xs px-2 py-0.5 rounded <?= getLang()==='en' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200' ?>">EN</a>
        </div>
    </div>
</aside>

<!-- Top bar mobile -->
<div class="lg:hidden fixed top-0 left-0 right-0 h-12 bg-gray-900 dark:bg-gray-950 border-b border-gray-800 z-50 flex items-center justify-between px-4">
    <button onclick="document.getElementById('mobile-drawer').classList.toggle('-translate-x-full')" class="p-1.5 rounded-lg hover:bg-gray-800">
        <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
    </button>
    <span class="text-sm font-bold text-white"><?= $appName ?></span>
    <a href="/profile.php" class="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold"><?= strtoupper(substr($username, 0, 1)) ?></a>
</div>

<!-- Mobile drawer overlay -->
<div id="mobile-drawer" class="lg:hidden fixed inset-0 z-50 -translate-x-full transition-transform duration-200">
    <div class="absolute inset-0 bg-black/50" onclick="this.parentElement.classList.add('-translate-x-full')"></div>
    <div class="relative w-56 h-full bg-gray-900 overflow-y-auto">
        <div class="px-4 py-4 border-b border-gray-800 flex items-center justify-between">
            <span class="text-lg font-bold text-white"><?= $appName ?></span>
            <button onclick="this.closest('#mobile-drawer').classList.add('-translate-x-full')" class="text-gray-400 hover:text-white">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
        </div>
        <nav class="px-3 py-3 space-y-1">
            <a href="/index.php" title="<?= t('nav.tip_dashboard') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.dashboard') ?></a>
            <?php if (($perms['can_deploy_keys'] ?? false) || $isSA): ?><a href="/ssh/" title="<?= t('nav.tip_ssh_keys') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.ssh_keys') ?></a><?php endif; ?>
            <?php if (($perms['can_update_linux'] ?? false) || $isSA): ?><a href="/update/" title="<?= t('nav.tip_updates') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.updates') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_iptables'] ?? false) || $isSA): ?><a href="/iptables/" title="<?= t('nav.tip_iptables') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.iptables') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_fail2ban'] ?? false) || $isSA): ?><a href="/fail2ban/" title="<?= t('nav.tip_fail2ban') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.fail2ban') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_services'] ?? false) || $isSA): ?><a href="/services/" title="<?= t('nav.tip_services') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.services') ?></a><?php endif; ?>
            <?php if (($perms['can_audit_ssh'] ?? false) || $isSA): ?><a href="/ssh-audit/" title="<?= t('nav.tip_ssh_audit') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.ssh_audit') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_supervision'] ?? false) || $isSA): ?><a href="/supervision/" title="<?= t('nav.tip_supervision') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.supervision') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_bashrc'] ?? false) || $isSA): ?><a href="/bashrc/" title="<?= t('nav.tip_bashrc') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.bashrc') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_graylog'] ?? false) || $isSA): ?><a href="/graylog/" title="<?= t('nav.tip_graylog') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.graylog') ?></a><?php endif; ?>
            <?php if (feature_enabled('wazuh') && (($perms['can_manage_wazuh'] ?? false) || $isSA)): ?><a href="/wazuh/" title="<?= t('nav.tip_wazuh') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.wazuh') ?></a><?php endif; ?>
            <?php if (($perms['can_scan_cve'] ?? false) || $isSA): ?><a href="/security/" title="<?= t('nav.tip_cve_scan') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.cve_scan') ?></a><?php endif; ?>
            <?php if ($hasAdminSection): ?>
            <hr class="border-gray-800 my-2">
            <?php if (($perms['can_admin_portal'] ?? false) || $isSA): ?><a href="/adm/admin_page.php" title="<?= t('nav.tip_admin') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.admin') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_remote_users'] ?? false) || $isSA): ?><a href="/adm/server_users.php" title="<?= t('nav.tip_remote_users') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.remote_users') ?></a><?php endif; ?>
            <?php if (($perms['can_manage_platform_key'] ?? false) || $isSA): ?><a href="/adm/platform_keys.php" title="<?= t('nav.tip_platform_key') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.platform_key') ?></a><?php endif; ?>
            <?php if (($perms['can_view_compliance'] ?? false) || $isSA): ?><a href="/security/compliance_report.php" title="<?= t('nav.tip_compliance') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.compliance') ?></a><?php endif; ?>
            <?php endif; ?>
            <hr class="border-gray-800 my-2">
            <a href="/documentation.php" title="<?= t('nav.tip_documentation') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.documentation') ?></a>
            <a href="/profile.php" title="<?= t('nav.tip_profile') ?>" class="block px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-gray-800"><?= t('nav.profile') ?></a>
            <a href="/auth/logout.php" class="block px-3 py-2 rounded-lg text-sm text-red-400 hover:bg-red-900/30"><?= t('nav.logout') ?></a>
            <div class="flex items-center gap-1 px-3 py-1">
                <a href="?lang=fr" class="text-xs px-2 py-0.5 rounded <?= getLang()==='fr' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200' ?>">FR</a>
                <a href="?lang=en" class="text-xs px-2 py-0.5 rounded <?= getLang()==='en' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200' ?>">EN</a>
            </div>
        </nav>
    </div>
</div>

<!-- Content wrapper : offset pour la sidebar -->
<div class="lg:ml-56 min-h-screen pt-12 lg:pt-0">

<script src="/js/utils.js?v=<?= file_exists(__DIR__ . '/js/utils.js') ? filemtime(__DIR__ . '/js/utils.js') : 1 ?>"></script>
<script>
// Dark mode toggle
(function() {
    const btn = document.getElementById('theme-toggle');
    const sun = document.getElementById('theme-icon-sun');
    const moon = document.getElementById('theme-icon-moon');
    const html = document.documentElement;
    function applyTheme(dark) {
        html.classList.toggle('dark', dark);
        if (sun) sun.classList.toggle('hidden', !dark);
        if (moon) moon.classList.toggle('hidden', dark);
    }
    const saved = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(saved === 'dark' || (!saved && prefersDark));
    if (btn) btn.addEventListener('click', () => {
        const nowDark = !html.classList.contains('dark');
        localStorage.setItem('theme', nowDark ? 'dark' : 'light');
        applyTheme(nowDark);
    });
})();

// Global search
let _searchTimeout;
function globalSearch(query) {
    const container = document.getElementById('search-results');
    if (!container) return;
    clearTimeout(_searchTimeout);
    if (query.length < 2) { container.classList.add('hidden'); return; }
    _searchTimeout = setTimeout(async () => {
        try {
            const r = await fetch('/adm/api/global_search.php?q=' + encodeURIComponent(query));
            const d = await r.json();
            if (!d.results || d.results.length === 0) {
                container.innerHTML = '<div class="p-3 text-xs text-gray-400 text-center">Aucun resultat</div>';
                container.classList.remove('hidden');
                return;
            }
            const icons = {server:'&#128421;', user:'&#128100;', cve:'&#128274;'};
            const colors = {online:'text-green-500', offline:'text-red-400', active:'text-green-500', inactive:'text-gray-400', critical:'text-red-600', high:'text-orange-500', medium:'text-yellow-500'};
            container.innerHTML = d.results.map(r => `
                <a href="${escHtml(r.url)}" class="flex items-center gap-3 px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors border-b border-gray-100 dark:border-gray-700 last:border-0">
                    <span class="text-sm ${colors[r.status] || 'text-gray-400'}">${icons[r.type] || ''}</span>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm font-medium text-gray-800 dark:text-gray-200 truncate">${escHtml(r.label)}</div>
                        <div class="text-[10px] text-gray-400 truncate">${escHtml(r.sub)}</div>
                    </div>
                    <span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-600 text-gray-500 dark:text-gray-400">${escHtml(r.type)}</span>
                </a>
            `).join('');
            container.classList.remove('hidden');
        } catch(e) { container.classList.add('hidden'); }
    }, 250);
}
document.addEventListener('click', e => {
    const sr = document.getElementById('search-results');
    const si = document.getElementById('global-search');
    if (sr && !sr.contains(e.target) && e.target !== si) sr.classList.add('hidden');
    // Fermer le dropdown notifications si clic en dehors
    const nw = document.getElementById('notif-wrapper');
    const nd = document.getElementById('notif-dropdown');
    if (nd && nw && !nw.contains(e.target)) nd.classList.add('hidden');
});

// ── Notifications ────────────────────────────────────────────────
const _notifIcons = {
    cve_critical: '<span class="text-red-500">&#9888;</span>',
    server_offline: '<span class="text-orange-500">&#9679;</span>',
    perm_granted: '<span class="text-blue-500">&#128274;</span>',
    perm_expired: '<span class="text-gray-400">&#128275;</span>',
    password_expiry: '<span class="text-yellow-500">&#128272;</span>',
    info: '<span class="text-blue-400">&#8505;</span>',
};

function refreshNotifBadge() {
    fetch('/adm/api/notifications.php?action=count')
        .then(r => r.json())
        .then(d => {
            const badge = document.getElementById('notif-badge');
            if (!badge) return;
            if (d.count > 0) {
                badge.textContent = d.count > 99 ? '99+' : d.count;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        })
        .catch(() => {});
}

function toggleNotifDropdown() {
    const dd = document.getElementById('notif-dropdown');
    if (!dd) return;
    dd.classList.toggle('hidden');
    if (!dd.classList.contains('hidden')) loadNotifList();
}

function loadNotifList() {
    fetch('/adm/api/notifications.php?action=list&limit=10')
        .then(r => r.json())
        .then(d => {
            const list = document.getElementById('notif-list');
            if (!d.success || !d.notifications.length) {
                list.innerHTML = '<div class="px-3 py-4 text-center text-xs text-gray-400">Aucune notification</div>';
                return;
            }
            list.innerHTML = d.notifications.map(n => {
                const icon = _notifIcons[n.type] || _notifIcons.info;
                const unread = !n.read_at;
                const bg = unread ? 'bg-blue-50 dark:bg-blue-900/20' : '';
                const ago = timeAgo(n.created_at);
                const readBtn = unread
                    ? `<button hx-post="/adm/api/notifications.php" hx-vals='{"action":"read","id":${n.id}}' hx-swap="none" class="text-[10px] text-blue-500 hover:text-blue-700 flex-shrink-0">Lire</button>`
                    : '';
                const link = n.link ? `onclick="window.location='${n.link}'"` : '';
                return `<div class="flex items-start gap-2 px-3 py-2 ${bg} hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer text-xs" ${link}>
                    <span class="text-sm mt-0.5">${icon}</span>
                    <div class="flex-1 min-w-0">
                        <div class="font-medium text-gray-800 dark:text-gray-200 ${unread ? 'font-bold' : ''}">${escHtml(n.title)}</div>
                        <div class="text-gray-500 dark:text-gray-400 truncate">${escHtml(n.message)}</div>
                        <div class="text-gray-400 mt-0.5">${ago}</div>
                    </div>
                    ${readBtn}
                </div>`;
            }).join('');
            if (typeof htmx !== 'undefined') htmx.process(list);
        })
        .catch(() => {});
}

function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function timeAgo(dateStr) {
    const d = new Date(dateStr.replace(' ', 'T') + 'Z');
    const now = new Date();
    const s = Math.floor((now - d) / 1000);
    if (s < 60) return 'maintenant';
    if (s < 3600) return Math.floor(s / 60) + 'min';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    return Math.floor(s / 86400) + 'j';
}

// Refresh badge au chargement + toutes les 60s
refreshNotifBadge();
setInterval(refreshNotifBadge, 60000);

// Ecouter l'event htmx refreshNotifBadge
document.addEventListener('refreshNotifBadge', function(e) {
    const d = e.detail || {};
    const badge = document.getElementById('notif-badge');
    if (badge) {
        if (d.count > 0) { badge.textContent = d.count; badge.classList.remove('hidden'); }
        else { badge.classList.add('hidden'); }
    }
    loadNotifList();
});
</script>
