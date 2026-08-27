<?php

/**
 * Menu labels — English.
 *
 * Taken from the legacy frontend on 2026-08-18 and GENERATED, not retyped.
 * Strict parity with lang/fr/nav.php: same key set, same commit. A missing key
 * does not fail — it prints its own identifier on screen.
 */
return [
    // Sections

    // Navigation
    // NAV-001 : cinq sections, dans l'ordre de la sequence operationnelle.
    // `section_navigation` et `section_other` sont RETIREES — mesure faite,
    // zero consommateur hors de ce catalogue apres le reordonnancement.
    'section_parc' => "FLEET & ACCESS",
    'section_exploitation' => "OPERATIONS",
    'section_securite' => "SECURITY",
    'section_admin' => "ADMINISTRATION",
    'section_autre' => "OTHER",

    'dashboard'   => 'Dashboard',
    'ssh_keys'    => 'SSH Keys',
    'updates'     => 'Updates',
    'iptables'    => 'Iptables',
    'fail2ban'    => 'Fail2ban',
    'services'    => 'Services',
    'ssh_audit'   => 'SSH Audit',
    'supervision' => 'Supervision',
    'bashrc'      => 'Bashrc',
    'graylog'     => 'Graylog',
    'wazuh'       => 'Wazuh',
    'cve_scan'    => 'CVE Scan',
    'docker'      => 'Docker containers',

    // Administration
    'admin'         => 'Admin',
    'tasks'         => 'Tasks',
    'groups'        => 'Groups & bulk',
    'maintenance'   => 'Maintenance',
    'approvals'     => 'Approvals',
    'commandlog'    => 'Command log',
    'chatops'       => 'ChatOps',
    'tickets'       => 'Tickets',
    'search'        => 'Search',
    'audit_log'     => 'Audit log',
    'backups'       => 'Backups',
    'remote_users'  => 'Remote Users',
    'platform_key'  => 'Platform SSH Key',
    'sudo_policies' => 'Sudo rights',
    'sftp_policies' => 'SFTP/SSH access',
    'compliance'    => 'Compliance',
    'drift'         => 'Config drift',

    // Autre
    'profil'        => 'Profile',
    'documentation' => 'Documentation',
    'api_docs'      => 'API Docs',

    // Chrome
    'profile' => 'Profile',
    'logout'  => 'Sign out',

    // Etat du portage
    'non_porte'              => 'previous portal',
    'non_porte_titre'        => 'this page has not been ported yet, it opens in the previous portal',
    'langue'                 => 'Language',
    'langue_fr'              => 'French',
    'langue_en'              => 'English',
    'langue_basculer'        => 'Show the portal in :langue',
    'legende_ancien_portail' => 'Entries marked with an arrow open the previous portal in a new tab.',
    'ouvrir_menu'     => 'Open menu',
    'fermer_menu'     => 'Close menu',
];
