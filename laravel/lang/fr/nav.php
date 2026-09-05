<?php

/**
 * Libelles du menu — francais.
 *
 * Releves sur le legacy le 2026-08-18 et GENERES, non recopies. Parite stricte
 * avec lang/en/nav.php : meme jeu de cles, meme commit. Une cle absente
 * n'echoue pas, elle affiche son propre identifiant a l'ecran.
 */
return [
    // Sections

    // Navigation
    // NAV-001 : cinq sections, dans l'ordre de la sequence operationnelle.
    // `section_navigation` et `section_other` sont RETIREES — mesure faite,
    // zero consommateur hors de ce catalogue apres le reordonnancement.
    'section_parc' => "PARC & ACCÈS",
    'section_exploitation' => "EXPLOITATION",
    'section_securite' => "SÉCURITÉ",
    'section_admin' => "ADMINISTRATION",
    'section_autre' => "AUTRE",

    'cgu' => "Conditions d'utilisation",
    'cafe' => "Offrir un cafe",
    'cafe_titre' => "Soutenir le projet — buymeacoffee.com",
    'version' => "Version :numero",
    'version_inconnue' => "Version inconnue",

    'dashboard'   => 'Dashboard',
    'ssh_keys'    => 'Cles SSH',
    'updates'     => 'Mises a jour',
    'iptables'    => 'Iptables',
    'fail2ban'    => 'Fail2ban',
    'services'    => 'Services',
    'ssh_audit'   => 'Audit SSH',
    'supervision' => 'Supervision',
    'bashrc'      => 'Bashrc',
    'graylog'     => 'Graylog',
    'wazuh'       => 'Wazuh',
    'cve_scan'    => 'Scan CVE',
    'docker'      => 'Conteneurs Docker',

    // Administration
    'admin'         => 'Admin',
    'tasks'         => 'Taches',
    'groups'        => 'Groupes & masse',
    'maintenance'   => 'Maintenance',
    'approvals'     => 'Approbations',
    'commandlog'    => 'Journal commandes',
    'chatops'       => 'ChatOps',
    'tickets'       => 'Tickets',
    'search'        => 'Recherche',
    'audit_log'     => 'Journal d\'audit',
    'backups'       => 'Sauvegardes',
    'remote_users'  => 'Utilisateurs distants',
    'platform_key'  => 'Cle SSH plateforme',
    'sudo_policies' => 'Droits sudo',
    'sftp_policies' => 'Acces SFTP/SSH',
    'compliance'    => 'Conformite',
    'drift'         => 'Derive de config',

    // Autre
    'profil'        => 'Profil',
    'documentation' => 'Documentation',
    'api_docs'      => 'API Docs',

    // Chrome
    'profile' => 'Profil',
    'logout'  => 'Deconnexion',

    // Etat du portage
    'non_porte'              => 'ancien portail',
    'non_porte_titre'        => "cette page n'est pas encore portée, elle s'ouvre dans l'ancien portail",
    'theme_basculer'          => 'Changer de theme (clair / sombre)',
    'langue'                 => 'Langue',
    'langue_fr'              => 'francais',
    'langue_en'              => 'anglais',
    'langue_basculer'        => 'Afficher le portail en :langue',
    'legende_ancien_portail' => "Les entrées marquées d'une flèche ouvrent l'ancien portail dans un nouvel onglet.",
    'ouvrir_menu'     => 'Ouvrir le menu',
    'fermer_menu'     => 'Fermer le menu',
];
