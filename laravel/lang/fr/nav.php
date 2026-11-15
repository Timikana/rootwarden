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
    'section_parc' => "Parc et accès",
    'section_exploitation' => "Exploitation",
    'section_securite' => "Sécurité",
    'section_admin' => "Administration",
    'section_autre' => "Autre",

    'cgu' => "Conditions d'utilisation",
    'cafe' => "Offrir un café",
    'cafe_titre' => "Soutenir le projet — buymeacoffee.com",
    'version' => "Version :numero",
    'version_inconnue' => "Version inconnue",

    'dashboard'   => "Tableau de bord",
    'ssh_keys'    => "Clés SSH",
    'updates'     => "Mises à jour",
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
    'tasks'         => "Tâches",
    'groups'        => "Groupes",
    'maintenance'   => 'Maintenance',
    'approvals'     => 'Approbations',
    'commandlog'    => "Journal des commandes",
    'chatops'       => 'ChatOps',
    'tickets'       => 'Tickets',
    'search'        => 'Recherche',
    'audit_log'     => 'Journal d\'audit',
    'backups'       => 'Sauvegardes',
    'remote_users'  => 'Utilisateurs distants',
    'platform_key'  => "Clé de plateforme",
    'sudo_policies' => 'Droits sudo',
    'sftp_policies' => "Accès SFTP/SSH",
    'compliance'    => "Conformité",
    'drift'         => "Dérive de configuration",

    // Autre
    'profil'        => 'Profil',
    'documentation' => 'Documentation',
    'api_docs'      => "Accès à l'API",

    // Chrome
    'profile' => 'Profil',
    'logout'  => "Déconnexion",

    // Etat du portage
    'non_porte'              => 'ancien portail',
    'non_porte_titre'        => "cette page n'est pas encore portée, elle s'ouvre dans l'ancien portail",
    'theme_basculer'          => "Changer de thème (clair / sombre)",
    'langue'                 => 'Langue',
    'langue_fr'              => "français",
    'langue_en'              => 'anglais',
    'langue_basculer'        => 'Afficher le portail en :langue',
    'legende_ancien_portail' => "Les entrées marquées d'une flèche ouvrent l'ancien portail dans un nouvel onglet.",
    'ouvrir_menu'     => 'Ouvrir le menu',
    'fermer_menu'     => 'Fermer le menu',
];
