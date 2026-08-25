<?php

/**
 * Notifications in-app — module `adm/`, sous-lot D2. Français.
 *
 * Libellés repris du legacy, avec les ACCENTS rétablis, et surtout AVEC LES
 * DOUZE TYPES. Le legacy en nomme six et affiche « Autre » pour les autres —
 * précisément ceux que les préférences gouvernent. Voir PARITE E-111.
 *
 * Parité stricte avec lang/en/notif.php.
 */
return [

    'title' => 'Notifications',
    'desc' => "Historique complet de vos notifications. Une notification n'est marquée lue qu'une fois le serveur l'a confirmé.",
    'resume' => ':nonLues non lue(s) sur :total au total',

    'tout_lire' => 'Tout marquer comme lu',
    'tout_lire_tip' => "Marque lues toutes vos notifications non lues. Sans effet sur celles des autres comptes.",
    'marquer_lue' => 'Marquer lue',
    'ouvrir' => 'Ouvrir',
    'non_lue' => 'Non lue',
    'lue' => 'Lue',
    'marquee_lue' => 'Notification marquée lue.',
    'supprimee' => 'Notification supprimée.',
    'tout_lu' => ':nombre notification(s) marquée(s) lue(s).',
    'rien_a_lire' => "Aucune notification non lue : rien n'a été modifié.",

    'filtre_type' => 'Type',
    'filtre_etat' => 'État',
    'tous_types' => 'Tous les types',
    'toutes' => 'Toutes',
    'non_lues' => 'Non lues',
    'lues' => 'Lues',
    'filtrer' => 'Filtrer',
    'reinitialiser' => 'Réinitialiser',

    'vide' => 'Aucune notification',
    'vide_aide' => "Élargissez le filtre, ou attendez qu'un événement en produise une.",

    'pagination' => 'Pages des notifications',
    'page_sur' => 'Page :page sur :total',
    'precedent' => 'Précédent',
    'suivant' => 'Suivant',

    // Les DOUZE types que le backend peut émettre.
    'type_cve_scan' => 'Scan CVE',
    'type_cve_scan_desc' => "À la fin d'un scan de vulnérabilités",
    'type_security_alert' => 'Alerte de sécurité',
    'type_security_alert_desc' => 'Vulnérabilité critique détectée',
    'type_ssh_audit' => 'Audit SSH',
    'type_ssh_audit_desc' => "À la fin d'un audit de configuration SSH",
    'type_compliance_report' => 'Rapport de conformité',
    'type_compliance_report_desc' => "À la production d'un rapport",
    'type_backup_status' => 'Sauvegarde',
    'type_backup_status_desc' => "Résultat d'une sauvegarde de la base",
    'type_update_status' => 'Mise à jour',
    'type_update_status_desc' => "Résultat d'une mise à jour de paquets",
    'type_cve_critical' => 'CVE critique',
    'type_cve_critical_desc' => 'Vulnérabilité de sévérité critique',
    'type_server_offline' => 'Serveur injoignable',
    'type_server_offline_desc' => 'Une machine ne répond plus',
    'type_perm_granted' => 'Permission accordée',
    'type_perm_granted_desc' => 'Une permission temporaire vous a été accordée',
    'type_perm_expired' => 'Permission expirée',
    'type_perm_expired_desc' => 'Une permission temporaire est arrivée à terme',
    'type_password_expiry' => 'Mot de passe',
    'type_password_expiry_desc' => 'Votre mot de passe approche de son expiration',
    'type_info' => 'Information',
    'type_info_desc' => 'Message général du portail',

    // Réglages
    'reglages_titre' => 'Préférences de notification',
    'reglages_desc' => "Choisissez, pour chaque compte, les événements qui produisent une notification.",
    'reserve_titre' => 'Cinq types ne sont pas gouvernés par cette page.',
    'reserve_texte' => "Ces événements sont envoyés sans consulter les préférences : les couper ici n'aurait aucun effet, et cette page ne le prétend pas.",
    'pref_activee' => 'Préférence activée.',
    'pref_desactivee' => 'Préférence désactivée.',

    'role_1' => 'Utilisateur',
    'role_2' => 'Administrateur',
    'role_3' => 'Super-administrateur',

    'err_hors_portee' => "Cette notification n'est pas la vôtre, ou elle est déjà lue.",
    'err_donnees' => 'Données manquantes.',
    'err_type' => "Ce type d'événement n'est pas réglable.",
    'err_reseau' => "Le portail n'a pas répondu (statut :statut). Rien n'a été modifié.",
];
