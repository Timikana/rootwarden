<?php

/**
 * In-app notifications — `adm/` module, sub-lot D2. English.
 *
 * Labels taken from the legacy, and above all WITH ALL TWELVE TYPES. The legacy
 * names six and shows "Autre" for the rest — precisely the ones the preferences
 * govern. See PARITE E-111.
 *
 * Strict parity with lang/fr/notif.php.
 */
return [

    'title' => 'Notifications',
    'desc' => 'Full history of your notifications. A notification is only marked as read once the server has confirmed it.',
    'resume' => ':nonLues unread out of :total in total',

    'tout_lire' => 'Mark all as read',
    'tout_lire_tip' => 'Marks all your unread notifications as read. No effect on other accounts.',
    'marquer_lue' => 'Mark as read',
    'ouvrir' => 'Open',
    'non_lue' => 'Unread',
    'lue' => 'Read',
    'marquee_lue' => 'Notification marked as read.',
    'supprimee' => 'Notification deleted.',
    'tout_lu' => ':nombre notification(s) marked as read.',
    'rien_a_lire' => 'No unread notification: nothing was changed.',

    'filtre_type' => 'Type',
    'filtre_etat' => 'Status',
    'tous_types' => 'All types',
    'toutes' => 'All',
    'non_lues' => 'Unread',
    'lues' => 'Read',
    'filtrer' => 'Filter',
    'reinitialiser' => 'Reset',

    'vide' => 'No notification',
    'vide_aide' => 'Widen the filter, or wait for an event to produce one.',

    'pagination' => 'Notification pages',
    'page_sur' => 'Page :page of :total',
    'precedent' => 'Previous',
    'suivant' => 'Next',

    // The TWELVE types the backend can emit.
    'type_cve_scan' => 'CVE scan',
    'type_cve_scan_desc' => 'When a vulnerability scan completes',
    'type_security_alert' => 'Security alert',
    'type_security_alert_desc' => 'Critical vulnerability detected',
    'type_ssh_audit' => 'SSH audit',
    'type_ssh_audit_desc' => 'When an SSH configuration audit completes',
    'type_compliance_report' => 'Compliance report',
    'type_compliance_report_desc' => 'When a report is produced',
    'type_backup_status' => 'Backup',
    'type_backup_status_desc' => 'Outcome of a database backup',
    'type_update_status' => 'Update',
    'type_update_status_desc' => 'Outcome of a package update',
    'type_cve_critical' => 'Critical CVE',
    'type_cve_critical_desc' => 'Vulnerability of critical severity',
    'type_server_offline' => 'Server unreachable',
    'type_server_offline_desc' => 'A machine stopped answering',
    'type_perm_granted' => 'Permission granted',
    'type_perm_granted_desc' => 'A temporary permission was granted to you',
    'type_perm_expired' => 'Permission expired',
    'type_perm_expired_desc' => 'A temporary permission has lapsed',
    'type_password_expiry' => 'Password',
    'type_password_expiry_desc' => 'Your password is nearing expiry',
    'type_info' => 'Information',
    'type_info_desc' => 'General portal message',

    // Settings
    'reglages_titre' => 'Notification preferences',
    'reglages_desc' => 'Choose, for each account, which events produce a notification.',
    'reserve_titre' => 'Five types are not governed by this page.',
    'reserve_texte' => 'These events are sent without consulting the preferences: switching them off here would have no effect, and this page does not pretend otherwise.',
    'pref_activee' => 'Preference enabled.',
    'pref_desactivee' => 'Preference disabled.',

    'role_1' => 'User',
    'role_2' => 'Administrator',
    'role_3' => 'Super administrator',

    'err_hors_portee' => 'This notification is not yours, or it is already read.',
    'err_donnees' => 'Missing data.',
    'err_type' => 'This event type is not configurable.',
    'err_reseau' => 'The portal did not answer (status :statut). Nothing was changed.',
];
