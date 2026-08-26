<?php

/**
 * Permissions fonctionnelles — module `adm/`, sous-lot D5. Français.
 *
 * LES DIX-HUIT permissions sont nommées, y compris `can_manage_fail2ban` et
 * `can_manage_api_keys` — que le legacy laisse hors de son interface, l'une
 * accordable sans être reprenable, l'autre inatteignable dans les deux sens
 * (PARITE E-118).
 *
 * Parité stricte avec lang/en/perms.php.
 */
return [

    'title' => 'Permissions et accès',
    'desc' => 'Accorder ou retirer un droit fonctionnel, et l\'accès à une machine. Chaque geste demande une confirmation par second facteur.',
    'source' => 'Les :nombre permissions sont lues dans le schéma de la base : une colonne ajoutée devient réglable, une colonne retirée disparaît partout à la fois.',
    'droits' => 'Droits fonctionnels',
    'acces' => 'Accès aux machines',
    'compte_resume' => ':droits droit(s), :machines machine(s)',
    'role_1' => 'Utilisateur',
    'role_2' => 'Administrateur',
    'role_3' => 'Super-administrateur',
    'activee' => 'Permission accordée.',
    'desactivee' => 'Permission retirée.',
    'acces_accorde' => 'Accès à la machine accordé.',
    'acces_retire' => 'Accès à la machine retiré.',
    'step_up_titre' => 'Confirmez avec votre second facteur',
    'step_up_aide' => 'Modifier un droit engage ce que ce compte pourra faire sur le parc. Saisissez le code à six chiffres de votre authentificateur.',
    'step_up_code' => 'Code à six chiffres',
    'step_up_valider' => 'Confirmer',
    'annuler' => 'Annuler',
    'err_soi_meme' => 'Vous ne pouvez pas modifier vos propres droits.',
    'err_rang' => 'Impossible de modifier un compte de rôle égal ou supérieur au vôtre.',
    'err_inconnu' => 'Ce compte n\'existe pas.',
    'err_permission' => 'Cette permission n\'existe pas.',
    'err_valeur' => 'La valeur est absente.',
    'err_machine' => 'Cette machine n\'existe pas.',
    'err_auto_acces' => 'Vous ne pouvez pas vous accorder un accès machine à vous-même.',
    'err_step_up' => 'Ce geste demande une confirmation par votre second facteur.',
    'err_reseau' => 'Le portail n\'a pas répondu (statut :statut). Rien n\'a été modifié.',

    // Les dix-huit permissions, nommees une a une.
    'p_can_deploy_keys' => 'Déployer les clés SSH',
    'p_can_update_linux' => 'Lancer les mises à jour Linux',
    'p_can_manage_iptables' => 'Gérer les règles iptables',
    'p_can_admin_portal' => 'Administrer le portail',
    'p_can_scan_cve' => 'Lancer un scan de vulnérabilités',
    'p_can_manage_remote_users' => 'Gérer les comptes distants',
    'p_can_manage_platform_key' => 'Gérer la clé de plateforme',
    'p_can_view_compliance' => 'Consulter la conformité',
    'p_can_manage_backups' => 'Gérer les sauvegardes',
    'p_can_schedule_cve' => 'Planifier les scans CVE',
    'p_can_manage_fail2ban' => 'Gérer Fail2ban',
    'p_can_manage_services' => 'Gérer les services systemd',
    'p_can_audit_ssh' => 'Auditer la configuration SSH',
    'p_can_manage_supervision' => 'Gérer la supervision',
    'p_can_manage_bashrc' => 'Gérer les .bashrc',
    'p_can_manage_graylog' => 'Gérer Graylog',
    'p_can_manage_wazuh' => 'Gérer Wazuh',
    'p_can_manage_api_keys' => 'Gérer les clés d\'API',
];
