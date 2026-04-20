<?php
// lang/fr/bashrc.php — Module Bashrc (deploiement standardise du .bashrc)
return [
    // Page
    'bashrc.title' => 'Bashrc',
    'bashrc.subtitle' => 'Deploiement standardise du .bashrc par utilisateur sur vos serveurs.',

    // Onglets
    'bashrc.tab_deploy' => 'Deploiement',
    'bashrc.tab_history' => 'Historique',
    'bashrc.tab_template' => 'Template',

    // Selection / config
    'bashrc.server' => 'Serveur cible',
    'bashrc.select_server' => '— Choisir un serveur —',
    'bashrc.mode' => 'Mode',
    'bashrc.mode_overwrite' => 'Ecraser',
    'bashrc.mode_merge' => 'Fusionner (conserver blocs custom)',
    'bashrc.install_figlet' => 'Installer figlet',
    'bashrc.figlet_missing' => 'figlet n\'est pas installe sur ce serveur. La banniere ASCII ne s\'affichera pas tant qu\'il ne l\'est pas.',
    'bashrc.pick_server_first' => 'Selectionnez un serveur pour afficher ses utilisateurs.',
    'bashrc.loading' => 'Chargement…',
    'bashrc.no_users' => 'Aucun utilisateur Linux eligible (UID>=1000 ou root, shell interactif).',
    'bashrc.installing' => 'Installation…',
    'bashrc.deploying' => 'Deploiement en cours…',

    // Tableau
    'bashrc.col_user' => 'Utilisateur',
    'bashrc.col_home' => 'Home',
    'bashrc.col_shell' => 'Shell',
    'bashrc.col_size' => 'Taille',
    'bashrc.col_mtime' => 'Modifie',
    'bashrc.col_status' => 'Statut',
    'bashrc.col_actions' => 'Actions',
    'bashrc.col_date' => 'Date',
    'bashrc.col_action' => 'Action',
    'bashrc.status_ok' => 'Conforme',
    'bashrc.status_diff' => 'Different',
    'bashrc.status_absent' => 'Absent',
    'bashrc.has_custom' => 'Custom',

    // Boutons
    'bashrc.btn_preview' => 'Apercu (diff)',
    'bashrc.btn_deploy' => 'Deployer',
    'bashrc.btn_dry_run' => 'Dry run',
    'bashrc.btn_restore' => 'Restaurer',

    // Preview / deploy
    'bashrc.preview_title' => 'Apercu des modifications',
    'bashrc.preview_empty' => 'Aucune difference a afficher.',
    'bashrc.deploy_result' => 'Resultat du deploiement',
    'bashrc.ok' => 'OK',
    'bashrc.failed' => 'Echec',
    'bashrc.skipped' => 'Ignore',
    'bashrc.dry_would_run' => 'Aurait deploye (dry run).',

    // Confirmations
    'bashrc.confirm_deploy' => 'Confirmez le deploiement du .bashrc pour ces utilisateurs ?',
    'bashrc.confirm_dry' => 'Lancer un dry run (sans modification) ?',
    'bashrc.confirm_restore' => 'Restaurer le backup le plus recent pour cet utilisateur ?',

    // Historique
    'bashrc.history_title' => 'Historique des deploiements (100 dernieres actions)',
    'bashrc.history_empty' => 'Aucune action enregistree.',

    // Template
    'bashrc.template_title' => 'Template .bashrc standardise',
    'bashrc.template_desc' => 'Editez le contenu du .bashrc qui sera deploye. Version persistee en BDD, source de verite pour tous les deploiements.',
    'bashrc.template_lines' => 'Lignes',
    'bashrc.template_save' => 'Sauvegarder',
    'bashrc.template_reset' => 'Annuler modifs',
    'bashrc.template_dirty' => 'Modifications non sauvegardees',
    'bashrc.template_saved' => 'Template sauvegarde.',
    'bashrc.saving' => 'Sauvegarde…',
    'bashrc.confirm_save_template' => 'Sauvegarder le nouveau template ? Les prochains deploiements utiliseront ce contenu.',
    'bashrc.confirm_reset_template' => 'Annuler les modifications locales et restaurer la derniere version sauvegardee ?',
];
