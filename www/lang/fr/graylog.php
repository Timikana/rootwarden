<?php
// lang/fr/graylog.php — Module Graylog (Sidecar + collectors)
return [
    'graylog.title' => 'Graylog',
    'graylog.subtitle' => 'Deploiement du Graylog Sidecar et gestion des collectors de logs.',

    // Onglets
    'graylog.tab_config' => 'Configuration',
    'graylog.tab_deploy' => 'Deploiement',
    'graylog.tab_collectors' => 'Collectors',
    'graylog.tab_history' => 'Historique',

    // Configuration
    'graylog.config_title' => 'Configuration serveur Graylog',
    'graylog.config_desc' => 'URL du serveur, token API et version du sidecar a deployer sur les machines.',
    'graylog.server_url' => 'URL du serveur',
    'graylog.api_token' => 'Token API',
    'graylog.api_token_placeholder' => 'Laisser vide pour ne pas modifier',
    'graylog.tls_verify' => 'Verifier le certificat TLS',
    'graylog.sidecar_version' => 'Version sidecar',
    'graylog.token_set' => 'defini',
    'graylog.token_not_set' => 'non defini',

    // Deploiement
    'graylog.deploy_title' => 'Deploiement du sidecar',
    'graylog.refresh' => 'Rafraichir',
    'graylog.no_servers' => 'Aucun serveur disponible.',
    'graylog.col_status' => 'Statut',
    'graylog.col_version' => 'Version',
    'graylog.col_actions' => 'Actions',
    'graylog.status_running' => 'Actif',
    'graylog.status_stopped' => 'Arrete',
    'graylog.status_never' => 'Non installe',

    'graylog.btn_install' => 'Installer',
    'graylog.btn_uninstall' => 'Desinstaller',
    'graylog.btn_restart' => 'Redemarrer',
    'graylog.btn_register' => 'Verifier',

    'graylog.confirm_install' => 'Installer le sidecar Graylog (filebeat) sur ce serveur ?',
    'graylog.confirm_uninstall' => 'Desinstaller le sidecar ? Les logs ne seront plus remontes.',
    'graylog.installing' => 'Installation en cours…',

    // Collectors
    'graylog.collectors_list' => 'Collectors',
    'graylog.new' => 'Nouveau',
    'graylog.col_name' => 'Nom du collector',
    'graylog.col_tags' => 'Tags (CSV)',
    'graylog.save' => 'Sauvegarder',
    'graylog.delete' => 'Supprimer',
    'graylog.saving' => 'Sauvegarde…',
    'graylog.saved' => 'Sauvegarde.',
    'graylog.confirm_delete_collector' => 'Supprimer ce collector ?',

    // Historique
    'graylog.history_title' => 'Historique (100 dernieres actions)',
    'graylog.history_empty' => 'Aucune action enregistree.',
    'graylog.col_date' => 'Date',
    'graylog.col_user' => 'Utilisateur',
    'graylog.col_action' => 'Action',

    'graylog.loading' => 'Chargement…',
];
