<?php
// lang/fr/graylog.php - Module Graylog (rsyslog forwarding + templates)
return [
    'graylog.title' => 'Graylog',
    'graylog.subtitle' => 'Forwarding rsyslog vers votre serveur Graylog et templates editables par source.',

    // Onglets
    'graylog.tab_config' => 'Configuration',
    'graylog.tab_deploy' => 'Deploiement',
    'graylog.tab_templates' => 'Templates rsyslog',
    'graylog.tab_history' => 'Historique',

    // Configuration
    'graylog.config_title' => 'Configuration serveur Graylog',
    'graylog.config_desc' => 'Les logs des machines seront forwardes vers ce serveur. Streams et extractors sont geres sur Graylog directement.',
    'graylog.server_host' => 'Host Graylog (IP/FQDN)',
    'graylog.server_port' => 'Port',
    'graylog.protocol' => 'Protocole',
    'graylog.tls_ca' => 'Chemin CA (TLS)',
    'graylog.rl_burst' => 'Rate limit burst (0 = off)',
    'graylog.rl_interval' => 'Rate limit interval (sec)',
    'graylog.save' => 'Sauvegarder',
    'graylog.saving' => 'Sauvegarde…',
    'graylog.saved' => 'Sauvegarde.',

    // Deploiement
    'graylog.deploy_title' => 'Deploiement rsyslog',
    'graylog.deploy_desc' => 'Installe rsyslog si absent, ecrit la regle de forwarding dans /etc/rsyslog.d/ et redemarre le service. Les templates activees sont egalement pousses.',
    'graylog.refresh' => 'Rafraichir',
    'graylog.loading' => 'Chargement…',
    'graylog.no_servers' => 'Aucun serveur disponible.',

    'graylog.col_status' => 'Statut',
    'graylog.col_version' => 'Version rsyslog',
    'graylog.col_last_deploy' => 'Dernier deploy',
    'graylog.col_actions' => 'Actions',
    'graylog.col_date' => 'Date',
    'graylog.col_user' => 'Utilisateur',
    'graylog.col_action' => 'Action',

    'graylog.status_forwarding' => 'Forwarding actif',
    'graylog.status_not_deployed' => 'Non deploye',

    'graylog.btn_deploy' => 'Deployer',
    'graylog.btn_test' => 'Test',
    'graylog.btn_uninstall' => 'Retirer',

    'graylog.confirm_deploy' => 'Deployer la config rsyslog sur ce serveur (install si absent + redemarrage) ?',
    'graylog.confirm_uninstall' => 'Retirer les fichiers RootWarden de /etc/rsyslog.d/ et redemarrer ?',
    'graylog.deploying' => 'Deploiement…',
    'graylog.test_sent' => 'Logger envoye',

    // Templates
    'graylog.templates_list' => 'Templates rsyslog',
    'graylog.new' => 'Nouveau',
    'graylog.tpl_name' => 'Nom (ex: apache-access)',
    'graylog.tpl_desc' => 'Description (optionnel)',
    'graylog.tpl_enabled' => 'Pousser au deploy',
    'graylog.tpl_editor_hint' => 'Snippet rsyslog pousse dans /etc/rsyslog.d/50-rootwarden-<nom>.conf lors du prochain deploy.',
    'graylog.delete' => 'Supprimer',
    'graylog.confirm_delete_template' => 'Supprimer ce template ?',
    'graylog.enabled' => 'actif',
    'graylog.disabled' => 'inactif',

    // Historique
    'graylog.history_title' => 'Historique (100 dernieres actions)',
    'graylog.history_empty' => 'Aucune action enregistree.',
];
