<?php
// lang/fr/wazuh.php - Module Wazuh (Agent + rules)
return [
    'wazuh.title' => 'Wazuh',
    'wazuh.subtitle' => 'Deploiement de l\'agent Wazuh, options par serveur, rules/decoders editables.',

    // Onglets
    'wazuh.tab_config' => 'Configuration',
    'wazuh.tab_deploy' => 'Deploiement',
    'wazuh.tab_options' => 'Options',
    'wazuh.tab_rules' => 'Rules & Decoders',
    'wazuh.tab_history' => 'Historique',

    // Configuration
    'wazuh.config_title' => 'Configuration Wazuh manager',
    'wazuh.config_desc' => 'Manager, password d\'enrolement et groupe par defaut utilises lors de l\'installation.',
    'wazuh.manager_ip' => 'Manager (IP/FQDN)',
    'wazuh.manager_port' => 'Port manager',
    'wazuh.registration_port' => 'Port enrolement',
    'wazuh.registration_password' => 'Mot de passe d\'enrolement',
    'wazuh.default_group' => 'Groupe par defaut',
    'wazuh.agent_version' => 'Version agent',
    'wazuh.enable_active_response_global' => 'Active Response active globalement',
    'wazuh.api_section' => 'API manager (facultatif, pour push rules)',
    'wazuh.api_url' => 'URL API',
    'wazuh.api_user' => 'Utilisateur API',
    'wazuh.api_password' => 'Mot de passe API',
    'wazuh.unchanged' => 'Laisser vide pour conserver',
    'wazuh.save' => 'Sauvegarder',

    // Deploiement
    'wazuh.deploy_title' => 'Deploiement de l\'agent',
    'wazuh.refresh' => 'Rafraichir',
    'wazuh.no_servers' => 'Aucun serveur.',
    'wazuh.col_agent_id' => 'Agent ID',
    'wazuh.col_status' => 'Statut',
    'wazuh.col_version' => 'Version',
    'wazuh.col_group' => 'Groupe',
    'wazuh.col_actions' => 'Actions',
    'wazuh.status_active' => 'Actif',
    'wazuh.status_disconnected' => 'Deconnecte',
    'wazuh.status_never' => 'Jamais connecte',
    'wazuh.status_pending' => 'En attente',
    'wazuh.status_unknown' => 'Inconnu',

    'wazuh.btn_install' => 'Installer',
    'wazuh.btn_detect' => 'Scanner',
    'wazuh.btn_detect_tip' => 'Detecter un agent Wazuh deja installe (sans reinstaller)',
    'wazuh.btn_uninstall' => 'Desinstaller',
    'wazuh.btn_restart' => 'Redemarrer',
    'wazuh.btn_setgroup' => 'Changer groupe',

    'wazuh.confirm_install' => 'Installer l\'agent Wazuh et l\'enroler aupres du manager ?',
    'wazuh.confirm_uninstall' => 'Desinstaller l\'agent ?',
    'wazuh.confirm_restart' => 'Redemarrer l\'agent ?',
    'wazuh.prompt_group' => 'Nouveau groupe pour cet agent ?',

    // Options
    'wazuh.server' => 'Serveur',
    'wazuh.select_server' => '- Choisir un serveur -',
    'wazuh.log_format' => 'Format de log',
    'wazuh.syscheck_frequency' => 'Frequence FIM (secondes)',
    'wazuh.fim_paths' => 'Chemins FIM surveilles',
    'wazuh.fim_paths_hint' => 'un par ligne, debut par /',
    'wazuh.active_response' => 'Active Response',
    'wazuh.sca' => 'SCA (Security Configuration Assessment)',
    'wazuh.rootcheck' => 'Rootcheck',

    // Rules
    'wazuh.rules_list' => 'Rules / Decoders / CDB',
    'wazuh.new' => 'Nouveau',
    'wazuh.rule_name' => 'Nom (ex: local_rules)',
    'wazuh.delete' => 'Supprimer',
    'wazuh.confirm_delete_rule' => 'Supprimer ce rule ?',

    // Historique
    'wazuh.history_title' => 'Historique (100 dernieres actions)',
    'wazuh.history_empty' => 'Aucune action enregistree.',
    'wazuh.col_date' => 'Date',
    'wazuh.col_user' => 'Utilisateur',
    'wazuh.col_action' => 'Action',

    'wazuh.loading' => 'Chargement…',
    'wazuh.saving' => 'Sauvegarde…',
    'wazuh.saved' => 'Sauvegarde.',
    'wazuh.pwd_set' => 'defini',
    'wazuh.pwd_not_set' => 'non defini',
];
