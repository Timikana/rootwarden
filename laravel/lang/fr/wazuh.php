<?php

/**
 * Module Wazuh — francais.
 *
 * Porte de `legacy/lang/fr/wazuh.php`. Le prefixe `wazuh.` est RETIRE : Laravel
 * nomme par fichier, donc `__('wazuh.title')` resout `title` ici. Le garder
 * aurait donne `wazuh.wazuh.title`.
 *
 * `status_unknown` EXISTAIT DEJA dans le legacy (`:47`) : le statut que le DSI a
 * adopte n'a pas eu a etre invente, et son badge ne rendra donc pas sa cle en
 * clair. Quatrieme occurrence du motif, et la premiere evitee AVANT la premiere
 * capture plutot qu'en la regardant.
 *
 * Parite stricte avec lang/en/wazuh.php : meme jeu de cles, meme commit.
 */
return [
    'title' => 'Wazuh',
    'subtitle' => 'Deploiement de l\'agent Wazuh, options par serveur, rules/decoders editables.',
    'tab_config' => 'Configuration',
    'tab_deploy' => 'Deploiement',
    'tab_options' => 'Options',
    'tab_rules' => 'Rules & Decoders',
    'tab_history' => 'Historique',
    'config_title' => 'Configuration Wazuh manager',
    'config_desc' => 'Manager, password d\'enrolement et groupe par defaut utilises lors de l\'installation.',
    'manager_ip' => 'Manager (IP/FQDN)',
    'manager_port' => 'Port manager',
    'registration_port' => 'Port enrolement',
    'registration_password' => 'Mot de passe d\'enrolement',
    'default_group' => 'Groupe par defaut',
    'agent_version' => 'Version agent',
    'enable_active_response_global' => 'Active Response active globalement',
    'api_section' => 'API manager (facultatif, pour push rules)',
    'api_url' => 'URL API',
    'api_user' => 'Utilisateur API',
    'api_password' => 'Mot de passe API',
    'unchanged' => 'Laisser vide pour conserver',
    'save' => 'Sauvegarder',
    'deploy_title' => 'Deploiement de l\'agent',
    'refresh' => 'Rafraichir',
    'no_servers' => 'Aucun serveur.',
    'col_agent_id' => 'Agent ID',
    'col_status' => 'Statut',
    'col_version' => 'Version',
    'col_group' => 'Groupe',
    'col_actions' => 'Actions',
    'col_network' => 'Reseau',
    'col_criticality' => 'Criticite',
    'col_environment' => 'Env',
    'status_active' => 'Actif',
    'status_disconnected' => 'Deconnecte',
    'status_never' => 'Jamais connecte',
    'status_pending' => 'En attente',
    'status_unknown' => 'Inconnu',
    'btn_install' => 'Installer',
    'btn_detect' => 'Scanner',
    'btn_detect_tip' => 'Detecter un agent Wazuh deja installe (sans reinstaller)',
    'btn_uninstall' => 'Desinstaller',
    'btn_restart' => 'Redemarrer',
    'btn_setgroup' => 'Changer groupe',
    'confirm_install' => 'Installer l\'agent Wazuh et l\'enroler aupres du manager ?',
    'btn_install_all' => 'Installer sur tous',
    'confirm_install_all' => 'Installer Wazuh agent sur TOUS les serveurs sans agent ? Operation sequentielle, peut prendre plusieurs minutes.',
    'installing_all' => 'Installation sequentielle en cours sur tous les serveurs sans agent... Ne pas fermer cette page.',
    'install_all_failures' => 'Echecs',
    'confirm_uninstall' => 'Desinstaller l\'agent ?',
    'confirm_restart' => 'Redemarrer l\'agent ?',
    'prompt_group' => 'Nouveau groupe pour cet agent ?',
    'server' => 'Serveur',
    'select_server' => '- Choisir un serveur -',
    'log_format' => 'Format de log',
    'syscheck_frequency' => 'Frequence FIM (secondes)',
    'fim_paths' => 'Chemins FIM surveilles',
    'fim_paths_hint' => 'un par ligne, debut par /',
    'active_response' => 'Active Response',
    'sca' => 'SCA (Security Configuration Assessment)',
    'rootcheck' => 'Rootcheck',
    'rules_list' => 'Rules / Decoders / CDB',
    'new' => 'Nouveau',
    'rule_name' => 'Nom (ex: local_rules)',
    'delete' => 'Supprimer',
    'confirm_delete_rule' => 'Supprimer ce rule ?',
    'history_title' => 'Historique (100 dernieres actions)',
    'history_empty' => 'Aucune action enregistree.',
    'col_date' => 'Date',
    'col_user' => 'Utilisateur',
    'col_action' => 'Action',
    'loading' => 'Chargement…',
    'saving' => 'Sauvegarde…',
    'saved' => 'Sauvegarde.',
    'pwd_set' => 'defini',
    'pwd_not_set' => 'non defini',
];
