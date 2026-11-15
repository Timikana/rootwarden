<?php

/**
 * Module Wazuh — francais.
 *
 * Parite stricte avec lang/en/wazuh.php : meme jeu de cles, meme commit.
 * Regles de redaction : docs/REDACTION-INTERFACE.md. Le JS compose certaines
 * cles (`col_*`, `status_*`) : les chercher par prefixe avant d'en retirer.
 */
return [
    'title' => 'Wazuh',
    'subtitle' => 'Configuration du manager, options par serveur et règles.',
    'tab_config' => 'Configuration',
    'tab_deploy' => 'Deploiement',
    'tab_options' => 'Options',
    'tab_rules' => 'Rules & Decoders',
    'tab_history' => 'Historique',
    'config_title' => 'Configuration Wazuh manager',
    'config_desc' => 'Utilisés à l\'installation d\'un agent.',
    'manager_ip' => 'Manager (IP/FQDN)',
    'manager_port' => 'Port manager',
    'registration_port' => 'Port d\'enrôlement',
    'registration_password' => 'Mot de passe d\'enrôlement',
    'default_group' => 'Groupe par défaut',
    'agent_version' => 'Version agent',
    'enable_active_response_global' => 'Active Response activée globalement',
    'api_section' => 'API manager (facultatif, pour push rules)',
    'api_url' => 'URL API',
    'api_user' => 'Utilisateur API',
    'api_password' => 'Mot de passe API',
    'unchanged' => 'Laisser vide pour conserver',
    'save' => 'Sauvegarder',
    // Chaque ligne est un SERVEUR (machines LEFT JOIN wazuh_agents), pas un agent.
    'deploy_title' => 'Les serveurs du parc et leur agent Wazuh',
    'refresh' => 'Rafraichir',
    'no_servers' => 'Aucun serveur à afficher.',
    'sans_agent' => 'aucun agent',
    'col_agent_id' => 'Agent ID',
    'col_status' => 'Statut',
    'col_version' => 'Version',
    'col_group' => 'Groupe',
    'col_actions' => 'Actions',
    'col_network' => 'Reseau',
    'col_criticality' => 'Criticite',
    'col_environment' => 'Env',
    'status_active' => 'Actif',
    'status_disconnected' => 'Déconnecté',
    'status_never' => 'jamais connecté',
    'status_pending' => 'En attente',
    'status_unknown' => 'état inconnu',
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
    'syscheck_frequency' => 'Fréquence FIM (secondes)',
    'fim_paths' => 'Chemins FIM surveillés',
    'fim_paths_hint' => 'un par ligne, debut par /',
    'active_response' => 'Active Response',
    'sca' => 'SCA (Security Configuration Assessment)',
    'rootcheck' => 'Rootcheck',
    'rules_list' => 'Règles, décodeurs et listes CDB en place',
    'new' => 'Nouveau',
    'rule_name' => 'Nom (ex: local_rules)',
    'delete' => 'Supprimer',
    'confirm_delete_rule' => 'Supprimer ce rule ?',
    'history_title' => 'Historique (100 dernieres actions)',
    'history_empty' => 'Aucune action enregistree.',
    'col_date' => 'Date',
    'col_user' => 'Utilisateur',
    'col_action' => 'Action',
    // ── CE QU'ENREGISTRER FAIT, PAR GESTE ───────────────────────────────
    // La configuration est lue par install() et install_all() ; les options
    // (wazuh_machine_options) et les regles (wazuh_rules) ne sont relues que
    // par leurs propres routes. Chaque phrase d'effet reste attachee a SON geste.
    'enr_config_effet' => "Les agents déjà installés ne changent pas.",
    'enr_options_effet' => "⚠ Ces options sont enregistrées mais ne sont appliquées à aucune machine.",
    'enr_regles_effet' => "⚠ Ces règles sont enregistrées mais ne sont déployées sur aucune machine.",

    'fim_aide' => "Un chemin absolu par ligne, 50 au plus.",

    'enr_encours' => 'Enregistrement…',
    'enr_ok' => 'Enregistré.',
    'enr_echec' => "L'enregistrement a échoué.",
    'enr_refuse' => 'Refusé par le serveur : :message',
    'enr_reseau' => "Le serveur n'a pas répondu. Rien n'a été enregistré.",

    'mdp_conserve' => "Un champ vide conserve le mot de passe enregistré.",
    'config_charge' => 'Configuration chargée.',
    'options_charge' => 'Options chargées.',

    'regle_liste_titre' => 'Règles enregistrées',
    'regle_editeur_titre' => 'Créer ou modifier une règle',
    'regle_type' => 'Type',
    'regle_contenu' => 'Contenu',
    'regle_nouvelle' => 'Nouvelle règle',
    'regle_ouvrir' => 'Ouvrir',
    'regle_aide_nom' => 'Lettres, chiffres, tiret et souligné ; 100 caractères au plus.',
    'regle_aide_xml' => "Le XML des règles et décodeurs est vérifié si l'outil de validation est installé sur le serveur.",
    'regle_taille' => '512 Ko au plus.',
    'type_rules' => 'Règles (XML)',
    'type_decoders' => 'Décodeurs (XML)',
    'type_cdb' => 'Liste CDB (texte)',

    'suppr_titre' => 'Supprimer une règle',
    'suppr_question' => 'Supprimer définitivement la règle « :nom » ?',
    'suppr_consequence' => "Elle est supprimée de RootWarden, sans annulation possible. Aucune machine n'est touchée.",
    'suppr_confirmer' => 'Supprimer cette règle',
    'suppr_annuler' => 'Annuler',
    'suppr_ok' => 'Règle supprimée.',
    'suppr_absente' => "Aucune règle de ce nom : rien n'a été supprimé.",

    'loading' => 'Chargement…',
    'saving' => 'Sauvegarde…',
    'saved' => 'Sauvegarde.',
    'pwd_set' => 'une valeur chiffrée est enregistrée',
    'pwd_not_set' => 'aucune valeur enregistrée',

    // ── LES ACTIONS SUR LES MACHINES : NOMMEES, PAS COMPTEES ────────────
    'np_titre' => 'Non disponible dans le portail',
    'np_liste' => "Installer un agent · installer sur tout le parc · relever l'état d'un agent · désinstaller · redémarrer · changer le groupe.",

    // ── DISTINGUER « ZERO MESURE » DE « JE N'AI PAS SU LIRE » ────────────
    'err_config'  => "Impossible de lire la configuration du manager.",
    'err_servers' => "Impossible de lire l'inventaire des agents.",
    'err_options' => "Impossible de lire les options de ce serveur.",
    'err_rules'   => "Impossible de lire la liste des règles.",
    'no_rules'    => "Aucune règle, aucun décodeur, aucune liste CDB.",
    'no_config'   => "Aucune configuration de manager n'est enregistrée.",
    'no_options'  => "Aucune option pour ce serveur : les valeurs par défaut s'appliquent.",
    'choisir_serveur' => 'Choisissez un serveur pour voir ses options.',

    // ── CE QUE LA PAGE FAIT ──────────────────────────────────────────────
    'portee_texte' => "Cette page enregistre des réglages ; elle n'agit sur aucune machine.",

    /*
     * ══ TRENTE-HUIT CLES DE CE CATALOGUE NE SONT PAS RENDUES PAR R1 ══════
     *
     * Ce ne sont PAS des cles mortes : elles appartiennent aux neuf gestes
     * d'ecriture et aux sections que R1 ne porte pas — `btn_install`,
     * `confirm_uninstall`, `prompt_group`, l'historique, l'edition des
     * regles, les onglets.
     *
     * **A LIRE PAR QUI VOUDRAIT LES NETTOYER** : une sonde de cles mortes les
     * signalera, et elle aura raison sur la forme. Elles sont conservees pour
     * R2 et R3, et les retirer obligerait a les re-traduire — dans les deux
     * langues — au moment ou l'on portera les gestes.
     *
     * R1 emprunte `tab_options` comme titre de section : la page rend des
     * sections et non des onglets, et ce libelle dit deja « Options ».
     */
];
