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
    'subtitle' => 'Configuration du manager, inventaire des agents, options par serveur et règles en place.',
    'tab_config' => 'Configuration',
    'tab_deploy' => 'Deploiement',
    'tab_options' => 'Options',
    'tab_rules' => 'Rules & Decoders',
    'tab_history' => 'Historique',
    'config_title' => 'Configuration Wazuh manager',
    'config_desc' => 'Manager, mot de passe d\'enrôlement et groupe par défaut, tels qu\'ils seront utilisés à l\'installation.',
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
    // ⚠ E-334 — CE N'EST PAS UNE LISTE D'AGENTS. `GET /wazuh/servers` rend
    // `machines LEFT JOIN wazuh_agents` : chaque ligne est un SERVEUR, et ses
    // colonnes d'agent sont vides quand il n'en a pas. Titrer « Agents du
    // parc » sur trois lignes ferait croire a trois agents installes, alors
    // que `wazuh_agents` porte ZERO ligne. Vu a l'image.
    'deploy_title' => 'Les serveurs du parc et leur agent Wazuh',
    'refresh' => 'Rafraichir',
    'no_servers' => 'Aucun agent Wazuh n\'est enregistré. Ce n\'est pas une erreur : le module n\'a jamais servi sur ce parc.',
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
    'status_disconnected' => 'Deconnecte',
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
    'syscheck_frequency' => 'Frequence FIM (secondes)',
    'fim_paths' => 'Chemins FIM surveilles',
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
    'loading' => 'Chargement…',
    'saving' => 'Sauvegarde…',
    'saved' => 'Sauvegarde.',
    'pwd_set' => 'une valeur chiffrée est enregistrée',
    'pwd_not_set' => 'aucune valeur enregistrée',

    // ══ E-203 bis — CE QUE R1 NE PORTE PAS, NOMME UN PAR UN ══════════════
    //
    // « Neuf gestes ne sont pas portes » serait invérifiable et infalsifiable.
    // On les NOMME. C'est la lecon du `superv` de cette nuit : une declaration
    // qui n'enumere pas ce qu'elle exclut ne peut ni se verifier ni se
    // dementir — et un compte ecrit a cote d'une enumeration se desynchronise.
    // Ici il n'y a PAS de compte : l'enumeration est la seule source.
    'np_titre' => 'Ce que cette page ne fait pas encore',
    'np_liste' => "Installer un agent · installer sur tout le parc · relever l'état d'un agent · désinstaller · redémarrer · changer le groupe — ces six ouvrent une session SSH sur la machine. Et : enregistrer la configuration · enregistrer les options d'un serveur · créer ou supprimer une règle.",
    'np_ouvrir' => "Ouvrir Wazuh sur l'ancien portail",

    /*
     * ⚠ TROIS DE CES GESTES NE PEUVENT PAS PROMETTRE CE QU'UN ECRAN DIRAIT.
     * Releve par lecture ligne a ligne du backend, et il faut que la personne
     * qui les exercera depuis l'ancien portail le sache :
     *
     *   - `group` ne TRANSMET jamais le groupe : la valeur est validee, ecrite
     *     en base, et la seule commande distante est un redemarrage de l'agent.
     *     Le verdict porte donc sur le REDEMARRAGE, pas sur le groupe — et
     *     l'agent qui redemarre se re-inscrit aupres du manager, qui lui
     *     assigne ce qu'il veut ;
     *   - `options` et `rules` (POST) n'atteignent AUCUNE machine. Aucun chemin
     *     de deploiement ne les consomme : on regle des chemins FIM, une
     *     frequence, l'active-response — et rien ne part. La page relit ce
     *     qu'elle a ecrit, donc l'ecran CONFIRME, et la boucle se referme sans
     *     que rien ne soit applique.
     */
    'np_reserve' => "Trois de ces gestes n'ont pas l'effet que leur nom suggère, y compris sur l'ancien portail : changer le groupe ne transmet pas le groupe à la machine, et enregistrer des options ou une règle n'atteint aucun serveur.",

    // ── DISTINGUER « ZERO MESURE » DE « JE N'AI PAS SU LIRE » ────────────
    'err_config'  => "La configuration du manager n'a pas pu être lue. Ce n'est pas « aucune configuration ».",
    'err_servers' => "L'inventaire des agents n'a pas pu être lu. Ce n'est pas « aucun agent ».",
    'err_options' => "Les options de ce serveur n'ont pas pu être lues.",
    'err_rules'   => "La liste des règles n'a pas pu être lue. Ce n'est pas « aucune règle ».",
    'no_rules'    => "Aucune règle, aucun décodeur, aucune liste CDB.",
    'no_config'   => "Aucune configuration de manager n'est enregistrée.",
    'no_options'  => "Aucune option particulière pour ce serveur : les valeurs par défaut s'appliquent.",
    'choisir_serveur' => 'Choisissez un serveur pour voir ses options.',

    // ── CE QUE LA PAGE DIT D'ELLE-MEME ──────────────────────────────────
    'portee_titre' => 'Ce que cette page peut faire aujourd’hui',
    'portee_texte' => "Elle lit : la configuration du manager, les agents enregistrés, les options par serveur et les règles en place. Elle ne joint aucune machine et n'écrit rien.",

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
