<?php

/**
 * Wazuh module — English.
 *
 * Ported from `legacy/lang/en/wazuh.php`. The `wazuh.` prefix is REMOVED:
 * Laravel namespaces by file, so `__('wazuh.title')` resolves `title` here.
 * Keeping it would have produced `wazuh.wazuh.title`.
 *
 * `status_unknown` ALREADY EXISTED in the legacy (`:47`): the status the DSI
 * adopted did not have to be invented, so its badge will not render its key in
 * clear. Fourth occurrence of the pattern, and the first avoided BEFORE the
 * first capture rather than by looking at it.
 *
 * Strict parity with lang/fr/wazuh.php: same key set, same commit.
 */
return [
    'title' => 'Wazuh',
    'subtitle' => 'Manager configuration, agent inventory, per-server options and rules in place.',
    'tab_config' => 'Configuration',
    'tab_deploy' => 'Deployment',
    'tab_options' => 'Options',
    'tab_rules' => 'Rules & Decoders',
    'tab_history' => 'History',
    'config_title' => 'Wazuh manager configuration',
    'config_desc' => 'Manager, enrolment password and default group, as they will be used at install time.',
    'manager_ip' => 'Manager (IP/FQDN)',
    'manager_port' => 'Manager port',
    'registration_port' => 'Enrollment port',
    'registration_password' => 'Enrollment password',
    'default_group' => 'Default group',
    'agent_version' => 'Agent version',
    'enable_active_response_global' => 'Global active response enabled',
    'api_section' => 'Manager API (optional, to push rules)',
    'api_url' => 'API URL',
    'api_user' => 'API user',
    'api_password' => 'API password',
    'unchanged' => 'Leave empty to keep current',
    'save' => 'Save',
    // NOT a list of agents: each row is a SERVER — see fr.
    'deploy_title' => 'Fleet servers and their Wazuh agent',
    'refresh' => 'Refresh',
    'no_servers' => 'No Wazuh agent is registered. This is not an error: the module has never been used on this fleet.',
    'sans_agent' => 'no agent',
    'col_agent_id' => 'Agent ID',
    'col_status' => 'Status',
    'col_version' => 'Version',
    'col_group' => 'Group',
    'col_actions' => 'Actions',
    'col_network' => 'Network',
    'col_criticality' => 'Criticality',
    'col_environment' => 'Env',
    'status_active' => 'Active',
    'status_disconnected' => 'Disconnected',
    'status_never' => 'never connected',
    'status_pending' => 'Pending',
    'status_unknown' => 'unknown state',
    'btn_install' => 'Install',
    'btn_detect' => 'Scan',
    'btn_detect_tip' => 'Detect an existing Wazuh agent without reinstalling',
    'btn_uninstall' => 'Uninstall',
    'btn_restart' => 'Restart',
    'btn_setgroup' => 'Change group',
    'confirm_install' => 'Install Wazuh agent and enroll with the manager?',
    'btn_install_all' => 'Install on all',
    'confirm_install_all' => 'Install Wazuh agent on ALL servers without agent? Sequential operation, may take several minutes.',
    'installing_all' => 'Sequential install in progress on all servers without agent... Do not close this page.',
    'install_all_failures' => 'Failures',
    'confirm_uninstall' => 'Uninstall the agent?',
    'confirm_restart' => 'Restart the agent?',
    'prompt_group' => 'New group for this agent?',
    'server' => 'Server',
    'select_server' => '- Pick a server -',
    'log_format' => 'Log format',
    'syscheck_frequency' => 'FIM frequency (seconds)',
    'fim_paths' => 'FIM watched paths',
    'fim_paths_hint' => 'one per line, must start with /',
    'active_response' => 'Active Response',
    'sca' => 'SCA (Security Configuration Assessment)',
    'rootcheck' => 'Rootcheck',
    'rules_list' => 'Rules, decoders and CDB lists in place',
    'new' => 'New',
    'rule_name' => 'Name (ex: local_rules)',
    'delete' => 'Delete',
    'confirm_delete_rule' => 'Delete this rule?',
    'history_title' => 'History (last 100 actions)',
    'history_empty' => 'No action recorded yet.',
    'col_date' => 'Date',
    'col_user' => 'User',
    'col_action' => 'Action',
    /* R2 — the three write actions. See fr for the measurement: the three do
     * NOT have the same effect, and the screen says so per action.
     *   wazuh_config          read by install()/install_all()  -> DEFERRED effect
     *   wazuh_machine_options read by nothing but its own GET  -> no effect today
     *   wazuh_rules           read by nothing but its own GET  -> no effect today
     */
    'enr_config_effet' => "Saving reaches no machine: this configuration is READ when an agent is installed. It decides what the NEXT installation will do — agents already installed do not change.",
    'enr_options_effet' => "⚠ Saving reaches no machine, AND nothing consumes these options today: no installation path reads them. They are stored and read back by this screen, nothing more.",
    'enr_regles_effet' => "⚠ Saving reaches no machine, AND nothing consumes these rules today: no deployment path reads them. They are stored and read back by this screen, nothing more.",

    'fim_aide' => 'One absolute path per line, at most 50. The server refuses any path not starting with "/": this text describes that, it does not enforce it here.',

    'enr_encours' => 'Saving…',
    'enr_ok' => 'Saved.',
    'enr_echec' => 'Saving failed.',
    'enr_refuse' => 'Refused by the server: :message',
    'enr_reseau' => 'The server did not answer. Nothing was saved.',

    'mdp_conserve' => 'A field left empty KEEPS the password already stored — it does not clear it. There is no clearing action on this screen.',
    'config_charge' => 'Configuration loaded.',
    'options_charge' => 'Options loaded.',

    'regle_liste_titre' => 'Stored rules',
    'regle_editeur_titre' => 'Create or edit a rule',
    'regle_type' => 'Type',
    'regle_contenu' => 'Content',
    'regle_nouvelle' => 'New rule',
    'regle_ouvrir' => 'Open',
    'regle_aide_nom' => 'Letters, digits, dash and underscore, at most 100 characters. The server decides: this text describes the accepted form, it does not enforce it here.',
    'regle_aide_xml' => 'For the "rules" and "decoders" types, the server checks that the content is XML — when its validation tool is available. Without it, it stores without checking: accepted content is therefore not proof that it is valid.',
    'regle_taille' => '512 KB at most.',
    'type_rules' => 'Rules (XML)',
    'type_decoders' => 'Decoders (XML)',
    'type_cdb' => 'CDB list (text)',

    'suppr_titre' => 'Delete a rule',
    'suppr_question' => 'Permanently delete the rule ":nom"?',
    'suppr_consequence' => 'It is removed from the database. No machine is touched — and nothing is restored: there is no undo.',
    'suppr_confirmer' => 'Delete this rule',
    'suppr_annuler' => 'Cancel',
    'suppr_ok' => 'Rule deleted.',
    'suppr_absente' => 'No rule with that name was found: nothing was deleted.',

    'loading' => 'Loading…',
    'saving' => 'Saving…',
    'saved' => 'Saved.',
    'pwd_set' => 'an encrypted value is stored',
    'pwd_not_set' => 'no value stored',

    // What R1 does not port, named one by one — see fr. No count next to the
    // enumeration: the enumeration is the only source.
    'np_titre' => 'What this page cannot do yet',
    'np_liste' => "Install an agent · install across the fleet · read an agent's state · uninstall · restart · change the group. These six — and since R2 these six ONLY — open an SSH session on the machine, which is why they are not here.",
    'np_ouvrir' => 'Open Wazuh on the old portal',
    'np_reserve' => "And ONE of the six does not have the effect its name suggests, even on the old portal: changing the group never sends the group to the machine — the value is validated, written to the database, and the only remote command is an agent restart. The verdict is about the RESTART. (The other two actions this sentence used to name — saving options, saving a rule — are on this page now, each with what saving does and does not do.)",

    'err_config'  => 'The manager configuration could not be read. This is not "no configuration".',
    'err_servers' => 'The agent inventory could not be read. This is not "no agent".',
    'err_options' => "This server's options could not be read.",
    'err_rules'   => 'The rule list could not be read. This is not "no rule".',
    'no_rules'    => 'No rule, no decoder, no CDB list.',
    'no_config'   => 'No manager configuration is stored.',
    'no_options'  => 'No specific option for this server: the defaults apply.',
    'choisir_serveur' => 'Choose a server to see its options.',

    'portee_titre' => 'What this page can do today',
    'portee_texte' => "It reads: the manager configuration, registered agents, per-server options and the rules in place. Since R2 it also WRITES: the configuration, a server's options, and creating, editing or deleting a rule. It joins NO machine — the six actions that open an SSH session are not here, and each write action states below what saving does and does not do.",

    /*
     * Thirty-eight keys of this catalogue are NOT rendered by R1. They are not
     * dead: they belong to the nine write actions and to the sections R1 does
     * not port. A dead-key probe will flag them and will be right about the
     * form — they are kept for R2 and R3. See fr.
     */
];
