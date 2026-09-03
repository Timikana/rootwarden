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
    'loading' => 'Loading…',
    'saving' => 'Saving…',
    'saved' => 'Saved.',
    'pwd_set' => 'an encrypted value is stored',
    'pwd_not_set' => 'no value stored',

    // What R1 does not port, named one by one — see fr. No count next to the
    // enumeration: the enumeration is the only source.
    'np_titre' => 'What this page cannot do yet',
    'np_liste' => "Install an agent · install across the fleet · read an agent's state · uninstall · restart · change the group — these six open an SSH session on the machine. And: save the configuration · save a server's options · create or delete a rule.",
    'np_ouvrir' => 'Open Wazuh on the old portal',
    'np_reserve' => "Three of these actions do not have the effect their name suggests, even on the old portal: changing the group does not send the group to the machine, and saving options or a rule reaches no server.",

    'err_config'  => 'The manager configuration could not be read. This is not "no configuration".',
    'err_servers' => 'The agent inventory could not be read. This is not "no agent".',
    'err_options' => "This server's options could not be read.",
    'err_rules'   => 'The rule list could not be read. This is not "no rule".',
    'no_rules'    => 'No rule, no decoder, no CDB list.',
    'no_config'   => 'No manager configuration is stored.',
    'no_options'  => 'No specific option for this server: the defaults apply.',
    'choisir_serveur' => 'Choose a server to see its options.',

    'portee_titre' => 'What this page can do today',
    'portee_texte' => 'It reads: the manager configuration, registered agents, per-server options and the rules in place. It joins no machine and writes nothing.',

    /*
     * Thirty-eight keys of this catalogue are NOT rendered by R1. They are not
     * dead: they belong to the nine write actions and to the sections R1 does
     * not port. A dead-key probe will flag them and will be right about the
     * form — they are kept for R2 and R3. See fr.
     */
];
