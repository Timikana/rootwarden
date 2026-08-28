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
    'subtitle' => 'Wazuh agent deployment, per-server options, editable rules/decoders.',
    'tab_config' => 'Configuration',
    'tab_deploy' => 'Deployment',
    'tab_options' => 'Options',
    'tab_rules' => 'Rules & Decoders',
    'tab_history' => 'History',
    'config_title' => 'Wazuh manager configuration',
    'config_desc' => 'Manager, enrollment password and default group used during installation.',
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
    'deploy_title' => 'Agent deployment',
    'refresh' => 'Refresh',
    'no_servers' => 'No server.',
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
    'status_never' => 'Never connected',
    'status_pending' => 'Pending',
    'status_unknown' => 'Unknown',
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
    'rules_list' => 'Rules / Decoders / CDB',
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
    'pwd_set' => 'set',
    'pwd_not_set' => 'not set',
];
