<?php
// lang/en/wazuh.php — Wazuh module (Agent + rules)
return [
    'wazuh.title' => 'Wazuh',
    'wazuh.subtitle' => 'Wazuh agent deployment, per-server options, editable rules/decoders.',

    // Tabs
    'wazuh.tab_config' => 'Configuration',
    'wazuh.tab_deploy' => 'Deployment',
    'wazuh.tab_options' => 'Options',
    'wazuh.tab_rules' => 'Rules & Decoders',
    'wazuh.tab_history' => 'History',

    // Configuration
    'wazuh.config_title' => 'Wazuh manager configuration',
    'wazuh.config_desc' => 'Manager, enrollment password and default group used during installation.',
    'wazuh.manager_ip' => 'Manager (IP/FQDN)',
    'wazuh.manager_port' => 'Manager port',
    'wazuh.registration_port' => 'Enrollment port',
    'wazuh.registration_password' => 'Enrollment password',
    'wazuh.default_group' => 'Default group',
    'wazuh.agent_version' => 'Agent version',
    'wazuh.enable_active_response_global' => 'Global active response enabled',
    'wazuh.api_section' => 'Manager API (optional, to push rules)',
    'wazuh.api_url' => 'API URL',
    'wazuh.api_user' => 'API user',
    'wazuh.api_password' => 'API password',
    'wazuh.unchanged' => 'Leave empty to keep current',
    'wazuh.save' => 'Save',

    // Deployment
    'wazuh.deploy_title' => 'Agent deployment',
    'wazuh.refresh' => 'Refresh',
    'wazuh.no_servers' => 'No server.',
    'wazuh.col_agent_id' => 'Agent ID',
    'wazuh.col_status' => 'Status',
    'wazuh.col_version' => 'Version',
    'wazuh.col_group' => 'Group',
    'wazuh.col_actions' => 'Actions',
    'wazuh.status_active' => 'Active',
    'wazuh.status_disconnected' => 'Disconnected',
    'wazuh.status_never' => 'Never connected',
    'wazuh.status_pending' => 'Pending',
    'wazuh.status_unknown' => 'Unknown',

    'wazuh.btn_install' => 'Install',
    'wazuh.btn_uninstall' => 'Uninstall',
    'wazuh.btn_restart' => 'Restart',
    'wazuh.btn_setgroup' => 'Change group',

    'wazuh.confirm_install' => 'Install Wazuh agent and enroll with the manager?',
    'wazuh.confirm_uninstall' => 'Uninstall the agent?',
    'wazuh.confirm_restart' => 'Restart the agent?',
    'wazuh.prompt_group' => 'New group for this agent?',

    // Options
    'wazuh.server' => 'Server',
    'wazuh.select_server' => '— Pick a server —',
    'wazuh.log_format' => 'Log format',
    'wazuh.syscheck_frequency' => 'FIM frequency (seconds)',
    'wazuh.fim_paths' => 'FIM watched paths',
    'wazuh.fim_paths_hint' => 'one per line, must start with /',
    'wazuh.active_response' => 'Active Response',
    'wazuh.sca' => 'SCA (Security Configuration Assessment)',
    'wazuh.rootcheck' => 'Rootcheck',

    // Rules
    'wazuh.rules_list' => 'Rules / Decoders / CDB',
    'wazuh.new' => 'New',
    'wazuh.rule_name' => 'Name (ex: local_rules)',
    'wazuh.delete' => 'Delete',
    'wazuh.confirm_delete_rule' => 'Delete this rule?',

    // History
    'wazuh.history_title' => 'History (last 100 actions)',
    'wazuh.history_empty' => 'No action recorded yet.',
    'wazuh.col_date' => 'Date',
    'wazuh.col_user' => 'User',
    'wazuh.col_action' => 'Action',

    'wazuh.loading' => 'Loading…',
    'wazuh.saving' => 'Saving…',
    'wazuh.saved' => 'Saved.',
    'wazuh.pwd_set' => 'set',
    'wazuh.pwd_not_set' => 'not set',
];
