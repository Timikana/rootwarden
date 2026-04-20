<?php
// lang/en/graylog.php — Graylog module (Sidecar + collectors)
return [
    'graylog.title' => 'Graylog',
    'graylog.subtitle' => 'Graylog Sidecar deployment and log collector management.',

    // Tabs
    'graylog.tab_config' => 'Configuration',
    'graylog.tab_deploy' => 'Deployment',
    'graylog.tab_collectors' => 'Collectors',
    'graylog.tab_history' => 'History',

    // Configuration
    'graylog.config_title' => 'Graylog server configuration',
    'graylog.config_desc' => 'Server URL, API token and sidecar version to deploy on machines.',
    'graylog.server_url' => 'Server URL',
    'graylog.api_token' => 'API token',
    'graylog.api_token_placeholder' => 'Leave empty to keep current',
    'graylog.tls_verify' => 'Verify TLS certificate',
    'graylog.sidecar_version' => 'Sidecar version',
    'graylog.token_set' => 'set',
    'graylog.token_not_set' => 'not set',

    // Deployment
    'graylog.deploy_title' => 'Sidecar deployment',
    'graylog.refresh' => 'Refresh',
    'graylog.no_servers' => 'No server available.',
    'graylog.col_status' => 'Status',
    'graylog.col_version' => 'Version',
    'graylog.col_actions' => 'Actions',
    'graylog.status_running' => 'Running',
    'graylog.status_stopped' => 'Stopped',
    'graylog.status_never' => 'Not installed',

    'graylog.btn_install' => 'Install',
    'graylog.btn_uninstall' => 'Uninstall',
    'graylog.btn_restart' => 'Restart',
    'graylog.btn_register' => 'Check',

    'graylog.confirm_install' => 'Install the Graylog sidecar (filebeat) on this server?',
    'graylog.confirm_uninstall' => 'Uninstall the sidecar? Logs will stop being shipped.',
    'graylog.installing' => 'Installing…',

    // Collectors
    'graylog.collectors_list' => 'Collectors',
    'graylog.new' => 'New',
    'graylog.col_name' => 'Collector name',
    'graylog.col_tags' => 'Tags (CSV)',
    'graylog.save' => 'Save',
    'graylog.delete' => 'Delete',
    'graylog.saving' => 'Saving…',
    'graylog.saved' => 'Saved.',
    'graylog.confirm_delete_collector' => 'Delete this collector?',

    // History
    'graylog.history_title' => 'History (last 100 actions)',
    'graylog.history_empty' => 'No action recorded yet.',
    'graylog.col_date' => 'Date',
    'graylog.col_user' => 'User',
    'graylog.col_action' => 'Action',

    'graylog.loading' => 'Loading…',
];
