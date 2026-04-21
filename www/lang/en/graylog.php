<?php
// lang/en/graylog.php - Graylog module (rsyslog forwarding + templates)
return [
    'graylog.title' => 'Graylog',
    'graylog.subtitle' => 'rsyslog forwarding to your Graylog server with editable per-source templates.',

    // Tabs
    'graylog.tab_config' => 'Configuration',
    'graylog.tab_deploy' => 'Deployment',
    'graylog.tab_templates' => 'rsyslog templates',
    'graylog.tab_history' => 'History',

    // Configuration
    'graylog.config_title' => 'Graylog server configuration',
    'graylog.config_desc' => 'Logs from machines will be forwarded to this server. Streams and extractors are managed directly on Graylog.',
    'graylog.server_host' => 'Graylog host (IP/FQDN)',
    'graylog.server_port' => 'Port',
    'graylog.protocol' => 'Protocol',
    'graylog.tls_ca' => 'CA path (TLS)',
    'graylog.rl_burst' => 'Rate limit burst (0 = off)',
    'graylog.rl_interval' => 'Rate limit interval (sec)',
    'graylog.save' => 'Save',
    'graylog.saving' => 'Saving…',
    'graylog.saved' => 'Saved.',

    // Deployment
    'graylog.deploy_title' => 'rsyslog deployment',
    'graylog.deploy_desc' => 'Installs rsyslog if missing, writes forwarding rule in /etc/rsyslog.d/ and restarts the service. Enabled templates are pushed too.',
    'graylog.refresh' => 'Refresh',
    'graylog.loading' => 'Loading…',
    'graylog.no_servers' => 'No server available.',

    'graylog.col_status' => 'Status',
    'graylog.col_version' => 'rsyslog version',
    'graylog.col_last_deploy' => 'Last deploy',
    'graylog.col_actions' => 'Actions',
    'graylog.col_date' => 'Date',
    'graylog.col_user' => 'User',
    'graylog.col_action' => 'Action',

    'graylog.status_forwarding' => 'Forwarding active',
    'graylog.status_not_deployed' => 'Not deployed',

    'graylog.btn_deploy' => 'Deploy',
    'graylog.btn_test' => 'Test',
    'graylog.btn_uninstall' => 'Remove',

    'graylog.confirm_deploy' => 'Deploy the rsyslog config on this server (install if missing + restart)?',
    'graylog.confirm_uninstall' => 'Remove RootWarden files from /etc/rsyslog.d/ and restart?',
    'graylog.deploying' => 'Deploying…',
    'graylog.test_sent' => 'Logger sent',

    // Templates
    'graylog.templates_list' => 'rsyslog templates',
    'graylog.new' => 'New',
    'graylog.tpl_name' => 'Name (ex: apache-access)',
    'graylog.tpl_desc' => 'Description (optional)',
    'graylog.tpl_enabled' => 'Push on deploy',
    'graylog.tpl_editor_hint' => 'rsyslog snippet pushed to /etc/rsyslog.d/50-rootwarden-<name>.conf on next deploy.',
    'graylog.delete' => 'Delete',
    'graylog.confirm_delete_template' => 'Delete this template?',
    'graylog.enabled' => 'enabled',
    'graylog.disabled' => 'disabled',

    // History
    'graylog.history_title' => 'History (last 100 actions)',
    'graylog.history_empty' => 'No action recorded yet.',
];
