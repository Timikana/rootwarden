<?php
// lang/en/bashrc.php — Bashrc module (standardized .bashrc deployment)
return [
    // Page
    'bashrc.title' => 'Bashrc',
    'bashrc.subtitle' => 'Standardized per-user .bashrc deployment on your servers.',

    // Tabs
    'bashrc.tab_deploy' => 'Deployment',
    'bashrc.tab_history' => 'History',
    'bashrc.tab_template' => 'Template',

    // Selection / config
    'bashrc.server' => 'Target server',
    'bashrc.select_server' => '— Choose a server —',
    'bashrc.mode' => 'Mode',
    'bashrc.mode_overwrite' => 'Overwrite',
    'bashrc.mode_merge' => 'Merge (keep custom blocks)',
    'bashrc.install_figlet' => 'Install figlet',
    'bashrc.figlet_missing' => 'figlet is not installed on this server. The ASCII banner will not render until it is installed.',
    'bashrc.pick_server_first' => 'Select a server to list its users.',
    'bashrc.loading' => 'Loading…',
    'bashrc.no_users' => 'No eligible Linux users (UID>=1000 or root, interactive shell).',
    'bashrc.installing' => 'Installing…',
    'bashrc.deploying' => 'Deploying…',

    // Table
    'bashrc.col_user' => 'User',
    'bashrc.col_home' => 'Home',
    'bashrc.col_shell' => 'Shell',
    'bashrc.col_size' => 'Size',
    'bashrc.col_mtime' => 'Modified',
    'bashrc.col_status' => 'Status',
    'bashrc.col_actions' => 'Actions',
    'bashrc.col_date' => 'Date',
    'bashrc.col_action' => 'Action',
    'bashrc.status_ok' => 'Compliant',
    'bashrc.status_diff' => 'Different',
    'bashrc.status_absent' => 'Missing',
    'bashrc.has_custom' => 'Custom',

    // Buttons
    'bashrc.btn_preview' => 'Preview (diff)',
    'bashrc.btn_deploy' => 'Deploy',
    'bashrc.btn_dry_run' => 'Dry run',
    'bashrc.btn_restore' => 'Restore',

    // Preview / deploy
    'bashrc.preview_title' => 'Change preview',
    'bashrc.preview_empty' => 'No differences to display.',
    'bashrc.deploy_result' => 'Deployment result',
    'bashrc.ok' => 'OK',
    'bashrc.failed' => 'Failed',
    'bashrc.skipped' => 'Skipped',
    'bashrc.dry_would_run' => 'Would deploy (dry run).',

    // Confirmations
    'bashrc.confirm_deploy' => 'Confirm .bashrc deployment for these users?',
    'bashrc.confirm_dry' => 'Run a dry run (no changes)?',
    'bashrc.confirm_restore' => 'Restore the latest backup for this user?',

    // History
    'bashrc.history_title' => 'Deployment history (last 100 actions)',
    'bashrc.history_empty' => 'No action recorded yet.',

    // Template
    'bashrc.template_title' => 'Standardized .bashrc template',
    'bashrc.template_desc' => 'Edit the content that will be deployed. Persisted in DB, source of truth for every deployment.',
    'bashrc.template_lines' => 'Lines',
    'bashrc.template_save' => 'Save',
    'bashrc.template_reset' => 'Cancel changes',
    'bashrc.template_dirty' => 'Unsaved changes',
    'bashrc.template_saved' => 'Template saved.',
    'bashrc.saving' => 'Saving…',
    'bashrc.confirm_save_template' => 'Save the new template? Future deployments will use this content.',
    'bashrc.confirm_reset_template' => 'Discard local changes and restore the last saved version?',
    'bashrc.template_danger' => 'Potentially destructive patterns detected',
    'bashrc.template_danger_confirm' => 'WARNING: the template contains dangerous patterns. Confirm anyway?',
];
