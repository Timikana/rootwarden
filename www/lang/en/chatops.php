<?php
// lang/en/chatops.php - Bidirectional ChatOps
return [
    'nav.chatops' => 'ChatOps',
    'nav.tip_chatops' => 'Commands/approvals from Slack or Teams (bidirectional)',

    'chatops.title' => 'ChatOps (Slack / Teams)',
    'chatops.desc' => 'Drive RootWarden from chat: check fleet status and approve/reject requests from Slack or Teams. Outbound notifications stay configured via webhooks.',
    'chatops.setup_title' => 'Inbound webhook setup',
    'chatops.setup_url' => 'URL to set as the target of the Slack slash command (or Teams outgoing webhook):',
    'chatops.setup_slack' => 'Slack: create a slash command pointing to this URL and set CHATOPS_SLACK_SIGNING_SECRET (signature verified).',
    'chatops.setup_token' => 'Teams / generic: send the X-ChatOps-Token header = CHATOPS_TOKEN (shared token).',
    'chatops.setup_commands' => 'Available commands',
    'chatops.mappings_title' => 'Chat -> RootWarden user mapping',
    'chatops.f_platform' => 'Platform',
    'chatops.f_chat_id' => 'Chat ID',
    'chatops.f_user' => 'User',
    'chatops.f_label' => 'Label',
    'chatops.btn_add' => 'Add',
    'chatops.col_platform' => 'Platform',
    'chatops.col_chat_id' => 'Chat ID',
    'chatops.col_user' => 'User',
    'chatops.col_label' => 'Label',
    'chatops.loading' => 'Loading...',

    // JS
    'js.chatops.enabled' => 'ChatOps enabled',
    'js.chatops.disabled' => 'ChatOps disabled (set CHATOPS_ENABLED + secret/token)',
    'js.chatops.empty' => 'No mapping. Link a chat ID to a user.',
    'js.chatops.delete' => 'Delete',
    'js.chatops.saved' => 'Mapping saved.',
    'js.chatops.deleted' => 'Mapping deleted.',
    'js.chatops.confirm_delete' => 'Delete this mapping?',
    'js.chatops.err_load' => 'Failed to load.',
    'js.chatops.err_save' => 'Failed to save.',
    'js.chatops.err_chatid' => 'Chat ID is required.',
];
