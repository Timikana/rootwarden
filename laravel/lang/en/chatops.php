<?php

/*
 * ChatOps: "chat identifier -> RootWarden account" mappings. Flat keys — the
 * file is loaded as one block by `@json(__('chatops'))`. The key set must stay
 * identical to `lang/fr/chatops.php`. Writing rules: docs/REDACTION-INTERFACE.md.
 */
return [
    'title' => 'ChatOps',
    'desc'  => 'Commands sent from Slack or Teams run on behalf of the mapped RootWarden account.',

    'setup_title'      => 'Configure your messaging platform',
    'setup_url'        => 'Inbound webhook address:',
    'setup_slack'      => 'Slack: create a slash command pointing at this address and set CHATOPS_SLACK_SIGNING_SECRET on the server.',
    'setup_token'      => 'Teams or generic: set CHATOPS_TOKEN on the server and send it in the X-ChatOps-Token header.',
    'setup_activer'    => 'Then set CHATOPS_ENABLED=true.',
    'setup_commands'   => 'Recognised commands',

    'mappings_title' => 'Mappings',
    'f_platform'     => 'Platform',
    'f_chat_id'      => 'Chat identifier',
    'f_user'         => 'RootWarden account',
    'f_label'        => 'Label',
    'btn_add'        => 'Add',
    'tip_add'        => 'Maps this chat identifier to the chosen account.',

    'col_platform' => 'Platform',
    'col_chat_id'  => 'Chat identifier',
    'col_user'     => 'Account',
    'col_label'    => 'Label',

    'loading'  => 'Loading…',
    'empty'    => 'No mapping yet. Map a chat identifier to an account.',
    'enabled'  => 'ChatOps active',
    'disabled' => 'ChatOps disabled',
    'delete'   => 'Delete',

    'confirm_titre'     => 'Delete this mapping?',
    'confirm_aide'      => 'The identifier :chat (:plateforme) will no longer be recognised: commands from that messaging account will be refused.',
    'confirm_supprimer' => 'Delete',
    'confirm_annuler'   => 'Cancel',

    'saved'      => 'Mapping saved.',
    'deleted'    => 'Mapping deleted.',
    'err_chatid' => 'Enter a chat identifier.',
    'err_load'   => 'Could not load the mappings.',
    'err_save'   => 'Saving failed.',
    'err_reseau' => 'The server did not respond. Try again in a moment.',
    'backend_injoignable' => 'Service temporarily unavailable.',
];
