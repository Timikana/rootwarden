<?php

/*
 * ChatOps: "chat identifier -> RootWarden account" mappings. Flat keys — the
 * file is loaded as one block by `@json(__('chatops'))`. The key set must stay
 * identical to `lang/fr/chatops.php`.
 */
return [
    'title' => 'ChatOps',
    'desc'  => 'Maps a messaging identifier (Slack, Teams) to a RootWarden account, so that commands sent from chat run on behalf of the right person.',

    'setup_title'      => 'What to configure',
    'setup_url'        => 'Address to declare as the inbound webhook in your messaging platform:',
    'setup_slack'      => 'Slack: create a slash command pointing at this address, and set the signing secret on the server side.',
    'setup_token'      => 'Teams or generic: set a shared token on the server side and send it in the header of every request.',
    'setup_commands'   => 'Recognised commands',
    'setup_changement' => 'This address changed with the new portal: it no longer ends in "webhook.php". Update it in your messaging platform before enabling ChatOps.',

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
