<?php

/*
 * Maintenance windows. Flat keys — loaded as one block by `@json(__('maint'))`.
 * The key set must stay identical to `lang/fr/maint.php`.
 */
return [
    'title' => 'Maintenance windows',
    'desc'  => "Time slots during which changing actions (updates, reboots, deployments) are allowed.",

    'guide_titre'    => "Warning: a window restricts the fleet",
    'guide_aucune'   => "With no window enabled, nothing is restricted.",
    'guide_une'      => "As soon as one window is enabled, changing actions only run during its slots.",
    'guide_role'     => "Superadmins always pass; their bypass is logged.",
    'guide_ailleurs' => "A refusal shows on the action's page (updates, supervision), not here.",

    'etat_libre'     => 'No restriction',
    'etat_restreint' => 'Fleet restricted',
    'etat_machines'  => ':n machine restricted|:n machines restricted',

    'etat_detail'    => ':n window(s) enabled, :g of them global',
    'horloge_serveur' => "⚠ Computed on the server clock (:heure, :decalage), not on your browser's.",

    'btn_new'        => 'New window',
    'tip_new'        => 'Define a range during which mutating actions are allowed.',
    'f_name'         => 'Name',
    'f_scope'        => 'Scope',
    'scope_global'   => 'Global (whole fleet)',
    'scope_machine'  => 'Specific machine',
    'f_machine'      => 'Machine',
    'f_days'         => 'Days',
    'f_start'        => 'Start',
    'f_end'          => 'End',
    'f_enabled'      => 'Enabled',
    'overnight_hint' => "Start after end: the window spans midnight (e.g. 22:00 → 06:00).",
    'btn_save'       => 'Save',
    'btn_cancel'     => 'Cancel',

    'col_name'   => 'Name',
    'col_scope'  => 'Scope',
    'col_days'   => 'Days',
    'col_hours'  => 'Hours',
    'col_status' => 'State',

    'mon' => 'Mon', 'tue' => 'Tue', 'wed' => 'Wed', 'thu' => 'Thu',
    'fri' => 'Fri', 'sat' => 'Sat', 'sun' => 'Sun',

    'loading'    => 'Loading…',
    'empty'      => 'No window defined — so no restriction.',
    'active_now' => 'Open now',
    'closed_now' => 'Closed now',
    'disabled'   => 'Disabled',
    'enable'     => 'Enable',
    'disable'    => 'Disable',
    'delete'     => 'Delete',

    'confirm_titre'     => 'Delete this window?',
    'confirm_aide'      => "The window “:name” will be deleted. If it was the last enabled one, the fleet is no longer restricted.",
    'confirm_supprimer' => 'Delete',
    'confirm_annuler'   => 'Cancel',

    'saved'      => 'Window saved.',
    'deleted'    => 'Window deleted.',
    'err_load'   => 'Could not load the windows.',
    'err_save'   => 'Saving failed.',
    'err_name'   => 'A name is required.',
    'err_days'   => 'Select at least one day.',
    'err_reseau' => 'The server did not respond. Try again in a moment.',
];
