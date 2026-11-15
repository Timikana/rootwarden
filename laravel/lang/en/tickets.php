<?php

// lang/en/tickets.php - ITSM ticketing.

return [
    'title' => 'Tickets',
    'desc'  => "Opens tickets in your ITSM tool (GLPI, Jira, ServiceNow or webhook) from findings, CVEs in particular. Without a provider, they stay in RootWarden.",

    'btn_new' => 'New ticket',
    'tip_new' => "Opens the creation form.",

    // Guidance. The legacy claims deduplication avoids "several tickets for the
    // same alert". The real key is the (source, reference, machine) triple: for
    // a manual ticket that comes down to the MACHINE alone.
    'guide_titre'  => "Before creating a ticket",
    'guide_local'  => "Without an ITSM provider, the ticket stays local: nothing is sent outside.",
    'guide_dedup'  => "One manual ticket per machine: creating a second one reopens the first.",
    'guide_cve'    => "Tickets raised from a CVE are unique per alert.",

    'f_summary'  => "Summary",
    'f_summary_aide' => "One sentence, read by whoever takes the ticket.",
    'f_machine'  => 'Machine',
    'f_machine_aide' => "Optional. One manual ticket per machine.",
    'no_machine' => '(none)',
    'f_desc'     => 'Description',
    'f_desc_aide' => "Optional. If empty, the summary is reused.",

    'btn_create'  => "Create the ticket",
    'tip_create'  => "Creates the ticket with the configured provider, otherwise in RootWarden.",
    'btn_cancel'  => 'Cancel',

    // Collision warning, shown BEFORE the click.
    'collision' => "A manual ticket already exists for this machine: “:resume”. It will be reopened instead of creating a new one.",

    'col_when'     => 'Date',
    'col_source'   => 'Source',
    'col_summary'  => "Summary",
    'col_machine'  => 'Machine',
    'col_provider' => 'Provider',
    'col_ref'      => "Reference",
    'loading'      => "Loading…",

    'provider_on'  => 'ITSM provider active',
    'provider_off' => "No provider configured: tickets stay local",

    'empty'      => 'No ticket',
    'empty_aide' => "Tickets come from a finding (CVE, audit) or the “New ticket” button.",

    'created'     => "Ticket created.",
    'deduped'     => "No ticket created: this machine's ticket was reopened.",
    'err_load'    => 'Could not load the ticket list.',
    'err_create'  => "Ticket creation failed.",
    'err_summary' => "The summary is required.",
];
