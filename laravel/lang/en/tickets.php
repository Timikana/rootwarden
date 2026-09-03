<?php

// lang/en/tickets.php - ITSM ticketing.

return [
    'title' => 'Tickets',
    'desc'  => 'Opens tickets in your ITSM tool (GLPI, Jira, ServiceNow or generic webhook) from '
             . 'findings, notably CVEs. With no provider configured, tickets stay local to RootWarden.',

    'btn_new' => 'New ticket',
    'tip_new' => 'Opens the manual creation form.',

    // Guidance. The legacy claims deduplication avoids "several tickets for the
    // same alert". The real key is the (source, reference, machine) triple: for
    // a manual ticket that comes down to the MACHINE alone.
    'guide_titre'  => 'What to know before creating one',
    'guide_local'  => 'With no ITSM provider configured, the ticket stays local: it is a tracking row inside '
                    . 'RootWarden, nothing is sent outside.',
    'guide_dedup'  => 'Deduplication keys on the (source, reference, machine) triple — NOT on the summary. '
                    . 'A manual ticket has neither a reference nor a varying source, so only ONE manual '
                    . 'ticket can exist per machine: a second creation reopens the first.',
    'guide_cve'    => 'Tickets raised from a CVE carry the CVE reference: those do deduplicate per alert, '
                    . 'as expected.',

    'f_summary'  => 'Summary',
    'f_summary_aide' => 'Required. One sentence: it is what the person picking up the ticket will see.',
    'f_machine'  => 'Machine',
    'f_machine_aide' => 'Optional — but it is the deduplication key of a manual ticket.',
    'no_machine' => '(none)',
    'f_desc'     => 'Description',
    'f_desc_aide' => 'Optional. If empty, the summary is reused.',

    'btn_create'  => 'Create the ticket',
    'tip_create'  => 'Creates the ticket in the configured provider, or locally if none.',
    'btn_cancel'  => 'Cancel',

    // Collision warning, shown BEFORE the click.
    'collision' => 'A manual ticket already exists for this machine: ":resume". Creating here will reopen it '
                 . 'instead of opening a new one.',

    'col_when'     => 'Date',
    'col_source'   => 'Source',
    'col_summary'  => 'Summary',
    'col_machine'  => 'Machine',
    'col_provider' => 'Provider',
    'col_ref'      => 'Reference',
    'loading'      => 'Loading...',

    'provider_on'  => 'ITSM provider active',
    'provider_off' => 'No provider configured — tickets stay local',

    'empty'      => 'No ticket',
    'empty_aide' => 'Tickets come from a finding — a CVE, an audit — or from the "New ticket" button.',

    'created'     => 'Ticket created.',
    'deduped'     => 'No ticket created: one already existed for this machine and was reopened. '
                   . 'Deduplication keys on (source, reference, machine), not on the summary.',
    'err_load'    => 'Could not load the ticket list.',
    'err_create'  => 'Ticket creation failed.',
    'err_summary' => 'The summary is required.',
];
