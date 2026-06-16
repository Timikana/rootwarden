<?php
// lang/en/tickets.php - ITSM ticketing
return [
    'nav.tickets' => 'Tickets',
    'nav.tip_tickets' => 'ITSM tickets (GLPI/Jira/ServiceNow) - CVE to ticket',

    'tickets.title' => 'Tickets',
    'tickets.desc' => 'Create tickets in your ITSM tool (GLPI, Jira, ServiceNow or a generic webhook) from findings, notably CVEs. If no provider is configured, tickets stay local.',
    'tickets.btn_new' => 'New ticket',
    'tickets.f_summary' => 'Summary',
    'tickets.f_machine' => 'Machine',
    'tickets.no_machine' => '(none)',
    'tickets.f_desc' => 'Description',
    'tickets.btn_create' => 'Create',
    'tickets.btn_cancel' => 'Cancel',
    'tickets.col_when' => 'Date',
    'tickets.col_source' => 'Source',
    'tickets.col_summary' => 'Summary',
    'tickets.col_machine' => 'Machine',
    'tickets.col_provider' => 'Provider',
    'tickets.col_ref' => 'Reference',
    'tickets.loading' => 'Loading...',

    // JS
    'js.tickets.provider_on' => 'ITSM provider active',
    'js.tickets.provider_off' => 'No provider configured (local tickets)',
    'js.tickets.empty' => 'No ticket.',
    'js.tickets.created' => 'Ticket created.',
    'js.tickets.deduped' => 'Ticket already exists (deduplicated).',
    'js.tickets.err_load' => 'Failed to load.',
    'js.tickets.err_create' => 'Failed to create.',
    'js.tickets.err_summary' => 'Summary is required.',
];
