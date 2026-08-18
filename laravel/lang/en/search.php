<?php

// lang/en/search.php - Global search.

return [
    'title' => 'Global search',
    'desc'  => 'Search in one place across servers, users, CVEs, tickets and the audit log.',

    'placeholder' => 'A server, a user, a CVE, a ticket...',
    'tip_input'   => 'Cross-cutting search, two characters minimum.',
    'label'       => 'Search term',

    'guide_titre'  => 'What the search covers',
    'guide_portee' => 'Five sources: servers, users, CVEs, tickets and the audit log. Each category returns '
                    . 'at most ten results — the search points you somewhere, it does not replace the '
                    . 'dedicated pages.',
    'guide_droits' => 'It reaches across accounts and the audit log: that is why it is restricted to portal '
                    . 'administration.',
    'guide_liens'  => 'A result leads to the page that owns it. Pages still served by the old portal are '
                    . 'marked with an arrow and open in a new tab.',

    'cat_machines' => 'Servers',
    'cat_users'    => 'Users',
    'cat_cves'     => 'CVEs',
    'cat_tickets'  => 'Tickets',
    'cat_audit'    => 'Audit log',

    'hint_min'     => 'Type at least two characters.',
    'searching'    => 'Searching...',
    'results_for'  => 'result(s) for',
    'no_results'   => 'No result',
    'no_results_aide' => 'None of the five sources contains that term. A server name, an IP address, a CVE '
                       . 'identifier or a ticket summary give the best results.',
    'err'          => 'The search failed.',
    'ancien_portail' => 'opens the old portal in a new tab',
];
