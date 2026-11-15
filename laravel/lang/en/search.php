<?php

// lang/en/search.php - Global search.

return [
    'title' => 'Global search',
    'desc'  => "Servers, users, CVEs, tickets and the audit log, in a single field.",

    'placeholder' => "Server, user, CVE, ticket…",
    'tip_input'   => "At least two characters.",
    'label'       => "Search term",
    /* Header search panel. Every other label is REUSED from this same list, so
     * one state never gets two wordings. */
    'menu_ouvrir' => 'Search',
    'menu_voir_tout' => 'Open the full search',

    'guide_titre'  => 'What the search covers',
    'guide_portee' => "At most ten results per category: search points you to the page that manages the item.",
    'guide_droits' => "Reserved to portal administration, since it spans accounts and the audit log.",
    'guide_liens'  => "Each result leads to the page that manages it.",

    'cat_machines' => 'Servers',
    'cat_users'    => 'Users',
    'cat_cves'     => 'CVEs',
    'cat_tickets'  => 'Tickets',
    'cat_audit'    => 'Audit log',

    'hint_min'     => "Type at least two characters.",
    'searching'    => "Searching…",
    'results_for'  => "result(s) for",
    'no_results'   => "No results",
    'no_results_aide' => "Try a server name, an IP address, a CVE identifier or a word from a ticket.",
    'err'          => "The search failed.",
    'ancien_portail' => "old portal, in a new tab",
];
