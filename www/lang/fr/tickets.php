<?php
// lang/fr/tickets.php - Ticketing ITSM
return [
    'nav.tickets' => 'Tickets',
    'nav.tip_tickets' => 'Tickets ITSM (GLPI/Jira/ServiceNow) - CVE vers ticket',

    'tickets.title' => 'Tickets',
    'tickets.desc' => 'Cree des tickets dans votre outil ITSM (GLPI, Jira, ServiceNow ou webhook generique) a partir des findings, notamment CVE. Si aucun fournisseur n\'est configure, les tickets restent locaux.',
    'tickets.btn_new' => 'Nouveau ticket',
    'tickets.tip_new' => 'Ouvrir le formulaire de creation manuelle d\'un ticket.',
    'tickets.f_summary' => 'Resume',
    'tickets.f_machine' => 'Machine',
    'tickets.no_machine' => '(aucune)',
    'tickets.f_desc' => 'Description',
    'tickets.btn_create' => 'Creer',
    'tickets.tip_create' => 'Creer le ticket dans le fournisseur ITSM configure (ou en local si aucun).',
    'tickets.btn_cancel' => 'Annuler',
    'tickets.col_when' => 'Date',
    'tickets.col_source' => 'Source',
    'tickets.col_summary' => 'Resume',
    'tickets.col_machine' => 'Machine',
    'tickets.col_provider' => 'Fournisseur',
    'tickets.col_ref' => 'Reference',
    'tickets.loading' => 'Chargement...',

    // JS
    'js.tickets.provider_on' => 'Fournisseur ITSM actif',
    'js.tickets.provider_off' => 'Aucun fournisseur configure (tickets locaux)',
    'js.tickets.empty' => 'Aucun ticket.',
    'js.tickets.created' => 'Ticket cree.',
    'js.tickets.deduped' => 'Ticket deja existant (dedoublonne).',
    'js.tickets.err_load' => 'Erreur de chargement.',
    'js.tickets.err_create' => 'Echec de creation.',
    'js.tickets.err_summary' => 'Le resume est requis.',
];
