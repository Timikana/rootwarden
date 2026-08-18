<?php

// lang/fr/tickets.php - Ticketing ITSM.

return [
    'title' => 'Tickets',
    'desc'  => 'Ouvre des tickets dans votre outil ITSM (GLPI, Jira, ServiceNow ou webhook '
             . 'generique) a partir des constats, notamment les CVE. Sans fournisseur configure, '
             . 'les tickets restent locaux a RootWarden.',

    'btn_new' => 'Nouveau ticket',
    'tip_new' => 'Ouvre le formulaire de creation manuelle.',

    // Guidage. Le legacy annonce que le dedoublonnage evite « plusieurs tickets
    // pour la meme alerte ». La cle reelle est le triplet (source, reference,
    // machine) : pour un ticket manuel, cela revient a la MACHINE seule.
    'guide_titre'  => 'Ce qu\'il faut savoir avant de creer',
    'guide_local'  => 'Sans fournisseur ITSM configure, le ticket reste local : c\'est une ligne de suivi '
                    . 'dans RootWarden, rien n\'est envoye a l\'exterieur.',
    'guide_dedup'  => 'Le dedoublonnage porte sur le triplet (source, reference, machine) — PAS sur le resume. '
                    . 'Un ticket manuel n\'ayant ni reference ni source variable, il ne peut donc exister '
                    . 'qu\'UN ticket manuel par machine : une seconde creation rouvre le premier.',
    'guide_cve'    => 'Les tickets issus d\'une CVE portent la reference du CVE : ceux-la se dedoublonnent bien '
                    . 'par alerte, comme attendu.',

    'f_summary'  => 'Resume',
    'f_summary_aide' => 'Obligatoire. Une phrase : c\'est ce que verra la personne qui prend le ticket.',
    'f_machine'  => 'Machine',
    'f_machine_aide' => 'Facultatif — mais c\'est la cle de dedoublonnage d\'un ticket manuel.',
    'no_machine' => '(aucune)',
    'f_desc'     => 'Description',
    'f_desc_aide' => 'Facultatif. Si vide, le resume est repris.',

    'btn_create'  => 'Creer le ticket',
    'tip_create'  => 'Cree le ticket chez le fournisseur configure, ou en local si aucun.',
    'btn_cancel'  => 'Annuler',

    // Avertissement de collision, affiche AVANT le clic.
    'collision' => 'Un ticket manuel existe deja pour cette machine : « :resume ». Creer ici le rouvrira '
                 . 'au lieu d\'en ouvrir un nouveau.',

    'col_when'     => 'Date',
    'col_source'   => 'Source',
    'col_summary'  => 'Resume',
    'col_machine'  => 'Machine',
    'col_provider' => 'Fournisseur',
    'col_ref'      => 'Reference',
    'loading'      => 'Chargement...',

    'provider_on'  => 'Fournisseur ITSM actif',
    'provider_off' => 'Aucun fournisseur configure — les tickets restent locaux',

    'empty'      => 'Aucun ticket',
    'empty_aide' => 'Les tickets naissent d\'un constat — une CVE, un audit — ou du bouton « Nouveau ticket ».',

    'created'     => 'Ticket cree.',
    'deduped'     => 'Aucun ticket cree : il en existait deja un pour cette machine, il a ete rouvert. '
                   . 'Le dedoublonnage porte sur (source, reference, machine), pas sur le resume.',
    'err_load'    => 'Impossible de charger la liste des tickets.',
    'err_create'  => 'La creation du ticket a echoue.',
    'err_summary' => 'Le resume est obligatoire.',
];
