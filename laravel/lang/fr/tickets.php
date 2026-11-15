<?php

// lang/fr/tickets.php - Ticketing ITSM.

return [
    'title' => 'Tickets',
    'desc'  => "Ouvre des tickets dans votre outil ITSM (GLPI, Jira, ServiceNow ou webhook) à partir des constats, notamment les CVE. Sans fournisseur, ils restent dans RootWarden.",

    'btn_new' => 'Nouveau ticket',
    'tip_new' => "Ouvre le formulaire de création.",

    // Guidage. Le legacy annonce que le dedoublonnage evite « plusieurs tickets
    // pour la meme alerte ». La cle reelle est le triplet (source, reference,
    // machine) : pour un ticket manuel, cela revient a la MACHINE seule.
    'guide_titre'  => "Avant de créer un ticket",
    'guide_local'  => "Sans fournisseur ITSM, le ticket reste local : rien n'est envoyé à l'extérieur.",
    'guide_dedup'  => "Un seul ticket manuel par machine : en créer un second rouvre le premier.",
    'guide_cve'    => "Les tickets issus d'une CVE sont uniques par alerte.",

    'f_summary'  => "Résumé",
    'f_summary_aide' => "Une phrase, lue par la personne qui prend le ticket.",
    'f_machine'  => 'Machine',
    'f_machine_aide' => "Facultatif. Un seul ticket manuel par machine.",
    'no_machine' => '(aucune)',
    'f_desc'     => 'Description',
    'f_desc_aide' => "Facultatif. Vide, elle reprend le résumé.",

    'btn_create'  => "Créer le ticket",
    'tip_create'  => "Crée le ticket chez le fournisseur configuré, sinon dans RootWarden.",
    'btn_cancel'  => 'Annuler',

    // Avertissement de collision, affiche AVANT le clic.
    'collision' => "Un ticket manuel existe déjà pour cette machine : « :resume ». Il sera rouvert au lieu d'en créer un nouveau.",

    'col_when'     => 'Date',
    'col_source'   => 'Source',
    'col_summary'  => "Résumé",
    'col_machine'  => 'Machine',
    'col_provider' => 'Fournisseur',
    'col_ref'      => "Référence",
    'loading'      => "Chargement…",

    'provider_on'  => 'Fournisseur ITSM actif',
    'provider_off' => "Aucun fournisseur configuré : les tickets restent locaux",

    'empty'      => 'Aucun ticket',
    'empty_aide' => "Les tickets naissent d'un constat (CVE, audit) ou du bouton « Nouveau ticket ».",

    'created'     => "Ticket créé.",
    'deduped'     => "Aucun ticket créé : celui de cette machine a été rouvert.",
    'err_load'    => 'Impossible de charger la liste des tickets.',
    'err_create'  => "La création du ticket a échoué.",
    'err_summary' => "Le résumé est obligatoire.",
];
