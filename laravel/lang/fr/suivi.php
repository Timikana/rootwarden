<?php

/**
 * Module `security/`, sous-lot S5 : le suivi de remediation.
 *
 * UN SEUL VOCABULAIRE PAR ETAT. Le legacy en portait DEUX pour les memes
 * statuts — `Open`/`Accepte` dans son selecteur, `Ouverte`/`Acceptee` dans son
 * message de confirmation — dont un en anglais. Les libelles ci-dessous sont
 * les seuls, et ils disent ce que l'etat SIGNIFIE plutot que de recopier le nom
 * technique de l'ENUM.
 */

return [
    'col_suivi'         => 'Suivi',
    'aucun'             => 'Aucun',
    'open'              => "À traiter",
    'in_progress'       => 'En cours',
    'accepted'          => "Risque accepté",
    'wont_fix'          => "Ne sera pas corrigé",
    'resolved'          => "Résolu par un scan",
    'resolved_aide'     => "Posé par le scanner quand la vulnérabilité disparaît d'un scan suivant ; il ne se choisit pas.",
    'ticket'            => "Créer un ticket",
    'ticket_court'     => 'Ticket',
    'ticket_aide'       => "Ouvre un ticket pour cette vulnérabilité.",
    'ticket_refuse'     => "Créer un ticket demande la permission d'administration du portail.",
    'ticket_cree'       => "Ticket créé.",
    'ticket_existant'   => "Un ticket existait déjà pour cette vulnérabilité.",
    'ticket_echec'      => "Le ticket n'a pas pu être créé.",
    'enregistre'        => "Suivi enregistré.",
    'err_statut'        => 'Statut inconnu : :statut',
    'err_parametres'    => "Vulnérabilité ou serveur manquant.",
    'err_machine'       => 'Serveur inconnu ou non accessible.',
    'err_reseau'        => "Le suivi n'a pas pu être enregistré.",
    'sans_auteur'       => "L'auteur d'un changement de statut n'est pas conservé.",
];
