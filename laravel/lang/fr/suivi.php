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
    'open'              => 'A traiter',
    'in_progress'       => 'En cours',
    'accepted'          => 'Risque accepte',
    'wont_fix'          => 'Ne sera pas corrige',
    'resolved'          => 'Resolu par un scan',
    'resolved_aide'     => 'Ce statut est pose par le scanner lorsque la vulnerabilite disparait d un scan suivant. Il ne se choisit pas a la main.',
    'ticket'            => 'Creer un ticket',
    'ticket_court'     => 'Ticket',
    'ticket_aide'       => 'Ouvre un ticket pour cette vulnerabilite.',
    'ticket_refuse'     => 'La creation de tickets demande la permission d administration du portail, que ce compte n a pas.',
    'ticket_cree'       => 'Ticket cree.',
    'ticket_existant'   => 'Un ticket existait deja pour cette vulnerabilite.',
    'ticket_echec'      => 'Le ticket n a pas pu etre cree.',
    'enregistre'        => 'Suivi enregistre.',
    'err_statut'        => 'Statut inconnu : :statut',
    'err_parametres'    => 'Vulnerabilite ou serveur manquant.',
    'err_machine'       => 'Serveur inconnu ou non accessible.',
    'err_reseau'        => 'Le suivi n a pas pu etre enregistre.',
    'sans_auteur'       => 'Le schema ne conserve pas l auteur d un changement de statut.',
];
