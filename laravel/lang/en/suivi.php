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
    'col_suivi'         => 'Tracking',
    'aucun'             => 'None',
    'open'              => 'To do',
    'in_progress'       => 'In progress',
    'accepted'          => 'Risk accepted',
    'wont_fix'          => 'Will not fix',
    'resolved'          => 'Resolved by a scan',
    'resolved_aide'     => 'This status is set by the scanner when the vulnerability disappears from a later scan. It cannot be chosen by hand.',
    'ticket'            => 'Create a ticket',
    'ticket_court'     => 'Ticket',
    'ticket_aide'       => 'Opens a ticket for this vulnerability.',
    'ticket_refuse'     => 'Creating tickets requires the portal administration permission, which this account does not have.',
    'ticket_cree'       => 'Ticket created.',
    'ticket_existant'   => 'A ticket already existed for this vulnerability.',
    'ticket_echec'      => 'The ticket could not be created.',
    'enregistre'        => 'Tracking saved.',
    'err_statut'        => 'Unknown status: :statut',
    'err_parametres'    => 'Missing vulnerability or server.',
    'err_machine'       => 'Unknown or inaccessible server.',
    'err_reseau'        => 'The tracking could not be saved.',
    'sans_auteur'       => 'The schema does not record who changed a status.',
];
