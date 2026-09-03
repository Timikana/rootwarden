<?php

/*
 * Step-up re-authentication. Refusal messages stay deliberately terse: they say
 * that we refuse, not what would be needed to succeed.
 */
return [
    'valide'               => 'Re-authentication accepted.',
    'code_invalide'        => 'Invalid six-digit code.',
    'code_deja_utilise'    => 'That code has already been used. Wait for the next one.',
    'trop_de_tentatives'   => 'Too many attempts. Wait one minute.',
    'action_inconnue'      => 'This action does not require re-authentication.',
    'sans_second_facteur'  => 'No second factor is configured on this account.',
    'revoque'              => 'Privileges released.',
    'session_absente'      => 'Session expired. Please sign in again.',

    // Panel labels live HERE and not in each module: `comptes` and
    // `permissions` carry their own; the two new consumers read these. Four
    // copies of one label diverge, and this one describes a guard.
    'panneau_titre'   => 'Confirm with your second factor',
    'panneau_aide'    => 'This action writes a rule on a real machine. Enter the six-digit code from your authenticator: the re-authentication lasts fifteen minutes, and for THIS action only.',
    'panneau_code'    => 'Six-digit code',
    'panneau_valider' => 'Confirm',
    'panneau_annuler' => 'Cancel',
    'panneau_echec'   => 'The re-authentication did not succeed.',
];
