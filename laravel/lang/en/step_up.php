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
];
