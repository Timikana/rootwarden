<?php

/**
 * Backend gateway — English.
 *
 * These messages travel in JSON read by the frontend, not only to the screen:
 * they must stay accurate and free of exploitable detail.
 * Strict parity with lang/fr/passerelle.php.
 */
return [

    'aucune_route'            => 'No route specified.',
    'chemin_invalide'         => 'Invalid path.',
    'route_non_autorisee'     => 'Route not allowed.',
    'privileges_insuffisants' => 'Insufficient privileges.',
    // This sentence pointed at a portal that is going away — see the note in
    // `lang/fr/passerelle.php`. The challenge is now ported on the two screens
    // that call these routes.
    'step_up_requis'          => 'This action requires re-authentication. Confirm it with your second factor.',
    'backend_injoignable'     => 'The service is temporarily unreachable. Try again in a moment.',
];
