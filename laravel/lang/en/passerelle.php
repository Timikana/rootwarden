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
    'step_up_requis'          => 'This action requires re-authentication, which is not available on this interface yet. Perform it from the previous portal.',
    'backend_injoignable'     => 'The service is temporarily unreachable. Try again in a moment.',
];
