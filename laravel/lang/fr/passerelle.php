<?php

/**
 * Passerelle vers le backend — francais.
 *
 * Ces messages partent dans du JSON lu par le frontend, pas seulement a
 * l'ecran : ils doivent rester exacts et sans detail exploitable.
 * Parite stricte avec lang/en/passerelle.php.
 */
return [

    'aucune_route'            => 'Aucune route indiquée.',
    'chemin_invalide'         => 'Chemin invalide.',
    'route_non_autorisee'     => 'Route non autorisée.',
    'privileges_insuffisants' => 'Privilèges insuffisants.',
    'step_up_requis'          => "Cette action exige une re-authentification, qui n'est pas encore disponible sur cette interface. Effectuez-la depuis l'ancien portail.",
    'backend_injoignable'     => 'Le service est momentanément injoignable. Réessayez dans quelques instants.',
];
