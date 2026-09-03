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
    /*
     * ⚠ CETTE PHRASE RENVOYAIT VERS UN PORTAIL QUI VA DISPARAITRE.
     *
     * Elle disait « pas encore disponible sur cette interface, effectuez-la
     * depuis l'ancien portail ». C'etait vrai : le defi n'etait branche NULLE
     * PART sur les cinq chemins de `MOTIFS_STEP_UP`, alors que `politiques.js`
     * et `acces-sftp.js` appellent quatre d'entre eux. L'utilisateur cliquait,
     * recevait ce refus, et n'avait aucun moyen de le lever.
     *
     * Le defi est desormais porte sur les deux ecrans concernes. La phrase dit
     * donc ce qu'il faut FAIRE, sur cette page, et ne nomme plus l'ancien
     * portail — qui n'existera plus apres la bascule.
     *
     * Elle reste NEUTRE sur le canal : c'est un message d'API, lu par un
     * humain seulement si l'ecran n'a pas su ouvrir son panneau.
     */
    'step_up_requis'          => "Cette action exige une re-authentification. Confirmez-la avec votre second facteur.",
    'backend_injoignable'     => 'Le service est momentanément injoignable. Réessayez dans quelques instants.',
];
