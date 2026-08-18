<?php

/**
 * Portal home — English.
 *
 * Strict parity with lang/fr/accueil.php: same key set, same commit.
 */
return [

    'bienvenue'   => 'Hello :nom',
    'orientation' => 'You are on the new interface. It currently carries authentication and navigation; business pages are still served by the previous portal, reachable from the menu.',

    // Roles
    'role_lecteur'    => 'Reader',
    'role_admin'      => 'Administrator',
    'role_superadmin' => 'Super administrator',

    // Tiles
    'acces_titre' => 'Modules available',
    'acces_texte' => '{0}No module is open to you with the :role role.|{1}A single module is open to you with the :role role.|[2,*]Modules opened by your rights, :role role.',

    'portes_titre' => 'Already ported',
    'portes_texte' => 'How many of your modules the new interface serves. The others open the previous portal in a new tab.',

    'securite_titre'  => 'Second factor',
    'securite_valeur' => 'Active',
    'securite_texte'  => 'Your session was opened with a single-use code. A code already used is refused, even from another browser.',

    'ancien_titre' => 'Previous portal',
    'ancien_texte' => 'Still running, with the same credentials. Menu entries marked with an arrow link straight to it.',

    // Explicit empty state
    'parc_titre' => 'The fleet is not shown here yet',
    'parc_texte' => 'The previous portal dashboard shows fleet state to everyone, without filtering by the machines actually assigned. It will be ported with that separation, and not before. In the meantime, view it from the previous portal.',
];
