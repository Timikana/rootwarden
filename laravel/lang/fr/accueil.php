<?php

/**
 * Accueil du portail — francais.
 *
 * Parite stricte avec lang/en/accueil.php : meme jeu de cles, meme commit.
 */
return [

    'bienvenue'   => 'Bonjour :nom',
    'orientation' => "Vous êtes sur la nouvelle interface. Elle porte pour l'instant l'authentification et la navigation ; les pages métier restent servies par l'ancien portail, accessibles depuis le menu.",

    // Roles
    'role_lecteur'    => 'Lecteur',
    'role_admin'      => 'Administrateur',
    'role_superadmin' => 'Superadministrateur',

    // Tuiles
    'acces_titre' => 'Modules accessibles',
    'acces_texte' => '{0}Aucun module ne vous est ouvert avec le rôle :role.|{1}Un seul module vous est ouvert avec le rôle :role.|[2,*]Modules ouverts par vos droits, rôle :role.',

    'portes_titre' => 'Déjà portés',
    'portes_texte' => "Nombre de vos modules servis par la nouvelle interface. Les autres ouvrent l'ancien portail dans un nouvel onglet.",

    'securite_titre'  => 'Second facteur',
    'securite_valeur' => 'Actif',
    'securite_texte'  => "Votre session a été ouverte avec un code à usage unique. Un code déjà utilisé est refusé, même depuis un autre navigateur.",

    'ancien_titre' => 'Ancien portail',
    'ancien_texte' => "Toujours en service, avec les mêmes identifiants. Les entrées de menu marquées d'une flèche y renvoient directement.",

    // Etat vide, explicite
    'parc_titre' => "Le parc n'est pas encore affiché ici",
    'parc_texte' => "Le tableau de bord de l'ancien portail montre l'état du parc à tout le monde, sans filtrer selon les machines réellement attribuées. Il sera porté avec ce cloisonnement, et pas avant. En attendant, consultez-le depuis l'ancien portail.",
];
