<?php

/**
 * Profil — francais. Parite stricte avec lang/en/profil.php.
 */
return [

    'compte_titre' => 'Compte',
    'compte_texte' => 'Connecté sous :nom, avec le rôle :role.',

    'second_facteur_titre'  => 'Second facteur',
    'second_facteur_valeur' => 'Actif',
    'second_facteur_texte'  => "Un code à usage unique est exigé à chaque connexion. Il n'existe aucun accès sans second facteur.",

    'non_porte_titre' => 'Pas encore ici',
    'non_porte_texte' => 'Les sessions ouvertes et les connexions memorisees ne sont pas encore listees ici : l\'ancien portail les affiche. Le changement de mot de passe, lui, se fait desormais sur cette page.',
    /*
     * ── SOUS-LOT A2 : LE CHANGEMENT DE MOT DE PASSE ──────────────────────
     *
     * La politique est celle du legacy, a l'identique : les deux portails
     * partagent la base, donc une regle plus laxiste d'un cote serait un
     * contournement de l'autre. Le legacy rend UNE seule cle pour les cinq
     * regles de complexite — on garde ce choix : dire QUELLE regle a echoue
     * renseigne autant l'attaquant que la personne.
     */
    'mdp_titre' => 'Changer le mot de passe',
    'mdp_politique' => 'Au moins :longueur caracteres, avec une minuscule, une majuscule, un chiffre et un caractere special. Les :historique derniers mots de passe sont refuses, ainsi que celui en cours.',
    'mdp_actuel' => 'Mot de passe actuel',
    'mdp_nouveau' => 'Nouveau mot de passe',
    'mdp_confirmation' => 'Confirmer le nouveau mot de passe',
    'mdp_enregistrer' => 'Changer le mot de passe',
    'mdp_effet_sessions' => "Vos autres sessions sur l'ANCIEN portail seront fermées — il vérifie à chaque requête — et les connexions mémorisées oubliées. ⚠ Sur CE portail, aucune autre session ne sera fermée : il ne consulte pas encore la table des sessions.",
    'mdp_ok' => 'Mot de passe modifie avec succes.',
    'mdp_erreur_actuel' => 'Mot de passe actuel incorrect.',
    'mdp_erreur_correspondance' => 'Les mots de passe ne correspondent pas.',
    'mdp_erreur_politique' => 'Le mot de passe doit contenir au moins 15 caracteres, une majuscule, une minuscule, un chiffre et un caractere special.',
    'mdp_erreur_historique' => 'Ce mot de passe a deja ete utilise. Choisissez-en un autre.',
    'mdp_erreur_fuite' => 'Ce mot de passe apparait dans une fuite de donnees publique. Choisissez-en un autre.',
    'mdp_erreur_compte' => 'Compte introuvable.',
];
