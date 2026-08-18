<?php

/**
 * Socle d'authentification — francais.
 *
 * Parite stricte avec lang/en/auth.php : meme jeu de cles, meme commit.
 * Une cle absente ne provoque pas d'erreur : elle affiche son IDENTIFIANT a
 * l'ecran, ce qui passe inapercu en relecture.
 */
return [

    // Etapes de la connexion — annoncer le parcours plutot que le faire decouvrir
    'etape_identifiants'   => 'Identifiants',
    'etape_second_facteur' => 'Second facteur',
    'etape_acces'          => 'Accès',
    'revenir'              => 'Revenir',

    // Connexion
    'connexion_titre'        => 'Connexion',
    'connexion_sous_titre'   => 'Connexion au portail',
    'connexion_identifiant'  => 'Identifiant',
    'connexion_mot_de_passe' => 'Mot de passe',
    'connexion_valider'      => 'Se connecter',
    'connexion_aide'         => "Un code à usage unique vous sera demandé à l'étape suivante.",

    // Second facteur
    'second_facteur_titre'       => 'Vérification en deux étapes',
    'second_facteur_sous_titre'  => 'Code TOTP',
    'second_facteur_instruction' => 'Entrez le code à 6 chiffres de votre application d\'authentification.',
    'second_facteur_valider'     => 'Vérifier',
    'second_facteur_aide'        => "Le code change toutes les 30 secondes. Un code déjà utilisé est refusé : attendez le suivant.",

    // Enrôlement
    'enrolement_titre'       => 'Second facteur à configurer',
    'enrolement_explication' => 'Ce compte n\'a pas encore de second facteur. L\'enrôlement n\'est pas encore disponible sur cette interface : effectuez-le depuis l\'ancien portail, puis revenez ici.',

    // Conditions d'utilisation
    'cgu_titre'      => 'Conditions d\'utilisation',
    'cgu_sous_titre' => 'Dernière étape avant l\'accès au portail.',
    'cgu_accepter'   => 'J\'accepte',
    'cgu_refuser'    => 'Refuser et se déconnecter',

    // Portail
    'accueil_titre'  => 'Accueil',
    'profil_titre'   => 'Profil',
    'deconnexion'    => 'Se déconnecter',
    'connecte_en_tant_que' => 'Connecté en tant que',

    // Erreurs
    'erreur_identifiants'        => 'Identifiant ou mot de passe incorrect.',
    'erreur_verrouille'          => 'Compte temporairement verrouillé. Réessayez plus tard.',
    'erreur_code_invalide'       => 'Code TOTP invalide. Veuillez réessayer.',
    'erreur_code_deja_utilise'   => 'Ce code a déjà été utilisé. Attendez le prochain code.',
    'erreur_trop_de_tentatives'  => 'Trop de tentatives. Patientez une minute.',
    'erreur_sans_secret'         => 'Aucun second facteur n\'est configuré sur ce compte.',
    'changement_requis'          => "Votre mot de passe doit être changé. Cette page n'est pas encore portée : effectuez le changement depuis l'ancien portail.",

    // Migration
    'socle_avertissement' => 'Seul le socle d\'authentification est porté. Les pages du portail restent sur l\'ancienne interface.',
    'ouvrir_ancien_portail' => 'Ouvrir l\'ancien portail',
];
