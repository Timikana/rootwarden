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
    'memorisation_libelle' => 'Se souvenir de moi sur cet appareil',
    'memorisation_duree' => 'Pendant :jours jours, ce navigateur retiendra votre identité — mais il vous demandera TOUJOURS votre second facteur. Il ne vous connecte jamais tout seul.',
    'memorisation_un_appareil' => 'Un seul appareil à la fois : cocher cette case sur un autre navigateur annule celui-ci. C\'est une limite du produit, pas un réglage.',
    'memorisation_ancien_portail' => 'Et si vous passez par l\'ancien portail, il effacera cette mémorisation — le temps de la migration, les deux ne la partagent pas.',
    'connexion_valider'      => 'Se connecter',
    'connexion_aide'         => "Un code à usage unique vous sera demandé à l'étape suivante.",

    // Second facteur
    'second_facteur_titre'       => 'Vérification en deux étapes',
    'second_facteur_sous_titre'  => 'Code TOTP',
    'second_facteur_instruction' => 'Entrez le code à 6 chiffres de votre application d\'authentification.',
    'second_facteur_valider'     => 'Vérifier',
    'second_facteur_aide'        => "Le code change toutes les 30 secondes. Un code déjà utilisé est refusé : attendez le suivant.",

    // Enrôlement
    'enrolement_qr_alt' => 'QR code à scanner avec votre application d\'authentification',
    'enrolement_saisie_manuelle' => 'Vous ne pouvez pas scanner ? Saisissez cette clé manuellement dans votre application :',
    'enrolement_activer' => 'Activer',
    'enrolement_titre'       => 'Second facteur à configurer',
    'enrolement_explication' => 'Ce compte n\'a pas encore de second facteur. Scannez ce QR code avec votre application d\'authentification, puis saisissez le code affiché pour l\'activer.',

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
    /*
     * ⚠ CE BANDEAU ENVOYAIT AILLEURS, 48 LIGNES AU-DESSUS DU FORMULAIRE.
     *
     * Il disait « cette page n'est pas encore portee : effectuez le changement
     * depuis l'ancien portail ». Or `profil.blade.php:56` porte le formulaire,
     * `web.php:111` sa route, et `MotDePasse.php:192` remet
     * `force_password_change` a zero. **Le formulaire est sur la page qui
     * affirmait qu'il n'y etait pas.**
     *
     * Cinquieme occurrence du defaut signature de ce chantier — une phrase
     * vraie a l'ecriture, devenue fausse quand la capacite a ete portee, sans
     * que rien ne la touche. Et la plus couteuse des cinq :
     *
     *   perdre un bouton SE VOIT.
     *   envoyer l'utilisateur ailleurs alors que le bouton est la NE SE VOIT PAS.
     *
     * MESURE DU 2026-09-03, et elle corrige DANS LES DEUX SENS le releve qui
     * m'a ete transmis :
     *   12 comptes actifs (et non 10), 8 porteurs du drapeau (et non 6)
     *   MAIS 5 des 8 sont des comptes `e2e_test_*` crees par les suites
     *   -> TROIS comptes reels concernes, dont `superadmin`
     * « 67 % des comptes actifs » serait exact et trompeur : ce qui compte est
     * le nombre de personnes, pas le nombre de lignes.
     *
     * Le bandeau reste CONDITIONNEL — une reserve sans objet devient un decor.
     */
    'changement_requis'          => "Votre mot de passe doit être changé. Le formulaire est sur cette page, juste en dessous.",

    // Migration
    'ouvrir_ancien_portail' => 'Ouvrir l\'ancien portail',
];
