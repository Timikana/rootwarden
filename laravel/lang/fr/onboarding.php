<?php

/*
 * L'assistant de premiere configuration. Le jeu de cles doit rester identique a
 * `lang/en/onboarding.php`.
 *
 * ⚠ LE VOUVOIEMENT EST UNIFIE ICI, ET C'EST UNE DIVERGENCE ASSUMEE. Le legacy
 * melange les deux dans le meme bloc — « Referencez au moins un serveur » et
 * « Tu peux masquer cet assistant » se suivent a onze lignes d'ecart. Le portage
 * vouvoie partout ailleurs.
 */
return [
    'titre'      => 'Bienvenue sur RootWarden',
    'sous_titre' => "Chaque étape est détectée automatiquement.",
    'masquer'    => "Masquer l'assistant",
    'avancement' => ':faites sur :total',

    'termine_titre' => 'RootWarden est prêt',
    'termine_desc'  => "Toutes les étapes sont faites. Vous pouvez masquer l'assistant.",
    'termine_cta'   => 'Masquer définitivement',

    'fait'   => 'Étape franchie',
    'a_faire' => 'Étape à franchir',

    'etape_serveurs_titre' => 'Ajouter votre premier serveur',
    'etape_serveurs_desc'  => "RootWarden agit sur vos serveurs uniquement par SSH.",
    'etape_serveurs_cta'   => 'Ajouter un serveur',

    'etape_comptes_titre' => 'Créer au moins un administrateur dédié',
    'etape_comptes_desc'  => "Un compte par personne : un compte partagé ne se révoque pas.",
    'etape_comptes_cta'   => 'Gérer les comptes',

    'etape_second_facteur_titre' => 'Activer le second facteur sur votre compte',
    'etape_second_facteur_desc'  => "Sans second facteur, le compte ne tient qu'à son mot de passe.",
    'etape_second_facteur_cta'   => 'Activer le second facteur',

    'etape_cle_ssh_titre' => 'Ajouter votre clé SSH publique',
    'etape_cle_ssh_desc'  => "Votre clé publique (ed25519 ou RSA) est déployée sur les serveurs auxquels vous avez accès.",
    'etape_cle_ssh_cta'   => 'Ajouter la clé',

    'etape_cle_plateforme_titre' => 'Déployer la clé de plateforme',
    'etape_cle_plateforme_desc'  => "La clé de RootWarden, qui remplace les mots de passe enregistrés.",
    'etape_cle_plateforme_cta'   => 'Déployer la clé',

    'etape_sans_mot_de_passe_titre' => 'Retirer les mots de passe SSH de la base',
    'etape_sans_mot_de_passe_desc'  => "Une fois la clé de plateforme en place, effacez les mots de passe enregistrés.",
    'etape_sans_mot_de_passe_cta'   => 'Ouvrir la clé de plateforme',

    'etape_cle_api_titre' => 'Créer une clé d\'API dédiée',
    'etape_cle_api_desc'  => "Remplacez la clé générée automatiquement par une clé limitée aux routes utiles.",
    'etape_cle_api_cta'   => 'Gérer les clés d\'API',

    'etape_premier_releve_titre' => 'Lancer un premier relevé',
    'etape_premier_releve_desc'  => "Un audit SSH ou un scan de vulnérabilités vérifie toute la chaîne.",
    'etape_premier_releve_cta'   => "Ouvrir l'audit SSH",

    /*
     * ⚠ L'AVERTISSEMENT DIT LA CONSEQUENCE, PAS L'ORDRE DES GESTES.
     * Le legacy ecrit « Deploie la keypair avant ». Il dit QUOI faire et tait
     * POURQUOI — or la raison est la seule chose qui permette de decider :
     * sans cle deployee, effacer les mots de passe retire le dernier acces.
     */
    'avert_sans_cle' => "Pas avant d'avoir déployé la clé de plateforme : vous perdriez tout accès aux serveurs concernés.",

    /*
     * La divergence de detection, DITE a l'ecran et pas seulement en commentaire :
     * la personne qui lit l'assistant doit savoir sur quoi il se fonde.
     */
    'cle_plateforme_source' => "Détecté d'après les serveurs portant la clé de plateforme.",
];
