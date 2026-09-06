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
    'sous_titre' => "Quelques étapes pour sécuriser et préparer votre plateforme. Chacune est détectée automatiquement : il n'y a rien à cocher.",
    'masquer'    => "Masquer l'assistant",
    'avancement' => ':faites sur :total',

    'termine_titre' => 'RootWarden est prêt',
    'termine_desc'  => "Toutes les étapes sont franchies. Vous pouvez masquer cet assistant : il ne réapparaîtra plus pour ce compte.",
    'termine_cta'   => 'Masquer définitivement',

    'fait'   => 'Étape franchie',
    'a_faire' => 'Étape à franchir',

    'etape_serveurs_titre' => 'Ajouter votre premier serveur',
    'etape_serveurs_desc'  => "Référencez au moins un serveur Linux à piloter. RootWarden n'agit jamais en local : tout passe par SSH.",
    'etape_serveurs_cta'   => 'Ajouter un serveur',

    'etape_comptes_titre' => 'Créer au moins un administrateur dédié',
    'etape_comptes_desc'  => "Ne laissez pas le compte superadministrateur initial seul. Créez un compte par personne qui pilote la plateforme — un compte partagé ne se révoque pas.",
    'etape_comptes_cta'   => 'Gérer les comptes',

    'etape_second_facteur_titre' => 'Activer le second facteur sur votre compte',
    'etape_second_facteur_desc'  => "Un compte d'administration sans second facteur tient à la seule solidité de son mot de passe.",
    'etape_second_facteur_cta'   => 'Activer le second facteur',

    'etape_cle_ssh_titre' => 'Ajouter votre clé SSH publique',
    'etape_cle_ssh_desc'  => "Déposez votre clé publique (ed25519 ou RSA) dans votre profil. Elle sera déployée sur les serveurs auxquels vous avez accès, et vous vous y connecterez sans mot de passe.",
    'etape_cle_ssh_cta'   => 'Ajouter la clé',

    'etape_cle_plateforme_titre' => 'Déployer la clé de plateforme',
    'etape_cle_plateforme_desc'  => "Une clé Ed25519 propre à RootWarden, poussée sur vos serveurs. C'est elle qui remplace les mots de passe enregistrés, et elle se remplace d'un seul geste.",
    'etape_cle_plateforme_cta'   => 'Déployer la clé',

    'etape_sans_mot_de_passe_titre' => 'Retirer les mots de passe SSH de la base',
    'etape_sans_mot_de_passe_desc'  => "Une fois la clé de plateforme en place, effacez les mots de passe enregistrés. Ce qui n'est pas stocké ne fuit pas.",
    'etape_sans_mot_de_passe_cta'   => 'Ouvrir la clé de plateforme',

    'etape_cle_api_titre' => 'Créer une clé d\'API dédiée',
    'etape_cle_api_desc'  => "Remplacez la clé générée automatiquement par une clé dédiée, bornée aux routes dont elle a besoin. Une clé sans portée ouvre tout.",
    'etape_cle_api_cta'   => 'Gérer les clés d\'API',

    'etape_premier_releve_titre' => 'Lancer un premier relevé',
    'etape_premier_releve_desc'  => "Audit SSH ou scan de vulnérabilités : c'est ce qui vérifie que la chaîne complète fonctionne, du SSH jusqu'à l'affichage.",
    'etape_premier_releve_cta'   => "Ouvrir l'audit SSH",

    /*
     * ⚠ L'AVERTISSEMENT DIT LA CONSEQUENCE, PAS L'ORDRE DES GESTES.
     * Le legacy ecrit « Deploie la keypair avant ». Il dit QUOI faire et tait
     * POURQUOI — or la raison est la seule chose qui permette de decider :
     * sans cle deployee, effacer les mots de passe retire le dernier acces.
     */
    'avert_sans_cle' => "À ne pas faire avant d'avoir déployé la clé de plateforme : sans elle, effacer les mots de passe retire le dernier accès aux serveurs concernés.",

    /*
     * La divergence de detection, DITE a l'ecran et pas seulement en commentaire :
     * la personne qui lit l'assistant doit savoir sur quoi il se fonde.
     */
    'cle_plateforme_source' => "Détecté d'après les serveurs portant la clé de plateforme.",
];
