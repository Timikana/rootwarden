<?php

/*
 * La reinitialisation de mot de passe par courriel. Le jeu de cles doit rester
 * identique a `lang/en/reinit.php`.
 */
return [
    'titre'       => 'Mot de passe oublié',
    'sous_titre'  => "Indiquez l'adresse de courriel de votre compte. Si elle correspond à un compte actif, un lien de réinitialisation lui sera préparé.",
    'champ_email' => 'Adresse de courriel',
    'envoyer'     => 'Demander un lien',
    'retour'      => 'Revenir à la connexion',

    /*
     * ⚠ CE MESSAGE EST LE MEME QUE L'ADRESSE EXISTE OU NON, ET IL EST RENDU
     * HORS de la branche qui teste le compte. C'est la moitie « message » de
     * l'anti-enumeration ; l'autre moitie est le TEMPS, et elle vit dans le
     * controleur.
     *
     * ⚠ ET IL DIT « PREPARE », PAS « ENVOYE ». `MAIL_MAILER` vaut `log` : rien
     * ne part vers une boite. Une phrase qui affirmerait un envoi ferait
     * attendre un courriel qui n'arrivera pas — et il faudrait la rectifier le
     * jour ou le SMTP sera pose. Celle-ci reste vraie dans les deux regimes.
     */
    'demande_recue' => "Si cette adresse correspond à un compte actif, un lien de réinitialisation lui a été préparé. Il est valable une heure et ne peut servir qu'une fois.",

    'trop_de_demandes' => "Trop de demandes depuis cette adresse. Réessayez dans une heure.",

    'jeton_invalide' => "Ce lien n'est plus valable : il a expiré, il a déjà servi, ou il a été remplacé par une demande plus récente. Demandez-en un nouveau.",

    'reinit_titre'      => 'Choisir un nouveau mot de passe',
    'reinit_sous_titre' => "Ce lien ne servira qu'une fois. Après validation, vous vous reconnecterez normalement — le second facteur reste exigé.",
    'champ_mot_de_passe' => 'Nouveau mot de passe',
    'champ_confirmation' => 'Confirmer le mot de passe',
    'valider'            => 'Enregistrer le mot de passe',

    'mot_de_passe_pose' => 'Mot de passe enregistré. Vous pouvez vous connecter.',

    /*
     * Les sessions et les jetons « se souvenir de moi » sont revoques par
     * `MotDePasse::reinitialise()`. On le DIT : quelqu'un qui reinitialise parce
     * qu'il soupconne un acces doit savoir que ce geste ferme les acces ouverts.
     */
    'consequence' => "Enregistrer un nouveau mot de passe ferme toutes les sessions ouvertes de ce compte et révoque les connexions mémorisées, sur tous les appareils.",

    'courriel_sujet' => 'RootWarden — réinitialisation de votre mot de passe',
    'courriel_corps' => <<<'TXT'
Bonjour :nom,

Une réinitialisation de mot de passe a été demandée pour votre compte RootWarden.

Ouvrez ce lien pour choisir un nouveau mot de passe :

:lien

Ce lien est valable :heures heure et ne peut servir qu'une fois. Toute demande
plus récente l'invalide.

Si vous n'êtes pas à l'origine de cette demande, vous n'avez rien à faire : sans
ce lien, votre mot de passe reste inchangé.
TXT,
];
