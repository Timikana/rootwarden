<?php

/**
 * Reglages propres a RootWarden.
 *
 * Tout se lit ICI, dans config/. Un env() place ailleurs rend null des le
 * premier `config:cache` — silencieusement, sans erreur.
 */
return [

    /*
     * Cle de chiffrement PARTAGEE avec le backend Python. Elle protege les
     * secrets TOTP et les mots de passe des machines.
     *
     * A ne pas confondre avec APP_KEY, qui ne sert qu'aux cookies de session
     * Laravel et n'a aucun rapport avec les donnees metier.
     */
    'secret_key' => env('SECRET_KEY', ''),

    'totp' => [
        /*
         * Tolerance en nombre de periodes de 30 s, de part et d'autre de
         * l'heure courante. Le legacy utilise 1 : on garde la meme valeur,
         * sinon un code accepte d'un cote serait refuse de l'autre.
         */
        'tolerance' => 1,

        /*
         * Duree de retention de la derniere fenetre consommee par compte.
         * Doit couvrir largement la tolerance : 4 periodes.
         */
        'retention_rejeu' => 120,
    ],

    'connexion' => [
        // Tentatives de second facteur autorisees par session, sur 60 s.
        'max_tentatives_2fa' => 5,
        // Echecs de second facteur par IP sur 10 minutes avant blocage.
        'max_echecs_ip' => 10,
    ],

    /*
     * Duree de validite d'une re-authentification ponctuelle (step-up),
     * par action. Identique au legacy.
     */
    'step_up_ttl' => 900,
];
