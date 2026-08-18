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

    /*
     * Drapeaux de fonctionnalite, releves du legacy (feature_enabled()).
     * Absent vaut ACTIF, comme lui : un module ne disparait pas parce qu'une
     * variable manque.
     */
    /*
     * Backend Python. URL INTERNE au reseau Docker : le navigateur ne la voit
     * jamais, il passe par la passerelle. A ne pas confondre avec une URL
     * publique.
     *
     * La cle d'API est partagee avec le legacy (meme variable d'environnement)
     * et ne quitte jamais le serveur.
     */
    'backend' => [
        'url'     => env('BACKEND_INTERNAL_URL', 'https://python:5000'),
        'cle_api' => env('API_KEY', ''),
        // Certaines routes de parc (scan CVE, mise a jour) durent longtemps.
        'delai'   => env('BACKEND_TIMEOUT', 120),
    ],

    'fonctionnalites' => [
        'wazuh' => env('FEATURE_WAZUH', true),
    ],
];
