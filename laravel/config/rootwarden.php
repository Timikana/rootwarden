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

    /*
     * Journal d'audit. La chaine de hachage de `user_logs` est signee par
     * `AUDIT_HMAC_KEY` quand elle existe, et par `secret_key` sinon — l'ordre
     * exact du legacy (`adm/includes/audit_log.php:44-58`). Mesure du
     * 2026-08-25 : la variable dediee est ABSENTE de cet environnement, donc les
     * deux portails signent avec la meme cle et se relisent l'un l'autre.
     * Separer les deux cles est une decision d'exploitation : la changer ici
     * rendrait illisibles les milliers de lignes deja scellees.
     */
    /*
     * Cout bcrypt, lu la ou le legacy le lit (`auth/password_policy.php:28`) :
     * la variable d'environnement `BCRYPT_COST`, defaut 12. Les deux portails
     * doivent rester d'accord — un compte dont le mot de passe est pose ici doit
     * pouvoir se connecter la-bas, et reciproquement.
     */
    'bcrypt_cost' => (int) env('BCRYPT_COST', 12),

    'audit' => [
        'cle_hmac' => env('AUDIT_HMAC_KEY', ''),
    ],

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
     * Tentatives de re-authentification tolerees par minute et PAR COMPTE. Le
     * legacy en tolere cinq par SESSION et ne remet pas le compteur a zero sur
     * succes : cinq step-up legitimes en une minute rendent 429.
     */
    'step_up_tentatives' => (int) env('STEP_UP_TENTATIVES', 5),

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
        // Les routes RELAYEES EN FLUX tiennent leur reponse ouverte pendant que
        // la commande tourne : une mise a jour de securite depasse largement le
        // delai ordinaire. Voir RoutesBackend::EN_FLUX.
        'delai_flux' => env('BACKEND_TIMEOUT_FLUX', 900),
    ],

    'fonctionnalites' => [
        'wazuh' => env('FEATURE_WAZUH', true),
    ],

    /*
     * La politique de mot de passe — sous-lot A2.
     *
     * Les MEMES valeurs que `legacy/auth/password_policy.php`, et les memes noms
     * de variable d'environnement : les deux portails partagent la base, donc ils
     * doivent partager la politique. Mesure du 2026-08-23 : ni `BCRYPT_COST` ni
     * `HIBP_ENABLED` ne sont definies dans les conteneurs, donc les defauts
     * s'appliquent et la verification HIBP est INERTE — aucune requete ne sort.
     *
     * `env()` n'est lu QUE depuis `config/` : ailleurs il rend `null` des le
     * premier `config:cache`.
     */
    'mot_de_passe' => [
        // OWASP 2024 : cout >= 12 sur un processeur moderne (~250 ms par hachage).
        // Le defaut de PHP est 10 (~60 ms), insuffisant face au forcage sur GPU.
        'cout' => (int) env('BCRYPT_COST', 12),
        'longueur_minimale' => 15,
        // Nombre d'anciens haches conserves ET refuses.
        'taille_historique' => 5,
        // Opt-in, en k-anonymity : seuls les cinq premiers caracteres de
        // l'empreinte SHA-1 quittent le serveur, jamais le mot de passe.
        'hibp' => filter_var(env('HIBP_ENABLED', false), FILTER_VALIDATE_BOOLEAN),
    ],
];
