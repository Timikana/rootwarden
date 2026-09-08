<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Application Name
    |--------------------------------------------------------------------------
    |
    | This value is the name of your application, which will be used when the
    | framework needs to place the application's name in a notification or
    | other UI elements where an application name needs to be displayed.
    |
    */

    // L'adresse de contact affichee par les CGU. MEME source que le legacy

    // (`SERVER_ADMIN`), pour que les deux portails ne puissent pas diverger.

    'contact_admin' => env('SERVER_ADMIN', 'admin@localhost'),


    'name' => env('APP_NAME', 'Laravel'),

    /*
    |--------------------------------------------------------------------------
    | Application Environment
    |--------------------------------------------------------------------------
    |
    | This value determines the "environment" your application is currently
    | running in. This may determine how you prefer to configure various
    | services the application utilizes. Set this in your ".env" file.
    |
    */

    'env' => env('APP_ENV', 'production'),

    /*
    |--------------------------------------------------------------------------
    | Application Debug Mode
    |--------------------------------------------------------------------------
    |
    | When your application is in debug mode, detailed error messages with
    | stack traces will be shown on every error that occurs within your
    | application. If disabled, a simple generic error page is shown.
    |
    */

    'debug' => (bool) env('APP_DEBUG', false),

    /*
    |--------------------------------------------------------------------------
    | Application URL
    |--------------------------------------------------------------------------
    |
    | This URL is used by the console to properly generate URLs when using
    | the Artisan command line tool. You should set this to the root of
    | the application so that it's available within Artisan commands.
    |
    */

    'url' => env('APP_URL', 'http://localhost'),

    /*
     * URL du frontend legacy, encore en service pendant la migration. Les
     * pages non portees y renvoient explicitement : un renvoi vaut mieux
     * qu'un ecran vide qui laisse croire que la fonction a disparu.
     *
     * ══ LE DEFAUT VAUT 8446, ET IL NE DOIT PAS ETRE « CORRIGE » EN 8443 ══════
     *
     * L'echange des ports du 2026-09-06 a donne au PORTAGE les ports du portail
     * historique, et relegue le legacy sur ceux que le portage abandonnait :
     *
     *     portage   8080 / 8443      <- docker-compose.yml:92 et :110
     *     legacy    8444 / 8446      <- docker-compose.yml:21 et :22
     *
     * Ce defaut valait `8443` : depuis l'echange, il nommait LE PORTAGE. Sept
     * lecteurs concatenent cette valeur avec un chemin du legacy —
     * `accueil.blade.php`, `composants/entrees-menu.blade.php`,
     * `pare-feu.blade.php`, `PortailController` (deux fois) et `LiensLegacy`
     * (deux fois). Sans `LEGACY_URL` dans l'environnement, chacun de ces liens
     * menait donc au portage, sur un chemin qu'il ne sert pas.
     *
     * > **Ce n'est pas une panne : c'est un lien qui porte le nom d'un portail et
     * > l'adresse de l'autre.** Il rend 404 dans le meilleur cas, et dans le pire
     * > il atteint une route du portage dont le sens n'est pas celui qu'on
     * > croyait ouvrir.
     *
     * ⚠ MESURE DU 2026-09-08 : LATENT, PAS ACTIF. Le conteneur porte
     * `LEGACY_URL=https://192.168.0.245:8446` (verifie par `printenv` ET par
     * `getenv()` depuis PHP), et il n'y a pas de `bootstrap/cache/config.php`.
     * Le defaut ne s'appliquait donc qu'a un checkout frais, un `artisan serve`
     * local, ou un conteneur demarre sans `env_file` — et c'est precisement ou
     * personne ne le verifie.
     *
     * *`localhost` en defaut est deliberé : deriver depuis `SERVER_NAME`
     * substituerait `localhost` dans un lien vu depuis une autre machine, ce qui
     * s'est deja paye. Ce defaut n'est qu'un dernier recours de developpement.*
     *
     * ⚠ ARBITRAGE LAISSE OUVERT — un defaut JUSTE reste un defaut DEVINE. La
     * forme forte serait de ne rien deviner : `LEGACY_URL` absente => aucun lien
     * legacy rendu, plutot qu'un lien vers une adresse supposee. Elle exige que
     * les sept lecteurs sachent ne pas rendre le lien, dont cinq vivent dans des
     * vues et des controleurs qu'une autre session ecrit en ce moment. Porte
     * comme arbitrage plutot que fait a la hache.
     */
    'url_legacy' => env('LEGACY_URL', 'https://localhost:8446'),

    /*
    |--------------------------------------------------------------------------
    | Application Timezone
    |--------------------------------------------------------------------------
    |
    | Here you may specify the default timezone for your application, which
    | will be used by the PHP date and date-time functions. The timezone
    | is set to "UTC" by default as it is suitable for most use cases.
    |
    */

    'timezone' => 'UTC',

    /*
    |--------------------------------------------------------------------------
    | Application Locale Configuration
    |--------------------------------------------------------------------------
    |
    | The application locale determines the default locale that will be used
    | by Laravel's translation / localization methods. This option can be
    | set to any locale for which you plan to have translation strings.
    |
    */

    'locale' => env('APP_LOCALE', 'en'),

    'fallback_locale' => env('APP_FALLBACK_LOCALE', 'en'),

    'faker_locale' => env('APP_FAKER_LOCALE', 'en_US'),

    /*
    |--------------------------------------------------------------------------
    | Encryption Key
    |--------------------------------------------------------------------------
    |
    | This key is utilized by Laravel's encryption services and should be set
    | to a random, 32 character string to ensure that all encrypted values
    | are secure. You should do this prior to deploying the application.
    |
    */

    'cipher' => 'AES-256-CBC',

    'key' => env('APP_KEY'),

    'previous_keys' => [
        ...array_filter(
            explode(',', (string) env('APP_PREVIOUS_KEYS', ''))
        ),
    ],

    /*
    |--------------------------------------------------------------------------
    | Maintenance Mode Driver
    |--------------------------------------------------------------------------
    |
    | These configuration options determine the driver used to determine and
    | manage Laravel's "maintenance mode" status. The "cache" driver will
    | allow maintenance mode to be controlled across multiple machines.
    |
    | Supported drivers: "file", "cache", "array"
    |
    */

    'maintenance' => [
        'driver' => env('APP_MAINTENANCE_DRIVER', 'file'),
        'store' => env('APP_MAINTENANCE_STORE', 'database'),
    ],

];
