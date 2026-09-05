<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Mailer
    |--------------------------------------------------------------------------
    |
    | This option controls the default mailer that is used to send all email
    | messages unless another mailer is explicitly specified when sending
    | the message. All additional mailers can be configured within the
    | "mailers" array. Examples of each type of mailer are provided.
    |
    */

    // ⚠ MAPPE SUR LES NOMS DU PROJET (2026-09-05). Mesure : le conteneur porte
    // 9 variables `MAIL_*` (MAIL_ENABLED, MAIL_FROM, MAIL_SMTP_HOST, ...) et ce
    // fichier en lisait 15 autres (MAIL_MAILER, MAIL_HOST, ...) — INTERSECTION
    // ZERO. `env('MAIL_MAILER')` etant absent, le repli `log` s'appliquait et
    // tout partait dans le journal. Les memes variables font deja fonctionner
    // `backend/mail_utils.py` (smtplib) : on branche le portage sur un SMTP qui
    // tourne, on n'en configure pas un nouveau.
    //
    // ⚠⚠ LE PILOTE RESTE `log` ET C'EST DELIBERE. `MAIL_ENABLED` vaut DEJA
    // `true` : en faire l'interrupteur ferait basculer le transport a
    // l'ENREGISTREMENT de ce fichier — il n'y a pas de `bootstrap/cache/config.php`
    // et `laravel/` est monte en direct, donc Laravel relit `config/` a chaque
    // requete. `MAIL_MAILER` est ABSENTE du conteneur : la poser est un geste
    // EXPLICITE de l'exploitant, qui ne peut pas se produire par inadvertance.
    // Le mappage rend CAPABLE ; l'exploitant ARME.
    //
    // ⚠⚠ ET IL Y A DESORMAIS UN EXPEDITEUR : `Auth/ReinitialisationController`
    // (`Mail::raw`). Poser `MAIL_MAILER=smtp` fait donc partir de VRAIS courriels
    // de reinitialisation immediatement. A savoir avant d'armer : ce conteneur
    // tourne sous `mod_php` sans `php-fpm`, donc pas de
    // `fastcgi_finish_request()` — le travail differe part apres l'ECRITURE de la
    // reponse et non apres sa FIN, ce qui rouvre un oracle temporel sur la
    // recuperation de compte (voir DOSSIER-24).
    'default' => env('MAIL_MAILER', 'log'),

    /*
    |--------------------------------------------------------------------------
    | Mailer Configurations
    |--------------------------------------------------------------------------
    |
    | Here you may configure all of the mailers used by your application plus
    | their respective settings. Several examples have been configured for
    | you and you are free to add your own as your application requires.
    |
    | Laravel supports a variety of mail "transport" drivers that can be used
    | when delivering an email. You may specify which one you're using for
    | your mailers below. You may also add additional mailers if needed.
    |
    | Supported: "smtp", "sendmail", "mailgun", "ses", "ses-v2",
    |            "postmark", "resend", "log", "array",
    |            "failover", "roundrobin"
    |
    */

    'mailers' => [

        'smtp' => [
            'transport' => 'smtp',
            // ⚠ LE NOM DIT L'INVERSE DE CE QU'IL SIGNIFIE ICI. `MAIL_SMTP_TLS`
            // ne veut pas dire « chiffrer » : il choisit LEQUEL des deux modes.
            // `backend/mail_utils.py:8-9,207-208` fait foi :
            //     MAIL_SMTP_TLS = true   -> STARTTLS     (port 587)
            //     MAIL_SMTP_TLS = false  -> SSL direct   (port 465)
            // Donc `false` est le mode chiffre D'EMBLEE, pas le moins chiffre.
            // `'smtps'` = TLS des le premier octet ; `null` laisse Symfony
            // negocier STARTTLS. J'avais d'abord ecrit l'inverse, en mappant le
            // NOM plutot que sa semantique : avec `false` et le port 465, ca
            // rendait `scheme=NULL`, donc un STARTTLS sur un port qui attend du
            // TLS immediat — echec au premier octet.
            'scheme' => env('MAIL_SMTP_TLS', false) ? null : 'smtps',
            'url' => env('MAIL_URL'),
            'host' => env('MAIL_SMTP_HOST', '127.0.0.1'),
            'port' => env('MAIL_SMTP_PORT', 2525),
            'username' => env('MAIL_SMTP_USER'),
            'password' => env('MAIL_SMTP_PASSWORD'),
            'timeout' => null,
            'local_domain' => env('MAIL_EHLO_DOMAIN', parse_url((string) env('APP_URL', 'http://localhost'), PHP_URL_HOST)),
        ],

        'ses' => [
            'transport' => 'ses',
        ],

        'postmark' => [
            'transport' => 'postmark',
            // 'message_stream_id' => env('POSTMARK_MESSAGE_STREAM_ID'),
            // 'client' => [
            //     'timeout' => 5,
            // ],
        ],

        'resend' => [
            'transport' => 'resend',
        ],

        'sendmail' => [
            'transport' => 'sendmail',
            'path' => env('MAIL_SENDMAIL_PATH', '/usr/sbin/sendmail -bs -i'),
        ],

        'log' => [
            'transport' => 'log',
            'channel' => env('MAIL_LOG_CHANNEL'),
        ],

        'array' => [
            'transport' => 'array',
        ],

        'failover' => [
            'transport' => 'failover',
            'mailers' => [
                'smtp',
                'log',
            ],
            'retry_after' => 60,
        ],

        'roundrobin' => [
            'transport' => 'roundrobin',
            'mailers' => [
                'ses',
                'postmark',
            ],
            'retry_after' => 60,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Global "From" Address
    |--------------------------------------------------------------------------
    |
    | You may wish for all emails sent by your application to be sent from
    | the same address. Here you may specify a name and address that is
    | used globally for all emails that are sent by your application.
    |
    */

    'from' => [
        // `hello@example.com` etait le defaut du squelette : une adresse
        // d'exemple qui serait partie en en-tete `From` au premier envoi.
        'address' => env('MAIL_FROM', 'no-reply@localhost'),
        'name' => env('MAIL_FROM_NAME', env('APP_NAME', 'Laravel')),
    ],

];
