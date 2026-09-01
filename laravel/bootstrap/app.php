<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        /*
         * NE PAS ajouter ValidateCsrfToken ici.
         *
         * Laravel 13 place `PreventRequestForgery` dans le groupe `web` par
         * defaut. Ce middleware accepte une requete si l'UNE de ces conditions
         * tient : methode de lecture, chemin exclu, ORIGINE valide
         * (`Sec-Fetch-Site: same-origin`), ou jeton correspondant.
         *
         * Une mesure du 2026-08-18 a d'abord fait croire a une absence de
         * controle : un `fetch` same-origin sans jeton passait. C'etait le
         * comportement ATTENDU — une requete same-origin n'est pas une
         * falsification. La propriete a verifier est qu'une requete
         * CROSS-SITE sans jeton soit refusee, ce que fait
         * tests/e2e/go-socle-passerelle.mjs.
         */
        /*
         * La langue se resout sur TOUTE requete web, y compris les ecrans
         * publics : la page de connexion doit pouvoir basculer avant qu'aucune
         * session applicative n'existe.
         */
        $middleware->web(append: [
            \App\Http\Middleware\Langue::class,
        ]);

        /*
         * LE SEUL CHEMIN PUBLIC QUI ECRIT — et il faut dire pourquoi.
         *
         * `/chatops/webhook` est appele par Slack, qui ne peut presenter ni
         * session ni jeton CSRF. L'authentification reelle est faite par le
         * backend, sur la SIGNATURE Slack ou un jeton partage, et il refuse
         * d'emblee si ChatOps est desactive (`backend/routes/chatops.py:34`).
         *
         * Ce que l'exclusion N'accorde PAS : la route ne lit rien de la session,
         * n'accorde aucun privilege, et ne relaie que le corps brut plus QUATRE
         * en-tetes nommes un par un. Elle ne recopie jamais les en-tetes en
         * bloc — un `Cookie` ou un `Authorization` transmis au backend
         * transformerait ce relais en confusion d'identite.
         *
         * Exclure ce chemin est la seule facon de le porter : le legacy fait de
         * meme, par un fichier PHP hors de toute session.
         */
        $middleware->validateCsrfTokens(except: [
            'chatops/webhook',
        ]);

        $middleware->alias([
            // Session COMPLETEMENT authentifiee : mot de passe ET second
            // facteur. Entre les deux, la session ne porte qu'un compte
            // temporaire et ne franchit pas ce garde.
            'session.authentifiee' => \App\Http\Middleware\SessionAuthentifiee::class,
            // `role:2` = administrateur ou au-dessus. `perm:can_x` se lit
            // « cette permission OU superadmin », comme partout ailleurs.
            'role' => \App\Http\Middleware\ExigeRole::class,
            'perm' => \App\Http\Middleware\ExigePermission::class,
            // Un compte marque « doit changer son mot de passe » ne va nulle
            // part d'autre. Applique au GROUPE authentifie et non au groupe
            // `web` : la deconnexion vit hors du groupe, donc elle reste
            // atteignable PAR CONSTRUCTION et non par exemption.
            'mot.de.passe.a.changer' => \App\Http\Middleware\ChangementMotDePasseExige::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
