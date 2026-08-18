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

        $middleware->alias([
            // Session COMPLETEMENT authentifiee : mot de passe ET second
            // facteur. Entre les deux, la session ne porte qu'un compte
            // temporaire et ne franchit pas ce garde.
            'session.authentifiee' => \App\Http\Middleware\SessionAuthentifiee::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
