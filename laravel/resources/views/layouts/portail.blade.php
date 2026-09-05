<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    {{-- Jeton CSRF : la passerelle est dans le groupe `web`, toute requete
         mutante doit le porter (en-tete X-CSRF-TOKEN). --}}
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $titre ?? config('app.name') }} · {{ config('app.name') }}</title>
    {{-- FAVICON. Le portage n'en declarait AUCUN, et `public/favicon.ico`
         faisait ZERO octet : le navigateur recevait un 200 et une image vide.
         Un fichier vide servi en 200 est pire qu'un 404 — il ne fait chercher
         nulle part. Les deux declarations reprennent celles du legacy
         (`head.php:31-32`), `apple-touch-icon` comprise. --}}
    <link rel="icon" type="image/png" sizes="32x32"
          href="/img/favicon.png?v={{ @filemtime(public_path('img/favicon.png')) ?: '0' }}">
    <link rel="apple-touch-icon" href="/img/favicon.png">
    <link rel="stylesheet" href="/css/rw.css?v={{ @filemtime(public_path('css/rw.css')) ?: '0' }}">
</head>
<body>

{{-- Le tiroir est pilote par une case a cocher masquee : pas une ligne de
     JavaScript pour ouvrir un menu. Moins de code, rien a casser. --}}
<input type="checkbox" id="rw-tiroir" class="rw-tiroir__bascule" hidden>

<div class="rw-portail">

    <aside class="rw-laterale">
        <a class="rw-laterale__marque" href="{{ route('accueil') }}">{{ config('app.name') }}</a>

        {{-- La legende explique la fleche UNE FOIS, au lieu de repeter
             « ancien portail » sur chaque entree non portee. --}}
        {{-- ⚠ CONDITIONNEE, ET NON SUPPRIMEE. Elle expliquait la fleche « ↗ »
             alors que le menu est passe a 32 entrees `route` et ZERO
             `legacy` : elle decrivait un marqueur qu'aucune entree ne
             porte plus. La supprimer serait correct aujourd'hui et faux
             des qu'une entree repasse en `legacy` — ce menu est passe de
             24 a 32 en une nuit. Le predicat la rend juste dans les deux
             regimes, et personne n'a a se souvenir de la remettre.
        
             AUX DEUX ENDROITS : barre laterale ET tiroir mobile. Le
             second est celui qu'on oublie, et celui que personne ne
             regarde. --}}
        @if (\App\Support\Navigation::porteDuLegacy($menu ?? []))
        <p class="rw-laterale__legende">
            <span class="rw-fleche">↗</span> {{ __('nav.legende_ancien_portail') }}
        </p>
        @endif

        <nav class="rw-menu">
            @include('composants.entrees-menu', ['variante' => 'laterale'])
        </nav>
    </aside>

    <div class="rw-principal">
        <header class="rw-entete">
            <label class="rw-entete__bascule" for="rw-tiroir" title="{{ __('nav.ouvrir_menu') }}">☰</label>
            <span class="rw-entete__titre">{{ $titre ?? config('app.name') }}</span>

            {{-- Compte et deconnexion DANS L'EN-TETE : c'est la qu'on les
                 cherche. En pied de barre laterale, ils bornaient la liste du
                 menu, qui se coupait en plein libelle. --}}
            <div class="rw-entete__compte">
                {{-- La cloche vit dans l'EN-TETE, comme celle du legacy — donc sur
                     toutes les pages. Le compte est rendu PAR LE SERVEUR, pas
                     recupere par un appel au chargement : un appel de moins par
                     page, et une pastille qui ne peut pas etre en retard sur ce
                     que la page affiche. --}}
                {{--
                    ⚠ CETTE LIGNE RESTE SUR UNE SEULE LIGNE. C'EST UNE MINE.

                    La forme expression de Blade — `@php(...)` — est reconnue par un
                    motif qui ne traverse PAS les sauts de ligne. Ecrite sur deux
                    lignes, elle tombait dans la forme BLOC : Blade rendait
                    `<?php(` suivi du texte litteral, et attendait un `@endphp`.
                    Tant qu'il n'y en avait aucun dans le fichier, le compile
                    restait valide par accident.

                    Mesure du 2026-08-27 : en ajoutant un `@php … @endphp` pour le
                    pied de page, ce `@endphp` s'est apparie avec CE `@php(` — tout
                    le bloc intermediaire a ete avale comme du PHP, et le gabarit
                    ENTIER a cesse de compiler (« unexpected token class »). Donc
                    toutes les pages, d'un coup, pour une ligne ajoutee ailleurs.

                    Remise sur une ligne : la forme expression est reconnue, elle se
                    ferme, et un futur `@endphp` n'a plus rien a quoi s'apparier.
                --}}
                @php($rwNonLues = app(\App\Services\Notifications::class)->nonLues((int) session('utilisateur_id', 0), (int) session('role_id', 0)))
                <a class="rw-lien" href="{{ route('notifications') }}"
                   title="{{ __('notif.title') }}" data-rw="notif-cloche">🔔
                    <span class="rw-badge rw-badge--alerte" data-rw="notif-pastille"
                          @if ($rwNonLues === 0) hidden @endif>{{ $rwNonLues }}</span>
                </a>
                @include('composants.langue')
                {{-- UNE CLASSE, PARCE QUE C'EST CE LIBELLE-LA QU'ON MASQUE SUR
                     PETIT ECRAN. La regle visait `.rw-entete__compte span` et
                     attrapait AUSSI la pastille de notification et la langue
                     active — trois elements caches la ou un seul devait l'etre. --}}
                <span class="rw-entete__nom">{{ __('auth.connecte_en_tant_que') }} <strong>{{ session('utilisateur_nom') }}</strong></span>
                <form class="rw-inline" method="POST" action="{{ route('deconnexion') }}">
                    @csrf
                    <button class="rw-bouton rw-bouton--discret" type="submit">{{ __('nav.logout') }}</button>
                </form>
            </div>
        </header>

        <main class="rw-contenu">
            @yield('corps')
        </main>

        {{--
            ── LE NUMERO DE VERSION, LU ET JAMAIS CALCULE ──────────────────

            Le portage n'affichait AUCUNE version : mesure du 2026-08-27, zero
            lecteur de `version.txt` dans `laravel/`. A l'extinction du legacy, le
            numero aurait donc disparu de l'interface — une 2.0 qui ne peut pas
            dire son numero.

            La source est unique : `legacy/version.txt`, monte en lecture seule.
            Une version inconnue se DIT, elle ne se rend pas par un vide. Et un
            montage de `volumes` ne prend effet qu'a la RECREATION du conteneur :
            « version inconnue » avant cela est le comportement correct.
        --}}
        <footer class="rw-pied" data-rw="pied-version">
            <span data-rw="pied-numero">{{ \App\Support\Version::numero() !== null
                ? __('nav.version', ['numero' => \App\Support\Version::numero()])
                : __('nav.version_inconnue') }}</span>

            {{-- LES CONDITIONS D'UTILISATION ETAIENT INJOIGNABLES. La page existe
                 (`cgu.blade.php`), la route existe (`GET /cgu`), et AUCUN lien n'y
                 menait : zero occurrence dans ce gabarit et dans l'ecran de
                 connexion. Une page d'engagement qui ne se rejoint pas equivaut a
                 ne pas en avoir — elle n'existe que pour etre opposable, et elle
                 ne l'est que si on peut y arriver.
                 C'est le defaut SYMETRIQUE de celui corrige ce matin : la un lien
                 vers une page absente, ici une page presente sans lien. --}}
            <a class="rw-pied__lien" href="{{ route('cgu') }}"
               data-rw="pied-cgu">{{ __('nav.cgu') }}</a>

            {{-- Le legacy porte ce lien depuis toujours (`footer.php:20`). Le
                 portage ne l'avait pas repris. --}}
            <a class="rw-pied__lien" href="https://buymeacoffee.com/timikana"
               target="_blank" rel="noopener" data-rw="pied-cafe"
               title="{{ __('nav.cafe_titre') }}">&#9749; {{ __('nav.cafe') }}</a>
        </footer>
    </div>

    {{-- Tiroir : MEME partiel que la barre laterale. --}}
    <div class="rw-tiroir">
        <label class="rw-tiroir__voile" for="rw-tiroir" aria-label="{{ __('nav.fermer_menu') }}"></label>
        <nav class="rw-tiroir__panneau">
            <div class="rw-tiroir__entete">
                <span>{{ config('app.name') }}</span>
                <label class="rw-tiroir__fermer" for="rw-tiroir" title="{{ __('nav.fermer_menu') }}">✕</label>
            </div>
            {{-- ⚠ CONDITIONNEE, ET NON SUPPRIMEE. Elle expliquait la fleche « ↗ »
                 alors que le menu est passe a 32 entrees `route` et ZERO
                 `legacy` : elle decrivait un marqueur qu'aucune entree ne
                 porte plus. La supprimer serait correct aujourd'hui et faux
                 des qu'une entree repasse en `legacy` — ce menu est passe de
                 24 a 32 en une nuit. Le predicat la rend juste dans les deux
                 regimes, et personne n'a a se souvenir de la remettre.
            
                 AUX DEUX ENDROITS : barre laterale ET tiroir mobile. Le
                 second est celui qu'on oublie, et celui que personne ne
                 regarde. --}}
            @if (\App\Support\Navigation::porteDuLegacy($menu ?? []))
            <p class="rw-laterale__legende">
                <span class="rw-fleche">↗</span> {{ __('nav.legende_ancien_portail') }}
            </p>
            @endif
            <div class="rw-menu">
                @include('composants.entrees-menu', ['variante' => 'tiroir'])
            </div>
        </nav>
    </div>

</div>
</body>
</html>
