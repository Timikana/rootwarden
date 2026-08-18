<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $titre ?? config('app.name') }} · {{ config('app.name') }}</title>
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
        <p class="rw-laterale__legende">
            <span class="rw-fleche">↗</span> {{ __('nav.legende_ancien_portail') }}
        </p>

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
                <span>{{ __('auth.connecte_en_tant_que') }} <strong>{{ session('utilisateur_nom') }}</strong></span>
                <form class="rw-inline" method="POST" action="{{ route('deconnexion') }}">
                    @csrf
                    <button class="rw-bouton rw-bouton--discret" type="submit">{{ __('nav.logout') }}</button>
                </form>
            </div>
        </header>

        <main class="rw-contenu">
            @yield('corps')
        </main>
    </div>

    {{-- Tiroir : MEME partiel que la barre laterale. --}}
    <div class="rw-tiroir">
        <label class="rw-tiroir__voile" for="rw-tiroir" aria-label="{{ __('nav.fermer_menu') }}"></label>
        <nav class="rw-tiroir__panneau">
            <div class="rw-tiroir__entete">
                <span>{{ config('app.name') }}</span>
                <label class="rw-tiroir__fermer" for="rw-tiroir" title="{{ __('nav.fermer_menu') }}">✕</label>
            </div>
            <p class="rw-laterale__legende">
                <span class="rw-fleche">↗</span> {{ __('nav.legende_ancien_portail') }}
            </p>
            <div class="rw-menu">
                @include('composants.entrees-menu', ['variante' => 'tiroir'])
            </div>
        </nav>
    </div>

</div>
</body>
</html>
