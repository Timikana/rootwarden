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
        <nav class="rw-menu">
            @include('composants.entrees-menu', ['variante' => 'laterale'])
        </nav>
        <div class="rw-laterale__pied">
            <span class="rw-laterale__compte">{{ session('utilisateur_nom') }}</span>
            <form method="POST" action="{{ route('deconnexion') }}">
                @csrf
                <button class="rw-bouton rw-bouton--discret" type="submit">{{ __('nav.logout') }}</button>
            </form>
        </div>
    </aside>

    <div class="rw-principal">
        <header class="rw-entete">
            <label class="rw-entete__bascule" for="rw-tiroir" title="{{ __('nav.ouvrir_menu') }}">☰</label>
            <span class="rw-entete__titre">{{ $titre ?? config('app.name') }}</span>
            <span class="rw-entete__compte">{{ __('auth.connecte_en_tant_que') }} <strong>{{ session('utilisateur_nom') }}</strong></span>
        </header>

        <main class="rw-contenu">
            @yield('corps')
        </main>
    </div>

    {{-- Tiroir : MEME partiel que la barre laterale. --}}
    <div class="rw-tiroir">
        <label class="rw-tiroir__voile" for="rw-tiroir" aria-label="{{ __('nav.fermer_menu') }}"></label>
        <nav class="rw-tiroir__panneau rw-menu">
            @include('composants.entrees-menu', ['variante' => 'tiroir'])
        </nav>
    </div>

</div>
</body>
</html>
