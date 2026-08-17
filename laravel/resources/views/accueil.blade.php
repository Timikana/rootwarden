@extends('layouts.socle', ['titre' => __('auth.accueil_titre')])

@section('corps')
<header class="rw-barre">
    <span class="rw-barre__marque">{{ config('app.name') }}</span>
    <span class="rw-barre__droite">
        {{ __('auth.connecte_en_tant_que') }} <strong>{{ session('utilisateur_nom') }}</strong>
        <form class="rw-inline" method="POST" action="{{ route('deconnexion') }}">
            @csrf
            <button class="rw-bouton rw-bouton--discret" type="submit">{{ __('auth.deconnexion') }}</button>
        </form>
    </span>
</header>

<main class="rw-contenu">
    <h1 class="rw-titre">{{ __('auth.accueil_titre') }}</h1>
    <p class="rw-sous-titre">{{ __('auth.socle_avertissement') }}</p>

    {{-- Aucune donnee de parc n'est affichee ici. Le tableau de bord du legacy
         sert des agregats du parc entier a des comptes sans permission : il
         sera porte avec son cloisonnement, pas avant. --}}
    <p class="rw-note">
        <a class="rw-lien" href="{{ config('app.url_legacy', 'https://localhost:8443') }}/index.php"
           target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
    </p>
</main>
@endsection
