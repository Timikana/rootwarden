@extends('layouts.socle', ['titre' => __('auth.profil_titre')])

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
    <h1 class="rw-titre">{{ __('auth.profil_titre') }}</h1>
    <p class="rw-sous-titre">{{ __('auth.socle_avertissement') }}</p>

    {{-- La page de profil du legacy publie l'identifiant de session COMPLET de
         chaque session ouverte. Elle sera portee avec une empreinte, jamais
         l'identifiant : un identifiant de session est un identifiant d'acces. --}}
    <p class="rw-note">
        <a class="rw-lien" href="{{ config('app.url_legacy', 'https://localhost:8443') }}/profile.php"
           target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
    </p>
</main>
@endsection
