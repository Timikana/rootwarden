@extends('layouts.portail', ['titre' => __('nav.profile')])

@section('corps')
    <h1 class="rw-titre">{{ __('nav.profile') }}</h1>
    <p class="rw-sous-titre">{{ session('utilisateur_nom') }}</p>

    @if ($changementRequis)
        <p class="rw-erreur">{{ __('auth.changement_requis') }}</p>
    @endif

    <p class="rw-encart">{{ __('auth.socle_avertissement') }}</p>

    {{-- La page de profil du legacy publie l'identifiant de session COMPLET de
         chaque session ouverte. Elle sera portee avec une empreinte, jamais
         l'identifiant : un identifiant de session est un identifiant d'acces. --}}
    <p class="rw-note">
        <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/profile.php"
           target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
    </p>
@endsection
