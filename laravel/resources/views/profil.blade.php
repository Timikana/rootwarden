@extends('layouts.portail', ['titre' => __('nav.profile')])

@section('corps')
    <h1 class="rw-titre">{{ __('nav.profile') }}</h1>
    <p class="rw-sous-titre">{{ session('utilisateur_nom') }} · {{ $libelleRole }}</p>

    @if ($changementRequis)
        <p class="rw-erreur rw-prose">{{ __('auth.changement_requis') }}</p>
    @endif

    <div class="rw-grille">
        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.compte_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.compte_texte', ['nom' => session('utilisateur_nom'), 'role' => $libelleRole]) }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.second_facteur_titre') }}</span>
            <span class="rw-tuile__valeur">{{ __('profil.second_facteur_valeur') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.second_facteur_texte') }}</p>
        </div>

        {{-- La page de profil du legacy publie l'identifiant de session COMPLET
             de chaque session ouverte. Le portage n'affichera qu'une empreinte :
             un identifiant de session est un identifiant d'acces. --}}
        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.non_porte_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.non_porte_texte') }}</p>
            <p class="rw-tuile__lien">
                <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/profile.php"
                   target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
            </p>
        </div>
    </div>
@endsection
