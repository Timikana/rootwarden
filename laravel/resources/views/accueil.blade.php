@extends('layouts.portail', ['titre' => __('nav.dashboard')])

@section('corps')
    <h1 class="rw-titre">{{ __('accueil.bienvenue', ['nom' => session('utilisateur_nom')]) }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('accueil.orientation') }}</p>

    {{-- La grille remplit la largeur disponible : `auto-fit` avec un minimum de
         280 px donne 2 colonnes sur un ecran moyen, 4 ou 5 sur un grand. --}}
    <div class="rw-grille">

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.acces_titre') }}</span>
            <span class="rw-tuile__valeur">{{ $modulesAccessibles }}</span>
            <p class="rw-tuile__texte">{{ trans_choice('accueil.acces_texte', $modulesAccessibles, ['role' => $libelleRole]) }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.portes_titre') }}</span>
            <span class="rw-tuile__valeur">{{ $modulesPortes }} / {{ $modulesAccessibles }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.portes_texte') }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.securite_titre') }}</span>
            <span class="rw-tuile__valeur">{{ __('accueil.securite_valeur') }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.securite_texte') }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.ancien_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.ancien_texte') }}</p>
            <p class="rw-tuile__lien">
                <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/index.php"
                   target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
            </p>
        </div>

    </div>

    {{-- Aucun agregat de parc n'est affiche ici. Le tableau de bord du legacy
         sert la taille du parc, les CVE critiques, la note d'audit SSH et les
         noms de cinq comptes a des roles sans aucune permission. Il sera porte
         AVEC son cloisonnement, pas avant. --}}
    <div class="rw-vide" style="margin-top:20px">
        <div class="rw-vide__titre">{{ __('accueil.parc_titre') }}</div>
        <p>{{ __("accueil.parc_texte") }}</p>
    </div>
@endsection
