@extends('layouts.portail', ['titre' => __('search.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('search.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('search.desc') }}</p>

    <div class="rw-encart rw-prose">
        <strong>{{ __('search.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('search.guide_portee') }}</li>
            <li>{{ __('search.guide_droits') }}</li>
            <li>{{ __('search.guide_liens') }}</li>
        </ul>
    </div>

    {{-- Le champ prend la largeur : c'est l'objet principal de la page. --}}
    <label class="rw-champ rw-recherche">
        <span class="rw-champ__etiquette">{{ __('search.label') }}</span>
        <input type="search" id="search-input" class="rw-saisie rw-saisie--large"
               data-rw="terme" autocomplete="off" autofocus
               value="{{ $terme }}"
               title="{{ __('search.tip_input') }}"
               placeholder="{{ __('search.placeholder') }}">
    </label>

    <p class="rw-annonce" id="search-meta" role="status" aria-live="polite" data-rw="etat"></p>

    <div class="rw-grille" id="search-results"></div>

    @php($libelles = ['cat_machines' => __('search.cat_machines'), 'cat_users' => __('search.cat_users'), 'cat_cves' => __('search.cat_cves'), 'cat_tickets' => __('search.cat_tickets'), 'cat_audit' => __('search.cat_audit'), 'hint_min' => __('search.hint_min'), 'searching' => __('search.searching'), 'results_for' => __('search.results_for'), 'no_results' => __('search.no_results'), 'no_results_aide' => __('search.no_results_aide'), 'err' => __('search.err'), 'ancien_portail' => __('search.ancien_portail')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="search-libelles" type="application/json">@json($libelles)</script>
    {{-- Table de traduction des liens du backend : voir App\Support\LiensLegacy. --}}
    <script id="search-liens" type="application/json">@json($liens)</script>

    <script src="/js/recherche.js?v={{ @filemtime(public_path('js/recherche.js')) ?: '0' }}"></script>
@endsection
