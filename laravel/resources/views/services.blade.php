@extends('layouts.portail', ['titre' => __('services.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('services.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('services.intro') }}</p>

@if ($total === 0)
    <div class="rw-vide" data-rw="services-vide">
        <p class="rw-vide__titre">{{ __('services.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('services.vide_texte') }}</p>
        <a class="rw-bouton rw-vide__action" href="{{ route('serveurs') }}">{{ __('services.vide_action') }}</a>
    </div>
@else

{{--
    La production ne se fond pas dans le choix. Ce module pilote des services
    systemd, et `srv-zabbix` en fait tourner : arreter l'un d'eux interrompt un
    service en production. Meme traitement qu'en `bashrc/` B1.
--}}
@if ($sensibles > 0)
    <div class="rw-avertissement" data-rw="services-avert">
        <strong>{{ __('services.avert_titre') }}</strong>
        <span class="rw-aide">
            {{ $sensibles === 1
                ? __('services.avert_un', ['total' => $total])
                : __('services.avert_plusieurs', ['nb' => $sensibles, 'total' => $total]) }}
        </span>
    </div>
@endif

<div class="rw-section">
    <label class="rw-champ">
        <span class="rw-champ__etiquette">{{ __('services.serveur') }}</span>
        <select class="rw-saisie" data-rw="services-serveur">
            <option value="">{{ __('services.choisir_serveur') }}</option>
            @foreach ($lignes as $l)
                <option value="{{ $l['machine']->id }}"
                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                        data-nom="{{ $l['machine']->name }}">
                    {{ $l['machine']->name }} ({{ $l['machine']->ip }}){{ $l['sensible'] ? ' — ' . __('services.sensible') : '' }}
                </option>
            @endforeach
        </select>
    </label>

    <div class="rw-actions">
        <button type="button" class="rw-bouton" data-rw="services-charger"
                disabled>{{ __('services.charger') }}</button>
    </div>

    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="services-etat">{{ __('services.choisir_serveur') }}</p>
</div>

<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('services.filtres') }}</h2>
    {{--
        LES FILTRES SONT MONTRES DES LE DEPART, DESACTIVES, AVEC LA RAISON.

        Le legacy les garde dans le DOM mais MASQUES jusqu'au chargement d'un
        serveur — mesure par S1 : `etat=false categorie=false recherche=false`.
        Une assertion d'existence les declarait bons. Un filtre qui apparait sans
        prevenir se cherche ; un filtre desactive qui dit pourquoi s'attend.
    --}}
    <p class="rw-aide" data-rw="services-filtres-aide">{{ __('services.filtres_inactifs') }}</p>
    <div class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('services.filtre_etat') }}</span>
            <select class="rw-saisie rw-saisie--compacte" data-rw="services-filtre-etat" disabled></select>
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('services.filtre_categorie') }}</span>
            <select class="rw-saisie rw-saisie--compacte" data-rw="services-filtre-categorie" disabled></select>
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('services.recherche') }}</span>
            <input type="search" class="rw-saisie rw-saisie--compacte"
                   data-rw="services-recherche" disabled>
        </label>
    </div>
</div>

{{--
    ── LE JOURNAL DES GESTES ────────────────────────────────────────────────

    Le legacy affiche un cadre NOIR VIDE des le chargement — mesure par S1. Un
    etat vide DIT ce qui manque et pourquoi, il ne se contente pas d'exister.
--}}
<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('services.journaux') }}</h2>
    <p class="rw-vide__texte" data-rw="services-journaux-vide">{{ __('services.journaux_vides') }}</p>
    <pre class="rw-journal" data-rw="services-journaux" hidden></pre>
</div>

{{--
    Une capacite non portee n'est pas un bouton inerte : le panneau dit ce que le
    geste engage, et son action principale est un lien MARQUE vers l'ancien
    portail. Les lectures sont S2, les ecritures S3.
--}}
<div class="rw-encart" data-rw="services-non-porte">
    <p class="rw-sous-titre-fort">{{ __('services.non_porte_titre') }}</p>
    <p class="rw-prose">{{ __('services.non_porte_texte') }}</p>
    <a class="rw-bouton" data-rw="services-lien-legacy"
       href="{{ rtrim(config('app.url_legacy'), '/') }}/services/"
       target="_blank" rel="noopener">{{ __('services.non_porte_lien') }} ↗</a>
</div>
@endif

    <script id="services-textes" type="application/json">@json($textes)</script>
    <script src="/js/services.js?v={{ @filemtime(public_path('js/services.js')) ?: '0' }}"></script>
@endsection
