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
        {{--
            LE BOUTON PORTE UN `data-rw`. Celui du legacy n'a **aucun**
            identifiant — seulement `onclick="loadServices()"` — et la suite a du
            l'ancrer sur cet attribut. Un element pilote par un test porte un
            ancrage stable.
        --}}
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

<div class="rw-section" data-rw="services-bloc-tableau" hidden>
    <p class="rw-aide" role="status" aria-live="polite" data-rw="services-compte"></p>
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('services.col_service') }}</th>
                    <th>{{ __('services.col_etat') }}</th>
                    {{--
                        « État au démarrage » et non « activé oui/non » : systemd
                        connaît `static` et `masked`, que ni « oui » ni « non »
                        ne savent dire. Le champ vient de `unit_file_state`.
                    --}}
                    <th>{{ __('services.col_active') }}</th>
                    <th>{{ __('services.col_categorie') }}</th>
                    <th>{{ __('services.col_description') }}</th>
                    <th>{{ __('services.col_actions') }}</th>
                </tr>
            </thead>
            <tbody data-rw="services-tableau"></tbody>
        </table>
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
    ═══ LE PANNEAU DE DECISION, A LA PLACE D'UN `confirm()` NATIF ═══════════

    `services.js` posait `window.confirm()`. Trois raisons de le retirer, et la
    troisieme est celle qui coute :

      - il recouvre la ligne sur laquelle on decide ;
      - il ne se style pas, donc il ne peut pas distinguer un arret d'un
        redemarrage ni marquer un service protege ;
      - **il BLOQUE Puppeteer.** Les cinq gestes qui ECRIVENT sur une machine
        etaient donc les seuls du module qu'aucune suite ne pouvait exercer.
        Un dialogue natif ne rend pas un geste dangereux : il le rend
        INTESTABLE, ce qui est pire.

    Le panneau NOMME le service ET la machine, comme le faisait le texte du
    `confirm()` : c'est de la parite, elle est conservee.
--}}
<div class="rw-panneau-decision" data-rw="services-panneau" hidden>
    <p class="rw-panneau-decision__texte" data-rw="services-panneau-titre"></p>
    <p class="rw-prose" data-rw="services-panneau-texte"></p>
    <div class="rw-panneau-decision__actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="services-panneau-annuler">{{ __('services.annuler') }}</button>
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="services-panneau-confirmer">{{ __('services.confirmer') }}</button>
    </div>
</div>

{{--
    ── CE QUE CET ENCART DISAIT, ET POURQUOI C'ETAIT FAUX ───────────────────

    Il annoncait « les gestes sur les services ne sont pas encore portes » et
    offrait un bouton PRINCIPAL vers `/services/` de l'ancien portail.

    Les deux etaient faux, et mesures :
      - les cinq gestes SONT portes. `pilote()` appelle `/services/<geste>` par
        concatenation — ce qui explique qu'une recherche du chemin litteral ne
        trouve que `/services/list` et laisse croire au contraire ;
      - `legacy/services/` est ARCHIVE depuis le 2026-08-27 (`_deprecated/`).
        Le bouton menait donc a un 404, en action PRINCIPALE.

    *Une donnee qui ment le plus longtemps est celle que personne ne remet en
    question.* Le lien est retire plutot que reetiquete : il n'y a plus rien au
    bout.
--}}
<div class="rw-encart" data-rw="services-etat-portage">
    <p class="rw-sous-titre-fort">{{ __('services.portage_titre') }}</p>
    <p class="rw-prose">{{ __('services.portage_texte') }}</p>
</div>
@endif

    <script id="services-textes" type="application/json">@json($textes)</script>
    <script src="/js/services.js?v={{ @filemtime(public_path('js/services.js')) ?: '0' }}"></script>
@endsection
