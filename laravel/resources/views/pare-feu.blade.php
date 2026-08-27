@extends('layouts.portail', ['titre' => __('pare-feu.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('pare-feu.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('pare-feu.intro') }}</p>

@if ($total === 0)
    {{--
        LA LISTE EST FILTREE PAR ACCES : un role 1 sans machine attribuee voit
        cet ecran, pas une liste vide sans explication. Le legacy rend un
        `<select>` ne portant que « Choisir un serveur » — indiscernable d'une
        page cassee.
    --}}
    <div class="rw-vide" data-rw="ipt-vide">
        <p class="rw-vide__titre">{{ __('pare-feu.machines_aucune_titre') }}</p>
        <p class="rw-vide__texte">{{ __('pare-feu.machines_aucune') }}</p>
    </div>
@else

@if ($sensibles > 0)
    <div class="rw-avertissement" data-rw="ipt-avert">
        <strong>{{ __('pare-feu.avert_titre') }}</strong>
        <span class="rw-aide">
            {{ $sensibles === 1
                ? __('pare-feu.avert_un', ['total' => $total])
                : __('pare-feu.avert_plusieurs', ['nb' => $sensibles, 'total' => $total]) }}
        </span>
    </div>
@endif

<div class="rw-section">
    <label class="rw-champ">
        <span class="rw-champ__etiquette">{{ __('pare-feu.serveur') }}</span>
        <select class="rw-saisie" data-rw="ipt-serveur">
            <option value="">{{ __('pare-feu.choisir') }}</option>
            @foreach ($lignes as $l)
                <option value="{{ $l['machine']->id }}"
                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                        data-nom="{{ $l['machine']->name }}">
                    {{ $l['machine']->name }} ({{ $l['machine']->ip }}){{ $l['sensible'] ? ' — ' . __('pare-feu.sensible') : '' }}
                </option>
            @endforeach
        </select>
    </label>

    {{--
        L'AVERTISSEMENT VIENT AVANT L'ACTION, et sur ce module il porte DEUX
        faits : la machine est sensible, et son port SSH est celui-ci. Le second
        n'a l'air de rien tant qu'on ne modifie pas les regles — c'est justement
        pourquoi il est annonce des la consultation, avant que I4 et I5 n'aient
        a le redecouvrir.

        Rendu SOUS le bouton, on lirait « cette machine est en production » apres
        avoir decide d'agir dessus. Defaut mesure a l'image en F1, invisible a
        toute assertion : « le message existe » etait vrai dans les deux
        dispositions.
    --}}
    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="ipt-etat-message">{{ __('pare-feu.choisir') }}</p>

    <div class="rw-actions">
        <button type="button" class="rw-bouton" data-rw="ipt-relever" disabled>
            {{ __('pare-feu.relever') }}
        </button>
    </div>

    {{--
        LE CONTENEUR D'ANNONCE — C'EST LA MOITIE DU SOUS-LOT.

        `showNotification` du legacy vise `#notifications`, qui n'existe sur
        AUCUNE page de ce module : mesure, zero occurrence dans
        `legacy/iptables/index.php` pour treize points d'appel dans son JS. Les
        treize levent une `TypeError`, **y compris ceux places dans un `catch`**.

        Consequence mesuree par l'inventaire : appliquer un jeu de regles
        REUSSIT sur la machine et l'ecran ne dit rien. Ni succes, ni erreur.
        Tous les sous-lots suivants heritent de cette zone : c'est pourquoi elle
        est posee des I1, avant tout geste qui ecrit.

        `rw-annonce` est une region PERSISTANTE (`role="status"`), pas une bulle
        fugace : une annonce disparue ne dit plus si ce qu'on relit date d'avant
        ou d'apres.
    --}}
    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-annonce"></p>
</div>

{{--
    LES QUATRE BLOCS DU RELEVE.

    En `rw-grille` (`auto-fit`, minimum 280 px) et NON en `.rw-carte` : celle-ci
    est plafonnee a 420 px et le rapport resterait etroit sur une page de 1400.
    C'est le corollaire deja paye sur le rapport de preflight des cles SSH.
--}}
<div class="rw-grille" data-rw="ipt-blocs" hidden></div>

<div class="rw-encart" data-rw="ipt-non-porte">
    <p class="rw-sous-titre-fort">{{ __('pare-feu.suite_titre') }}</p>
    <p class="rw-prose">{{ __('pare-feu.suite') }}</p>
    <a class="rw-bouton" data-rw="ipt-lien-legacy"
       href="{{ rtrim(config('app.url_legacy'), '/') }}/iptables/"
       target="_blank" rel="noopener">{{ __('pare-feu.suite_lien') }} ↗</a>
</div>
@endif

    {{-- `@json` reste sur UNE ligne : multiligne, il casse le PHP compile. --}}
    <script id="ipt-textes" type="application/json">@json($textes)</script>
    {{-- Le port SSH par machine, lu en BASE. Les gabarits du legacy supposent
         22 ; cette table existe pour que le portage n'ait jamais a le supposer. --}}
    <script id="ipt-ports" type="application/json">@json($portsSsh)</script>
    <script src="/js/pare-feu.js?v={{ @filemtime(public_path('js/pare-feu.js')) ?: '0' }}"></script>
@endsection
