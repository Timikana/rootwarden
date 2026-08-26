@extends('layouts.portail', ['titre' => __('bashrc.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('bashrc.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('bashrc.intro') }}</p>

@if ($total === 0)
    <div class="rw-vide" data-rw="bashrc-vide">
        <p class="rw-vide__titre">{{ __('bashrc.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('bashrc.vide_texte') }}</p>
        <a class="rw-bouton rw-vide__action" href="{{ route('serveurs') }}">{{ __('bashrc.vide_action') }}</a>
    </div>
@else

{{--
    UNE MACHINE DE PRODUCTION NE SE FOND PAS DANS LA LISTE.

    Le legacy affiche `srv-zabbix` avec la meme case a cocher que les machines
    d'essai — rien ne la distingue. Et `_list_users` propose `root` : la page
    permet donc de cocher production + `root` et de deployer. Defaut vu A
    L'IMAGE, invisible a toute assertion DOM.

    L'avertissement est en TETE, avant le tableau : lu apres, il arriverait
    apres la decision.
--}}
@if ($sensibles > 0)
    <div class="rw-avertissement" data-rw="bashrc-avert">
        <strong>{{ __('bashrc.avert_titre') }}</strong>
        <span class="rw-aide">
            {{ $sensibles === 1
                ? __('bashrc.avert_un', ['total' => $total])
                : __('bashrc.avert_plusieurs', ['nb' => $sensibles, 'total' => $total]) }}
        </span>
    </div>
@endif

<div class="rw-onglets" role="tablist">
    <button type="button" class="rw-onglet rw-onglet--actif" role="tab" aria-selected="true"
            data-rw="bashrc-onglet-deploiement"
            data-panneau="deploiement">{{ __('bashrc.onglet_deploiement') }}</button>
    <button type="button" class="rw-onglet" role="tab" aria-selected="false"
            data-rw="bashrc-onglet-historique"
            data-panneau="historique">{{ __('bashrc.onglet_historique') }}</button>
    <button type="button" class="rw-onglet" role="tab" aria-selected="false"
            data-rw="bashrc-onglet-gabarit"
            data-panneau="gabarit">{{ __('bashrc.onglet_gabarit') }}</button>
</div>

<section class="rw-section" data-rw="bashrc-panneau-deploiement">
    <h2 class="rw-section__entete">{{ __('bashrc.machines') }}</h2>

    {{--
        LE COMPTEUR S'ENONCE, IL NE S'AFFICHE PAS COMME UN CHIFFRE.

        Le legacy montre « Serveurs cibles 0 ». Un `0` se lit comme une donnee,
        pas comme un etat : « aucune machine selectionnee — un deploiement ne
        deploierait rien » dit la MEME chose et se comprend sans interpreter.
    --}}
    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="bashrc-compteur">{{ __('bashrc.aucune_selection') }}</p>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th><span class="rw-visuellement-cache">{{ __('bashrc.machines') }}</span></th>
                    <th>{{ __('bashrc.col_nom') }}</th>
                    <th>{{ __('bashrc.col_ip') }}</th>
                    <th>{{ __('bashrc.col_etat') }}</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($lignes as $l)
                    <tr @class(['rw-ligne-sensible' => $l['sensible']])
                        data-rw="bashrc-ligne-{{ $l['machine']->id }}">
                        <td>
                            <label class="rw-champ rw-champ--case">
                                <input type="checkbox" class="rw-case"
                                       data-rw="bashrc-cible-{{ $l['machine']->id }}"
                                       data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                                       value="{{ $l['machine']->id }}">
                                <span class="rw-visuellement-cache">{{ $l['machine']->name }}</span>
                            </label>
                        </td>
                        <td>
                            <span class="rw-tableau__fort">{{ $l['machine']->name }}</span>
                            @if ($l['sensible'])
                                <span class="rw-badge rw-badge--alerte"
                                      data-rw="bashrc-marque-{{ $l['machine']->id }}"
                                      title="{{ __('bashrc.sensible_aide') }}">{{ __('bashrc.sensible') }}</span>
                            @endif
                        </td>
                        <td><code class="rw-code">{{ $l['machine']->ip }}</code></td>
                        <td>
                            @if ($l['deploiement'])
                                {{ __('bashrc.deploye_le', [
                                    'date' => $l['deploiement']['date'],
                                    'auteur' => $l['deploiement']['auteur'] ?? '—']) }}
                            @else
                                <span class="rw-tableau__discret">{{ __('bashrc.jamais') }}</span>
                            @endif
                            {{--
                                UNE SIMULATION N'EST PAS UN DEPLOIEMENT, et elle
                                se dit a part. Le legacy la jette : sa colonne
                                dit « jamais deploye », ce qui est vrai, mais
                                perd que quelqu'un a simule un deploiement sur
                                cette machine — sur `srv-zabbix`, l'information
                                merite d'exister.
                            --}}
                            @if ($l['simulation'])
                                {{--
                                    UN BLOC, PAS UN `span`. En inline, la phrase
                                    se collait a « jamais deploye » et les deux
                                    se lisaient comme une seule : « jamais
                                    deploye simule le 2026-07-25… ». Presenter
                                    la simulation ACCOLEE au verdict de
                                    deploiement, c'est precisement ce que ce
                                    bloc existe pour eviter. Vu a l'image.
                                --}}
                                <div class="rw-aide" data-rw="bashrc-simulation-{{ $l['machine']->id }}">
                                    {{ __('bashrc.simule_le', [
                                        'date' => $l['simulation']['date'],
                                        'auteur' => $l['simulation']['auteur'] ?? '—']) }}
                                </div>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    {{--
        ── LES COMPTES DE LA MACHINE (B2) ──────────────────────────────────

        Rempli par `/bashrc/users` a travers la passerelle, quand UNE SEULE
        machine est cochee. Le legacy fait de meme (`_currentMachineId` n'est
        pose que dans ce cas) ; ici on le DIT au lieu de ne rien faire.

        La route ouvre une session SSH et lance un `awk` sur `/etc/passwd` :
        c'est une LECTURE, elle n'ecrit rien.
    --}}
    <h2 class="rw-section__entete">{{ __('bashrc.comptes_titre') }}</h2>
    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="bashrc-comptes-etat">{{ __('bashrc.comptes_choisir') }}</p>

    <div data-rw="bashrc-comptes" hidden>
        <label class="rw-champ rw-champ--case">
            <input type="checkbox" class="rw-case" data-rw="bashrc-comptes-tout">
            <span>
                <span>{{ __('bashrc.tout') }}</span>
                {{--
                    « TOUT COCHER » RETIENT AUSSI `root`, ET ON LE DIT.

                    Le legacy le fait en silence. `_list_users` retient
                    `UID == 0`, donc `root` est dans la liste — et c'est le
                    compte dont le `.bashrc` s'execute a chaque connexion
                    administrateur. Le comportement est porte a l'identique ;
                    ce qui change, c'est qu'il s'annonce.
                --}}
                <span class="rw-aide">{{ __('bashrc.tout_avec_root') }}</span>
            </span>
        </label>

        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th><span class="rw-visuellement-cache">{{ __('bashrc.col_compte') }}</span></th>
                        <th>{{ __('bashrc.col_compte') }}</th>
                        <th>{{ __('bashrc.col_uid') }}</th>
                        <th>{{ __('bashrc.col_home') }}</th>
                        <th>{{ __('bashrc.col_bashrc') }}</th>
                    </tr>
                </thead>
                <tbody data-rw="bashrc-comptes-corps"></tbody>
            </table>
        </div>

        <div class="rw-actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="bashrc-apercu"
                    title="{{ __('bashrc.apercu_aide') }}">{{ __('bashrc.apercu') }}</button>
        </div>
    </div>

    {{--
        ── L'APERCU ────────────────────────────────────────────────────────
        `/bashrc/preview` lit le fichier distant et construit le diff cote
        serveur. Lecture, elle aussi.
    --}}
    <section class="rw-section" data-rw="bashrc-apercu-panneau" hidden>
        <h2 class="rw-section__entete">{{ __('bashrc.apercu_titre') }}</h2>
        <div data-rw="bashrc-apercu-contenu"></div>
    </section>

    {{--
        Une capacite non portee n'est pas un bouton inerte : le panneau dit ce
        que le geste engage, et son action principale est un lien MARQUE vers
        l'ancien portail. Le DEPLOIEMENT lui-meme est B4 — B2 ne porte que les
        deux lectures.
    --}}
    <div class="rw-encart" data-rw="bashrc-non-porte">
        <p class="rw-sous-titre-fort">{{ __('bashrc.non_porte_titre') }}</p>
        <p class="rw-prose">{{ __('bashrc.non_porte_texte') }}</p>
        <a class="rw-bouton" data-rw="bashrc-lien-legacy"
           href="{{ rtrim(config('app.url_legacy'), '/') }}/bashrc/"
           target="_blank" rel="noopener">{{ __('bashrc.non_porte_lien') }} ↗</a>
    </div>
</section>

<section class="rw-section" data-rw="bashrc-panneau-historique" hidden>
    <h2 class="rw-section__entete">{{ __('bashrc.onglet_historique') }}</h2>
    <p class="rw-aide">{{ __('bashrc.sensible_aide') }}</p>
</section>

<section class="rw-section" data-rw="bashrc-panneau-gabarit" hidden>
    <h2 class="rw-section__entete">{{ __('bashrc.onglet_gabarit') }}</h2>
    <p class="rw-prose">{{ __('bashrc.non_porte_texte') }}</p>
    <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/bashrc/"
       target="_blank" rel="noopener">{{ __('bashrc.non_porte_lien') }} ↗</a>
</section>
@endif

    {{--
        Les phrases du compteur partent en UN bloc JSON, calcule dans le
        CONTROLEUR : ecrites dans le JS elles echapperaient aux deux catalogues,
        et passees a `@json` comme litteral inline elles cassent le PHP compile
        — la premiere redaction rendait `json_encode([... )` sans crochet
        fermant, et la page 500ait. `@json` prend une VARIABLE.
    --}}
    <script id="bashrc-textes" type="application/json">@json($textes)</script>
    <script src="/js/bashrc.js?v={{ @filemtime(public_path('js/bashrc.js')) ?: '0' }}"></script>
@endsection
