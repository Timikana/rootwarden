@extends('layouts.portail', ['titre' => __('superv.titre')])

@section('corps')
    <section class="rw-section">
        <div class="rw-entete-page">
            <div>
                <h2 class="rw-titre">{{ __('superv.titre') }}</h2>
                <p class="rw-aide">{{ __('superv.sous_titre') }}</p>
                <p class="rw-aide rw-prose">{{ __('superv.description') }}</p>
            </div>

            {{-- LE CHOIX DE PLATEFORME. Il ne declenche AUCUN appel : les quatre
                 blocs de configuration sont deja dans la page, le script en
                 montre un et cache les trois autres. Le legacy, lui, rejoue
                 `GET /supervision/profiles` a chaque changement. --}}
            <label class="rw-etiquette-champ rw-etiquette-champ--borne">
                <span class="rw-etiquette">{{ __('superv.plateforme') }}</span>
                <select class="rw-saisie rw-saisie--compacte" data-rw="superv-plateforme">
                    @foreach ($plateformes as $plateforme)
                        <option value="{{ $plateforme }}">{{ ucfirst($plateforme) }}</option>
                    @endforeach
                </select>
            </label>
        </div>

        {{-- LES QUATRE ONGLETS, dans l'ordre du legacy. Chaque bouton porte son
             `data-rw` : un test n'a jamais a compter des boutons ni a viser
             « le premier ». --}}
        <div class="rw-onglets" role="tablist">
            @foreach ($onglets as $onglet)
                <button type="button" role="tab"
                        class="rw-onglet @if ($loop->first) rw-onglet--actif @endif"
                        data-rw="onglet-{{ $onglet }}"
                        aria-selected="{{ $loop->first ? 'true' : 'false' }}"
                        aria-controls="panneau-{{ $onglet }}">{{ __('superv.onglet_' . $onglet) }}</button>
            @endforeach
        </div>

        {{-- ══ ONGLET 1 : configuration globale ═══════════════════════════════
             Les quatre blocs de plateforme sont TOUS rendus, un seul visible. La
             lecture de leurs valeurs (V3) et leur enregistrement (V4) ne sont pas
             dans V1 : le panneau le DIT et mene a l'ancien portail, plutot que
             d'offrir un formulaire qui n'enregistrerait rien. --}}
        <div id="panneau-config" data-rw="panneau-config" role="tabpanel">
            @foreach ($plateformes as $plateforme)
                <article id="config-{{ $plateforme }}" class="rw-carte rw-carte--pleine"
                         @if (! $loop->first) hidden @endif>
                    <h3 class="rw-sous-titre">{{ __('superv.config_titre') }} — {{ ucfirst($plateforme) }}</h3>
                    <p class="rw-aide rw-prose">{{ __('superv.config_description') }}</p>
                    <div class="rw-vide">
                        <p class="rw-vide__titre">{{ __('superv.pas_encore_porte') }}</p>
                        <p class="rw-vide__texte rw-prose">{{ __('superv.a_venir_config') }}</p>
                        <div class="rw-vide__action">
                            <a class="rw-bouton rw-bouton--discret"
                               href="{{ config('app.url_legacy') }}/supervision/"
                               target="_blank" rel="noopener">{{ __('superv.vers_legacy') }} ↗</a>
                        </div>
                    </div>
                </article>
            @endforeach
        </div>

        {{-- ══ ONGLET 2 : profils ═════════════════════════════════════════════ --}}
        <div id="panneau-profiles" data-rw="panneau-profiles" role="tabpanel" hidden>
            <article class="rw-carte rw-carte--pleine">
                <h3 class="rw-sous-titre">{{ __('superv.profils_titre') }}</h3>
                <p class="rw-aide rw-prose">{{ __('superv.profils_description') }}</p>
                <div class="rw-vide">
                    <p class="rw-vide__titre">{{ __('superv.pas_encore_porte') }}</p>
                    <p class="rw-vide__texte rw-prose">{{ __('superv.a_venir_profils') }}</p>
                    <div class="rw-vide__action">
                        <a class="rw-bouton rw-bouton--discret"
                           href="{{ config('app.url_legacy') }}/supervision/"
                           target="_blank" rel="noopener">{{ __('superv.vers_legacy') }} ↗</a>
                    </div>
                </div>
            </article>
        </div>

        {{-- ══ ONGLET 3 : deploiement ═════════════════════════════════════════
             C'est le panneau le plus dangereux du module : trois boutons y
             installent, reconfigurent ou DESINSTALLENT l'agent sur chaque machine
             cochee. Aucun d'eux n'est porte dans V1, et aucun n'est ici — un
             bouton present mais inerte serait pire qu'absent. --}}
        <div id="panneau-deploy" data-rw="panneau-deploy" role="tabpanel" hidden>
            <article class="rw-carte rw-carte--pleine">
                <h3 class="rw-sous-titre">{{ __('superv.deploiement_titre') }}</h3>
                <p class="rw-aide rw-prose">{{ __('superv.deploiement_description') }}</p>
                <div class="rw-vide">
                    <p class="rw-vide__titre">{{ __('superv.pas_encore_porte') }}</p>
                    <p class="rw-vide__texte rw-prose">{{ __('superv.a_venir_deploiement') }}</p>
                    <div class="rw-vide__action">
                        <a class="rw-bouton rw-bouton--discret"
                           href="{{ config('app.url_legacy') }}/supervision/"
                           target="_blank" rel="noopener">{{ __('superv.vers_legacy') }} ↗</a>
                    </div>
                </div>
            </article>
        </div>

        {{-- ══ ONGLET 4 : editeur ═════════════════════════════════════════════
             LE SEUL GESTE QUE V1 PORTE VRAIMENT : le garde « aucun serveur
             choisi ». C'est la seule des onze cles cassees du module qui soit
             atteignable sans joindre une machine — et cote legacy elle s'affiche
             en clair, `editor_select_server`, dans une boite native. --}}
        <div id="panneau-editor" data-rw="panneau-editor" role="tabpanel" hidden>
            <article class="rw-carte rw-carte--pleine">
                <h3 class="rw-sous-titre">{{ __('superv.editeur_titre') }}</h3>
                <p class="rw-aide rw-prose">{{ __('superv.editeur_description') }}</p>

                @if (count($machines) === 0)
                    <div class="rw-vide">
                        <p class="rw-vide__titre">{{ __('superv.aucune_machine') }}</p>
                        <p class="rw-vide__texte rw-prose">{{ __('superv.aucune_machine_aide') }}</p>
                    </div>
                @else
                    <div class="rw-barre-filtres">
                        <label class="rw-etiquette-champ rw-etiquette-champ--borne">
                            <span class="rw-etiquette">{{ __('superv.editeur_serveur') }}</span>
                            <select class="rw-saisie rw-saisie--compacte" data-rw="superv-serveur">
                                <option value="">{{ __('superv.editeur_choisir_serveur') }}</option>
                                @foreach ($machines as $m)
                                    <option value="{{ $m->id }}">{{ $m->name }} ({{ $m->ip }})</option>
                                @endforeach
                            </select>
                        </label>
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="superv-lire-config">{{ __('superv.editeur_lire') }}</button>
                    </div>

                    {{-- Le refus s'ecrit DANS la page, pas dans une boite native :
                         la boite recouvre la ligne sur laquelle on decide, ne se
                         style pas, et bloque le test qui doit mener le geste au
                         bout. --}}
                    <p class="rw-aide" data-rw="superv-editeur-message" aria-live="polite" hidden></p>
                @endif

                <div class="rw-vide">
                    <p class="rw-vide__titre">{{ __('superv.pas_encore_porte') }}</p>
                    <p class="rw-vide__texte rw-prose">{{ __('superv.a_venir_editeur') }}</p>
                    <div class="rw-vide__action">
                        <a class="rw-bouton rw-bouton--discret"
                           href="{{ config('app.url_legacy') }}/supervision/"
                           target="_blank" rel="noopener">{{ __('superv.vers_legacy') }} ↗</a>
                    </div>
                </div>
            </article>
        </div>
    </section>

    <script id="superv-libelles" type="application/json">@json($libelles)</script>
    <script src="{{ asset('js/supervision.js') }}" defer></script>
@endsection
