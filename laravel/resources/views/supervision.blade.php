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

        {{-- ══ ONGLET 1 : configuration globale ════════════════════════════
             LECTURE SEULE (V3). Les quatre blocs sont peints ICI, cote serveur,
             et le script n'en montre qu'un : changer de plateforme n'emet AUCUN
             appel. Le legacy, lui, rend Zabbix cote serveur et les TROIS AUTRES
             par un `GET /supervision/config/<plateforme>` declenche au
             changement — deux chemins pour une meme donnee.

             LES DEUX SECRETS NE SONT PAS LUS EN BASE : le service ne rend qu'un
             booleen de presence. Le legacy affiche `********` dans un
             `<input type="password">`, donc la valeur reelle ne sort pas non
             plus — mesure faite, aucun defaut de ce cote — mais ne pas la lire
             du tout ferme la question au lieu de la surveiller. --}}
        <div id="panneau-config" data-rw="panneau-config" role="tabpanel">
            @foreach ($plateformes as $plateforme)
                @php($config = $configuration[$plateforme] ?? null)
                <article id="config-{{ $plateforme }}" class="rw-carte rw-carte--pleine"
                         @if (! $loop->first) hidden @endif>
                    <h3 class="rw-sous-titre">{{ __('superv.config_titre') }} — {{ ucfirst($plateforme) }}</h3>
                    <p class="rw-aide rw-prose">{{ __('superv.config_description') }}</p>

                    @if ($config === null)
                        {{-- L'ABSENCE SE DIT. Sans ligne en base, les deux
                             portails affichent des valeurs par defaut : sans
                             avertissement, un exploitant les lit comme une
                             configuration enregistree. --}}
                        <div class="rw-vide" data-rw="superv-config-vide">
                            <p class="rw-vide__titre">{{ __('superv.config_aucune') }}</p>
                            <p class="rw-vide__texte rw-prose">{{ __('superv.config_aucune_aide', ['plateforme' => ucfirst($plateforme)]) }}</p>
                        </div>
                    @else
                        <div class="rw-tableau-cadre" data-rw="superv-config-corps">
                            <table class="rw-tableau">
                                <tbody>
                                    @foreach ($champs[$plateforme] as $colonne => $cle)
                                        <tr>
                                            <th scope="row">{{ __('superv.champ_' . $cle) }}</th>
                                            <td>
                                                @if (trim((string) ($config->$colonne ?? '')) === '')
                                                    <span class="rw-aide">{{ __('superv.champ_vide') }}</span>
                                                @else
                                                    <code>{{ $config->$colonne }}</code>
                                                @endif
                                            </td>
                                        </tr>
                                    @endforeach

                                    {{-- LA PRESENCE D'UN SECRET, JAMAIS SA
                                         VALEUR. Le service ne selectionne meme
                                         pas la colonne. --}}
                                    @if ($plateforme === 'zabbix')
                                        <tr data-rw="superv-config-psk">
                                            <th scope="row">{{ __('superv.champ_psk_valeur') }}</th>
                                            <td>
                                                <span class="rw-badge @if (! $config->psk_pose) rw-badge--neutre @endif">{{ $config->psk_pose ? __('superv.secret_pose') : __('superv.secret_absent') }}</span>
                                                <span class="rw-aide rw-cellule-note">{{ __('superv.secret_jamais_affiche') }}</span>
                                            </td>
                                        </tr>
                                    @endif
                                    @if ($plateforme === 'telegraf')
                                        <tr data-rw="superv-config-jeton">
                                            <th scope="row">{{ __('superv.champ_telegraf_jeton') }}</th>
                                            <td>
                                                <span class="rw-badge @if (! $config->jeton_pose) rw-badge--neutre @endif">{{ $config->jeton_pose ? __('superv.secret_pose') : __('superv.secret_absent') }}</span>
                                                <span class="rw-aide rw-cellule-note">{{ __('superv.secret_jamais_affiche') }}</span>
                                            </td>
                                        </tr>
                                    @endif
                                </tbody>
                            </table>
                        </div>
                        <p class="rw-aide rw-prose">{{ __('superv.config_plus_recente') }}</p>
                    @endif

                    {{-- L'ECRITURE N'EST PAS PORTEE (V4), et la page le dit
                         plutot que d'offrir un formulaire qui n'enregistrerait
                         rien. --}}
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

        {{-- ══ ONGLET 2 : profils ═════════════════════════════════════════
             LECTURE SEULE (V2). Les quatre catalogues sont peints ICI, cote
             serveur, et le script n'en montre qu'un : changer de plateforme
             n'emet donc AUCUN appel. Le legacy, lui, rejoue
             `GET /supervision/profiles` a l'ouverture de l'onglet ET a chaque
             bascule — et la bascule en emet QUATRE, dont deux identiques. --}}
        <div id="panneau-profiles" data-rw="panneau-profiles" role="tabpanel" hidden>
            <article class="rw-carte rw-carte--pleine">
                <h3 class="rw-sous-titre">{{ __('superv.profils_titre') }}</h3>
                <p class="rw-aide rw-prose">{{ __('superv.profils_description') }}</p>

                @foreach ($plateformes as $plateforme)
                    @php($catalogue = $profils[$plateforme] ?? [])
                    <div id="profils-{{ $plateforme }}" @if (! $loop->first) hidden @endif>
                        @if (count($catalogue) === 0)
                            <div class="rw-vide" data-rw="superv-profils-vide">
                                <p class="rw-vide__titre">{{ __('superv.profils_aucun') }}</p>
                                <p class="rw-vide__texte rw-prose">{{ __('superv.profils_aucun_aide', ['plateforme' => ucfirst($plateforme)]) }}</p>
                            </div>
                        @else
                            {{-- Le defilement appartient au CADRE du tableau,
                                 jamais au corps de la page. --}}
                            <div class="rw-tableau-cadre">
                                <table class="rw-tableau">
                                    <thead>
                                        <tr>
                                            <th>{{ __('superv.profil_nom') }}</th>
                                            <th>{{ __('superv.profil_metadonnees') }}</th>
                                            <th>{{ __('superv.profil_serveur') }}</th>
                                            <th>{{ __('superv.profil_mandataire') }}</th>
                                            <th>{{ __('superv.profil_machines') }}</th>
                                        </tr>
                                    </thead>
                                    <tbody data-rw="superv-profils-corps">
                                        @foreach ($catalogue as $profil)
                                            <tr>
                                                <td>
                                                    <strong>{{ $profil->name }}</strong>
                                                    @if (trim((string) $profil->description) !== '')
                                                        <span class="rw-aide rw-cellule-note">{{ $profil->description }}</span>
                                                    @endif
                                                </td>
                                                <td>{{ trim((string) $profil->host_metadata) !== '' ? $profil->host_metadata : __('superv.profil_herite') }}</td>
                                                {{-- UNE VALEUR ABSENTE DIT CE QU'ELLE
                                                     SIGNIFIE. Le legacy ecrit « - »,
                                                     qui n'apprend rien : ici, NULL veut
                                                     dire « la configuration globale
                                                     s'applique », et c'est ce qui est
                                                     ecrit. --}}
                                                <td>{{ trim((string) $profil->zabbix_server) !== '' ? $profil->zabbix_server : __('superv.profil_herite') }}</td>
                                                <td>{{ trim((string) $profil->zabbix_proxy) !== '' ? $profil->zabbix_proxy : __('superv.profil_herite') }}</td>
                                                <td>
                                                    <span class="rw-badge rw-badge--note @if ((int) $profil->machines === 0) rw-badge--neutre @endif">{{ $profil->machines }}</span>
                                                </td>
                                            </tr>
                                        @endforeach
                                    </tbody>
                                </table>
                            </div>
                            {{-- L'astuce ne vaut que s'il y a des valeurs dont
                                 parler : sur une plateforme sans profil, elle
                                 decrivait un contenu absent. --}}
                            <p class="rw-aide rw-prose">{{ __('superv.profils_interpolation') }}</p>
                        @endif
                    </div>
                @endforeach

                {{-- LA MODIFICATION N'EST PAS PORTEE (V5), et la page le dit
                     plutot que d'offrir des boutons inertes. Le legacy, lui,
                     serialise le profil ENTIER — `notes` comprise — dans un
                     attribut `onclick` de chacune de ses lignes. --}}
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
