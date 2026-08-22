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
             LECTURE (V3) ET ECRITURE (V4). Les quatre blocs sont peints ICI, cote
             serveur, et le script n'en montre qu'un : changer de plateforme
             n'emet AUCUN appel. Le legacy, lui, rend Zabbix cote serveur et les
             TROIS AUTRES par un `GET /supervision/config/<plateforme>` declenche
             au changement.

             L'ENREGISTREMENT EST UNE SOUMISSION DE FORMULAIRE, PAS UN APPEL
             CLIENT : rien ne part du navigateur en arriere-plan, donc la
             propriete « cette page n'appelle personne » reste vraie.

             LE SECRET N'EST PAS LU EN BASE : le service rend un booleen de
             presence, et le champ part VIDE. Vide veut dire « ne change rien ». --}}
        <div id="panneau-config" data-rw="panneau-config" role="tabpanel">
            @if (session('superv_message'))
                <p class="rw-confirmation" data-rw="superv-config-message"
                   role="status">{{ session('superv_message') }}</p>
            @elseif (session('superv_erreur'))
                <p class="rw-erreur" data-rw="superv-config-message"
                   role="alert">{{ session('superv_erreur') }}</p>
            @endif

            @foreach ($plateformes as $plateforme)
                @php($config = $configuration[$plateforme] ?? null)
                <article id="config-{{ $plateforme }}" class="rw-carte rw-carte--pleine"
                         @if (! $loop->first) hidden @endif>
                    <h3 class="rw-sous-titre">{{ __('superv.config_titre') }} — {{ ucfirst($plateforme) }}</h3>
                    <p class="rw-aide rw-prose">{{ __('superv.config_description') }}</p>

                    @if ($config === null)
                        {{-- L'ABSENCE SE DIT. Sans ligne en base, le formulaire
                             part vide : sans avertissement, un exploitant lirait
                             ses champs vides comme une configuration enregistree. --}}
                        <div class="rw-vide" data-rw="superv-config-vide">
                            <p class="rw-vide__titre">{{ __('superv.config_aucune') }}</p>
                            <p class="rw-vide__texte rw-prose">{{ __('superv.config_aucune_aide', ['plateforme' => ucfirst($plateforme)]) }}</p>
                        </div>
                    @endif

                    <form method="POST" action="{{ route('supervision.configuration') }}"
                          data-rw="superv-config-form-{{ $plateforme }}">
                        @csrf
                        <input type="hidden" name="plateforme" value="{{ $plateforme }}">

                        <div class="rw-tableau-cadre" data-rw="superv-config-corps">
                            <table class="rw-tableau">
                                <tbody>
                                    @foreach ($champs[$plateforme] as $colonne => $cle)
                                        <tr>
                                            <th scope="row">
                                                <label for="cfg-{{ $plateforme }}-{{ $colonne }}">{{ __('superv.champ_' . $cle) }}</label>
                                            </th>
                                            <td>
                                                @if (isset($choix[$colonne]))
                                                    {{-- CHOIX FERME : la colonne est
                                                         un `enum` en base, ou sa liste
                                                         de valeurs est fermee cote
                                                         deploiement. --}}
                                                    <select class="rw-saisie rw-saisie--compacte"
                                                            id="cfg-{{ $plateforme }}-{{ $colonne }}"
                                                            name="{{ $colonne }}"
                                                            data-rw="superv-config-champ-{{ $colonne }}">
                                                        @foreach ($choix[$colonne] as $valeur)
                                                            <option value="{{ $valeur }}" @selected(($config->$colonne ?? '') === $valeur)>{{ $valeur }}</option>
                                                        @endforeach
                                                    </select>
                                                @elseif ($colonne === 'extra_config')
                                                    <textarea class="rw-saisie" rows="3"
                                                              id="cfg-{{ $plateforme }}-{{ $colonne }}"
                                                              name="{{ $colonne }}"
                                                              data-rw="superv-config-champ-{{ $colonne }}">{{ $config->$colonne ?? '' }}</textarea>
                                                @else
                                                    <input class="rw-saisie" type="text"
                                                           id="cfg-{{ $plateforme }}-{{ $colonne }}"
                                                           name="{{ $colonne }}"
                                                           value="{{ $config->$colonne ?? '' }}"
                                                           data-rw="superv-config-champ-{{ $colonne }}">
                                                @endif
                                            </td>
                                        </tr>
                                    @endforeach

                                    {{-- LE SECRET : UN CHAMP QUI PART TOUJOURS VIDE.
                                         Le legacy y met `********`, ce qui oblige son
                                         backend a reconnaitre son propre masque pour
                                         ne pas l'ecrire. Un champ vide dont le
                                         libelle dit « laisser vide pour conserver »
                                         n'a pas besoin de cette gymnastique. --}}
                                    @if ($plateforme === 'zabbix')
                                        <tr data-rw="superv-config-psk">
                                            <th scope="row">
                                                <label for="cfg-zabbix-psk">{{ __('superv.champ_psk_valeur') }}</label>
                                            </th>
                                            <td>
                                                <input class="rw-saisie" type="password"
                                                       id="cfg-zabbix-psk" name="tls_psk_value" value=""
                                                       autocomplete="new-password"
                                                       data-rw="superv-config-champ-tls_psk_value">
                                                <span class="rw-badge @if (! ($config->psk_pose ?? false)) rw-badge--neutre @endif">{{ ($config->psk_pose ?? false) ? __('superv.secret_pose') : __('superv.secret_absent') }}</span>
                                                <span class="rw-aide rw-cellule-note">{{ __('superv.secret_conserve') }}</span>
                                            </td>
                                        </tr>
                                    @endif
                                    @if ($plateforme === 'telegraf')
                                        <tr data-rw="superv-config-jeton">
                                            <th scope="row">{{ __('superv.champ_telegraf_jeton') }}</th>
                                            <td>
                                                <span class="rw-badge @if (! ($config->jeton_pose ?? false)) rw-badge--neutre @endif">{{ ($config->jeton_pose ?? false) ? __('superv.secret_pose') : __('superv.secret_absent') }}</span>
                                                {{-- LE JETON TELEGRAF N'EST PAS PORTE :
                                                     son ecriture vit dans une route a part
                                                     du backend, et l'inventer ici serait
                                                     concevoir. La page le DIT. --}}
                                                <span class="rw-aide rw-cellule-note">{{ __('superv.secret_jeton_non_porte') }}</span>
                                            </td>
                                        </tr>
                                    @endif
                                </tbody>
                            </table>
                        </div>

                        @if ($config !== null)
                            <p class="rw-aide rw-prose">{{ __('superv.config_plus_recente') }}</p>
                        @endif

                        {{-- Action principale a DROITE en pied de formulaire. --}}
                        <div class="rw-actions">
                            <p class="rw-aide rw-actions__gauche">{{ __('superv.enregistrement_portee', ['plateforme' => ucfirst($plateforme)]) }}</p>
                            <button type="submit" class="rw-bouton"
                                    data-rw="superv-config-enregistrer">{{ __('superv.enregistrer') }}</button>
                        </div>
                    </form>
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
