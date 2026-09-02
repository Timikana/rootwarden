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
{{-- ⚠ DEUX ANCRES, PARCE QUE DEUX ETATS OPPOSES ────────────────────────

                 La confirmation et l'erreur partageaient `superv-config-message`.
                 Les deux `@if` etant exclusifs, un seul `<p>` existe a la fois —
                 donc l'etat EST mesurable, mais l'ancre ne le DISCRIMINE pas :
                 une assertion sur « le geste a reussi » serait **verte sur un
                 echec**.

                 Ancres separees plutot qu'assertion sur la classe : *une suite
                 qui doit lire une classe de PRESENTATION pour connaitre un etat
                 METIER depend d'une decision de style*, et ce depot a paye trois
                 fois une classe renommee ou purgee. Le jour ou `rw-erreur`
                 change de nom, l'assertion passerait au vert sur un echec sans
                 que rien ne bouge dans la page. --}}
                        @if (session('superv_message'))
                <p class="rw-confirmation" data-rw="superv-config-succes"
                   role="status">{{ session('superv_message') }}</p>
            @elseif (session('superv_erreur'))
                <p class="rw-erreur" data-rw="superv-config-erreur"
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
            @if (session('superv_profil_message'))
                <p class="rw-confirmation" data-rw="superv-profil-succes"
                   role="status">{{ session('superv_profil_message') }}</p>
            @elseif (session('superv_profil_erreur'))
                <p class="rw-erreur" data-rw="superv-profil-erreur"
                   role="alert">{{ session('superv_profil_erreur') }}</p>
            @endif

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
                                            <th>{{ __('superv.profil_actions') }}</th>
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
                                                {{-- LES ACTIONS DE LA LIGNE.
                                                     « Modifier » est une ADRESSE :
                                                     le serveur pre-remplit le
                                                     formulaire. Le legacy, lui,
                                                     serialise le profil ENTIER dans
                                                     un attribut `onclick` — 671
                                                     caracteres mesures, `notes`
                                                     d'exploitation comprise. --}}
                                                <td class="rw-tableau__actions">
                                                    <a class="rw-bouton rw-bouton--discret"
                                                       href="{{ route('supervision', ['profil' => $profil->id]) }}#config-{{ $plateforme }}"
                                                       data-rw="superv-profil-modifier-{{ $profil->id }}">{{ __('superv.profil_modifier') }}</a>
                                                    <button type="button" class="rw-bouton rw-bouton--discret"
                                                            data-rw="superv-profil-supprimer-{{ $profil->id }}"
                                                            data-cible="profil-suppression-{{ $profil->id }}">{{ __('superv.profil_supprimer') }}</button>
                                                </td>
                                            </tr>
                                            {{-- LA DECISION SE PREND DANS LA PAGE,
                                                 sous la ligne concernee, et elle
                                                 NOMME son cout : le nombre de
                                                 machines qui perdront leur profil.
                                                 Le legacy le dit dans un `confirm()`
                                                 natif au texte francais en dur. --}}
                                            <tr id="profil-suppression-{{ $profil->id }}" hidden>
                                                <td colspan="6">
                                                    <form class="rw-panneau-decision" method="POST"
                                                          action="{{ route('supervision.profils.supprimer') }}">
                                                        @csrf
                                                        <input type="hidden" name="plateforme" value="{{ $plateforme }}">
                                                        <input type="hidden" name="id" value="{{ $profil->id }}">
                                                        <div class="rw-panneau-decision__texte">
                                                            <strong>{{ __('superv.profil_supprimer_titre', ['nom' => $profil->name]) }}</strong>
                                                            <p class="rw-aide">{{ __('superv.profil_supprimer_cout', ['machines' => $profil->machines]) }}</p>
                                                        </div>
                                                        <div class="rw-panneau-decision__actions">
                                                            <button type="button" class="rw-bouton rw-bouton--discret"
                                                                    data-rw="superv-profil-annuler-{{ $profil->id }}"
                                                                    data-cible="profil-suppression-{{ $profil->id }}">{{ __('superv.annuler') }}</button>
                                                            <button type="submit" class="rw-bouton rw-bouton--danger"
                                                                    data-rw="superv-profil-confirmer">{{ __('superv.profil_supprimer_confirmer') }}</button>
                                                        </div>
                                                    </form>
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
                            {{-- L'ASSIGNATION N'EST PAS PORTEE, et la colonne
                                 « Machines » ci-dessus le rend visible : elle
                                 compte des rattachements qu'on ne peut pas encore
                                 faire d'ici. Le taire laisserait chercher. --}}
                            {{-- Le tableau de deploiement EST porte : la
                                 subordonnee « qui n'est pas encore porte » de
                                 l'ancien libelle etait fausse. --}}
                            <p class="rw-aide rw-prose">{{ __('superv.profils_assignation_ailleurs') }}</p>
                        @endif
                    </div>
                @endforeach

                {{-- CREER OU MODIFIER. UN SEUL formulaire, et son contenu vient
                     du SERVEUR : `?profil=<id>` le pre-remplit. Pas de gabarit
                     JavaScript, donc pas d'enregistrement recopie dans le DOM. --}}
                {{-- LE FORMULAIRE EST UNE AUTRE SECTION QUE LE CATALOGUE, et ca
                     doit se voir : sans separateur, son titre se collait au dernier
                     paragraphe du tableau et les deux se lisaient d'un bloc.
                     Vu a l'image. --}}
                <form class="rw-note" method="POST" action="{{ route('supervision.profils.enregistrer') }}"
                      data-rw="superv-profil-form">
                    @csrf
                    <input type="hidden" name="plateforme" value="{{ $plateforme }}">
                    <input type="hidden" name="id" data-rw="superv-profil-champ-id"
                           value="{{ ($profilModifie && $profilModifie->platform === $plateforme) ? $profilModifie->id : '' }}">

                    <h4 class="rw-sous-titre">{{ ($profilModifie && $profilModifie->platform === $plateforme) ? __('superv.profil_titre_modifier', ['nom' => $profilModifie->name]) : __('superv.profil_titre_nouveau') }}</h4>

                    <div class="rw-tableau-cadre">
                        <table class="rw-tableau">
                            <tbody>
                                @foreach ($champsProfil as $colonne => $cle)
                                    <tr>
                                        <th scope="row">
                                            <label for="prof-{{ $plateforme }}-{{ $colonne }}">{{ __('superv.champ_' . $cle) }}</label>
                                        </th>
                                        <td>
                                            @if ($colonne === 'notes')
                                                <textarea class="rw-saisie" rows="3"
                                                          id="prof-{{ $plateforme }}-{{ $colonne }}"
                                                          name="{{ $colonne }}"
                                                          data-rw="superv-profil-champ-{{ $colonne }}">{{ ($profilModifie && $profilModifie->platform === $plateforme) ? $profilModifie->$colonne : '' }}</textarea>
                                            @else
                                                <input class="rw-saisie" type="text"
                                                       id="prof-{{ $plateforme }}-{{ $colonne }}"
                                                       name="{{ $colonne }}"
                                                       value="{{ ($profilModifie && $profilModifie->platform === $plateforme) ? $profilModifie->$colonne : '' }}"
                                                       data-rw="superv-profil-champ-{{ $colonne }}">
                                            @endif
                                        </td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>

                    <div class="rw-actions">
                        {{-- « Nouveau profil » vide le formulaire : c'est un LIEN
                             vers la page sans `?profil`, donc le serveur rend un
                             formulaire vierge. Aucun etat a remettre a zero en JS. --}}
                        <a class="rw-bouton rw-bouton--discret rw-actions__gauche"
                           href="{{ route('supervision') }}#config-{{ $plateforme }}"
                           data-rw="superv-profil-nouveau">{{ __('superv.profil_nouveau') }}</a>
                        <button type="submit" class="rw-bouton"
                                data-rw="superv-profil-enregistrer">{{ __('superv.enregistrer') }}</button>
                    </div>
                </form>
            </article>
        </div>

        {{-- ══ ONGLET 3 : deploiement ═══════════════════════════════════════
             SOUS-LOT V6 : le parc, ses agents releves, et la DETECTION DE
             VERSION — le premier geste du module qui ouvre une session SSH.

             CE QUI N'EST PAS ICI EST VOLONTAIRE. Deployer, reconfigurer et
             desinstaller (V10 a V12) modifient la machine ; le scan du parc
             entier (V8) lance quatre requetes par serveur et doit etre reconcu
             en tache de fond. Aucun de ces boutons n'existe donc encore, et la
             page le DIT — un bouton present mais inerte serait pire qu'absent.

             LA DETECTION PASSE PAR LA PASSERELLE, et c'est l'exception declaree
             du module : c'est le backend qui ouvre le SSH, comme pour K2/K3/K4.
             Il n'y a AUCUNE case a cocher : chaque ligne porte son propre
             bouton. Une selection multiple appellerait le scan du parc par la
             porte de V6, et surtout « tout cocher » embarquerait srv-zabbix,
             qui est en PRODUCTION. --}}
        @php($plateformeInitiale = $plateformes[0] ?? 'zabbix')
        {{-- Les profils par plateforme et les rattachements en vigueur. `@json`
             ne recoit qu'une VARIABLE : son analyseur d'argument ne franchit pas
             une expression composee, et un gabarit entier tombe en erreur de
             syntaxe pour une expression pourtant sur une ligne. --}}
        <script id="superv-profils-donnees" type="application/json">@json($profils)</script>
        <script id="superv-assignations-donnees" type="application/json">@json($assignations)</script>
        <div id="panneau-deploy" data-rw="panneau-deploy" role="tabpanel" hidden>
            <article class="rw-carte rw-carte--pleine">
                <h3 class="rw-sous-titre">{{ __('superv.deploiement_titre') }}</h3>
                <p class="rw-aide rw-prose">{{ __('superv.deploiement_description') }}</p>

                @if (count($machines) === 0)
                    <div class="rw-vide">
                        <p class="rw-vide__titre">{{ __('superv.aucune_machine') }}</p>
                        <p class="rw-vide__texte rw-prose">{{ __('superv.aucune_machine_aide') }}</p>
                    </div>
                @else
                    <div class="rw-tableau-cadre">
                        <table class="rw-tableau">
                            <thead>
                                <tr>
                                    <th>{{ __('superv.machine_nom') }}</th>
                                    <th>{{ __('superv.machine_adresse') }}</th>
                                    <th>{{ __('superv.machine_environnement') }}</th>
                                    <th>{{ __('superv.machine_agents') }}</th>
                                    {{-- V13 : LE DEBOUCHE DU CATALOGUE DE PROFILS.
                                         Il etait porte et fonctionnel ; cette colonne
                                         manquait, donc un profil cree ne pouvait etre
                                         porte par aucune machine. --}}
                                    <th>{{ __('superv.profil_colonne') }}</th>
                                    <th>{{ __('superv.profil_actions') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach ($machines as $m)
                                    @php($sesAgents = $agents[(int) $m->id] ?? [])
                                    <tr data-rw="superv-machine-{{ $m->id }}">
                                        <td><strong>{{ $m->name }}</strong></td>
                                        <td><code>{{ $m->ip }}:{{ $m->port }}</code></td>
                                        <td>{{ $m->environment ?: __('superv.champ_vide') }}</td>
                                        {{-- L'INVENTAIRE DIT CE QU'IL SAIT, ET
                                             DEPUIS QUAND IL NE SAIT RIEN. Une
                                             absence d'agent est un CONSTAT :
                                             une detection qui ne trouve rien
                                             supprime la ligne. --}}
                                        <td data-rw="superv-agents-{{ $m->id }}">
                                            @if (count($sesAgents) === 0)
                                                <span class="rw-badge rw-badge--neutre">{{ __('superv.agent_aucun') }}</span>
                                            @else
                                                @foreach ($sesAgents as $plateforme => $version)
                                                    <span class="rw-badge">{{ ucfirst($plateforme) }} {{ $version !== '' ? $version : '?' }}</span>
                                                @endforeach
                                            @endif
                                        </td>
                                        {{-- LE SELECTEUR DE PROFIL — une liste
                                             FERMEE, remplie par le script depuis
                                             les donnees du serveur, et re-remplie
                                             quand la plateforme change : une
                                             machine porte UN profil PAR
                                             PLATEFORME.

                                             « Aucun profil » est une valeur
                                             offerte, pas un vide : la retirer se
                                             fait par `DELETE`, et c'est un geste
                                             que l'exploitant doit pouvoir poser
                                             sans supprimer le profil lui-meme. --}}
                                        <td>
                                            <select class="rw-saisie rw-saisie--compacte"
                                                    data-rw="superv-affectation-{{ $m->id }}"
                                                    data-machine="{{ $m->id }}"
                                                    aria-label="{{ __('superv.profil_colonne') }}"></select>
                                        </td>
                                        <td class="rw-tableau__actions">
                                            <button type="button" class="rw-bouton rw-bouton--discret"
                                                    data-rw="superv-detecter-version"
                                                    data-machine="{{ $m->id }}"
                                                    data-nom="{{ $m->name }}">{{ __('superv.version_detecter') }}</button>
                                            {{-- LES REGLAGES SONT UNE ADRESSE, pas un
                                                 enregistrement pose dans le DOM : le serveur
                                                 pre-remplit le formulaire depuis `?reglages=<id>`.
                                                 Meme principe qu'en V5 pour les profils. --}}
                                            <a class="rw-bouton rw-bouton--discret"
                                               data-rw="superv-reglages-lien-{{ $m->id }}"
                                               href="{{ route('supervision', ['reglages' => $m->id]) }}#reglages">{{ __('superv.reglages_lien') }}</a>
                                            {{-- SOUS-LOT V10 : la reconfiguration, PAR LIGNE.
                                                 Le legacy l'offre aussi « sur la selection », et
                                                 SANS AUCUNE confirmation — la ou `deploy` et
                                                 `uninstall` ouvrent au moins un `confirm()`. Ici
                                                 pas de case a cocher (V6), donc pas d'action de
                                                 masse : une ligne, une machine, un panneau. --}}
                                            {{-- UNE REGLE APPLIQUEE PAR LE BACKEND SE REND
                                                 VISIBLE. `zabbix_reconfigure` refuse (400) tant
                                                 qu'aucune configuration globale n'existe. Un
                                                 bouton cliquable pour se faire refuser fait
                                                 decider dans le vide : il est DESACTIVE, avec
                                                 l'explication en infobulle. --}}
                                            <button type="button" class="rw-bouton rw-bouton--discret"
                                                    data-rw="superv-reconfigurer"
                                                    data-machine="{{ $m->id }}"
                                                    data-nom="{{ $m->name }}"
                                                    @disabled(($configuration['zabbix'] ?? null) === null)
                                                    @if (($configuration['zabbix'] ?? null) === null) title="{{ __('superv.reconf_sans_config') }}" @endif
                                                    >{{ __('superv.reconf_bouton') }}</button>
                                            {{-- SOUS-LOT V11 : LE GESTE QUI DETRUIT.
                                                 Par ligne, comme les autres (aucune case a
                                                 cocher — V6). Cote legacy c'est un `confirm()`
                                                 natif qui affiche la chaine `confirm_uninstall`,
                                                 la cle etant absente de `js.php` : on demande
                                                 donc de confirmer une DESTRUCTION avec un
                                                 identifiant a l'ecran. Remplace ici par un
                                                 panneau, pas deplace. --}}
                                            <button type="button" class="rw-bouton rw-bouton--discret"
                                                    data-rw="superv-desinstaller"
                                                    data-machine="{{ $m->id }}"
                                                    data-nom="{{ $m->name }}"
                                                    {{-- L'ENVIRONNEMENT VOYAGE AVEC LE GESTE. Vu a
                                                         l'image : le panneau nommait la machine sans
                                                         dire qu'elle etait en PRODUCTION. V8 avait
                                                         etabli qu'on NOMME la production plutot que
                                                         de la compter ; c'est sur le geste qui
                                                         DETRUIT que ca compte le plus. --}}
                                                    data-environnement="{{ strtoupper((string) ($m->environment ?? '')) }}"
                                                    >{{ __('superv.desinst_bouton') }}</button>
                                            {{-- SOUS-LOT V12 : LE DEPLOIEMENT.
                                                 Par ligne, comme tout le reste. Le legacy
                                                 l'offre AUSSI sur la selection (case a cocher
                                                 + « Deployer la selection »), derriere un
                                                 `confirm()` natif qui affiche la chaine
                                                 `confirm_deploy`. Cette traduction EXISTE
                                                 pourtant, en FR et en EN — dans
                                                 `lang/*/supervision.php`, donc hors de
                                                 l'espace `js.` que `getJsTranslations('js.')`
                                                 charge. Elle est ecrite, correcte, et
                                                 inaccessible.

                                                 L'ETAT DESACTIVE SUIT LA PLATEFORME, il n'est
                                                 pas fige sur Zabbix : `zabbix_deploy` refuse
                                                 (400) sans configuration globale, mais
                                                 `generic_deploy` installe quand meme. Un
                                                 bouton grise pour la mauvaise raison est un
                                                 mensonge de plus. --}}
                                            <button type="button" class="rw-bouton rw-bouton--discret"
                                                    data-rw="superv-deployer"
                                                    data-machine="{{ $m->id }}"
                                                    data-nom="{{ $m->name }}"
                                                    data-environnement="{{ strtoupper((string) ($m->environment ?? '')) }}"
                                                    {{-- `refuse_sans_config` DECRIT LE BACKEND (Zabbix refuse
                                                         sans configuration globale) ; il ne dit pas si le bouton
                                                         doit etre grise ICI. Les confondre desactivait le bouton
                                                         Zabbix EN PERMANENCE, meme configuration posee. L'etat
                                                         bloque est la conjonction des deux : le backend refuserait,
                                                         ET la configuration manque. --}}
                                                    @disabled($boutonsBloques['deploiement'][$plateformeInitiale] ?? false)
                                                    @if ($boutonsBloques['deploiement'][$plateformeInitiale] ?? false) title="{{ __('superv.depl_sans_config') }}" @endif
                                                    >{{ __('superv.depl_bouton') }}</button>
                                        </td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>
                    {{-- LE VERDICT S'ECRIT DANS LA PAGE ET Y RESTE. Le legacy le
                         passe a un `toast()` qui s'efface au bout de 4 s, alors
                         qu'une session SSH en demande le double : le message a
                         disparu avant que son effet soit constatable. --}}
                    <p class="rw-annonce" data-rw="superv-version-message" aria-live="polite"></p>

                    {{-- ══ SOUS-LOT V11 : LA DESINSTALLATION ═════════════════
                         LE SOUS-LOT QUI DETRUIT. Le panneau NOMME ce qui part :
                         le paquet purge, sa configuration, et la ligne
                         d'inventaire. « Nommer, pas compter » vaut d'autant plus
                         ici que rien ne se rattrape.

                         ET LE PORTAGE VERIFIE APRES COUP. Le backend ne peut plus
                         mentir depuis v1.37.44, mais il ne peut pas tout
                         garantir : « rien a purger » n'est pas « desinstalle ».
                         Le portage rejoue donc la detection de version une fois
                         le geste fini, et dit ce qu'elle TROUVE. Une reussite
                         mesuree vaut mieux qu'une reussite annoncee. --}}
                    <section class="rw-note" data-rw="superv-desinst">
                        <h4 class="rw-sous-titre">{{ __('superv.desinst_titre') }}</h4>
                        <p class="rw-aide rw-prose">{{ __('superv.desinst_description') }}</p>

                        <div class="rw-panneau-decision" data-rw="superv-panneau-desinst" hidden>
                            <div class="rw-panneau-decision__texte">
                                <p class="rw-erreur" data-rw="superv-desinst-cout"></p>
                                <p class="rw-avertissement" data-rw="superv-desinst-prod" hidden></p>
                                <ul class="rw-aide rw-prose rw-liste-effets" data-rw="superv-desinst-effets">
                                    <li>{{ __('superv.desinst_effet_service') }}</li>
                                    <li>{{ __('superv.desinst_effet_purge') }}</li>
                                    <li>{{ __('superv.desinst_effet_inventaire') }}</li>
                                </ul>
                                <p class="rw-aide rw-prose">{{ __('superv.desinst_aide_verif') }}</p>
                            </div>
                            <div class="rw-panneau-decision__actions">
                                <button type="button" class="rw-bouton rw-bouton--discret"
                                        data-rw="superv-desinst-annuler">{{ __('superv.desinst_annuler') }}</button>
                                <button type="button" class="rw-bouton rw-bouton--danger"
                                        data-rw="superv-desinst-confirmer">{{ __('superv.desinst_confirmer') }}</button>
                            </div>
                        </div>

                        <p class="rw-annonce" data-rw="superv-desinst-message" aria-live="polite"></p>
                        {{-- LA VERIFICATION EST DITE A PART DU VERDICT DE LA COMMANDE :
                             l'une rapporte ce que la commande a rendu, l'autre ce
                             qu'on a CONSTATE ensuite. Les confondre ferait croire
                             que le succes annonce vaut preuve. --}}
                        <p class="rw-annonce" data-rw="superv-desinst-verif" aria-live="polite"></p>
                        <pre class="rw-journal" data-rw="superv-desinst-journal" hidden></pre>
                    </section>

                    {{-- ══ SOUS-LOT V12 : LE DEPLOIEMENT ═════════════════════
                         LE GESTE QUI INSTALLE, ET QUI COMMENCE PAR DETRUIRE.
                         Mesure du backend : `zabbix_deploy` PURGE les agents en
                         place avant d'installer, renomme la configuration en
                         `.old` et telecharge un `.deb` sur repo.zabbix.com. Rien
                         de tout cela ne se devine du mot « deployer », donc les
                         etapes sont enumerees — et enumerees PAR PLATEFORME,
                         parce qu'elles different vraiment.

                         ET LE FLUX MENT. Releve sur le banc d'essai :

                             Exécution terminée (code 127).   <- wget absent
                             Exécution terminée (code 100).   <- paquet introuvable
                             Exécution terminée (code 127).   <- systemctl absent
                             SUCCESS_MACHINE::2::Deploiement reussi ...

                         Trois echecs, et le marqueur conclut a la reussite. Pire
                         qu'en V10 : `_upsert_agent` a AUSSI inscrit l'agent dans
                         l'inventaire. Le portail affirmait donc un agent installe
                         la ou la machine n'en portait aucun.

                         D'OU LA VERIFICATION APRES COUP, qui prend ici tout son
                         sens : elle rejoue la detection de version et confronte
                         ce qu'elle trouve a ce que l'inventaire vient d'ecrire.
                         Quand elle ne trouve rien, elle le dit — et elle dit que
                         c'est l'inventaire qui a tort. --}}
                    <section class="rw-note" data-rw="superv-depl">
                        <h4 class="rw-sous-titre">{{ __('superv.depl_titre') }}</h4>
                        <p class="rw-aide rw-prose">{{ __('superv.depl_description') }}</p>

                        {{-- UNE REGLE APPLIQUEE PAR LE BACKEND SE REND VISIBLE, et
                             elle n'est pas la meme partout : Zabbix REFUSE sans
                             configuration globale (400, mesure a 513 ms), les trois
                             autres installent quand meme sans rien configurer. Deux
                             annonces distinctes, une par cas, basculees avec le
                             selecteur comme les autres blocs par plateforme. --}}
                        @foreach ($plateformes as $plateforme)
                            @php($cfg = $configuration[$plateforme] ?? null)
                            <div id="depl-{{ $plateforme }}" @unless($plateforme === $plateformeInitiale) hidden @endunless>
                                @if ($cfg === null && ($deploiement[$plateforme]['refuse_sans_config'] ?? false))
                                    <div class="rw-vide" data-rw="superv-depl-indisponible">
                                        <p class="rw-vide__titre">{{ __('superv.depl_sans_config') }}</p>
                                        <p class="rw-vide__texte rw-prose">{{ __('superv.depl_sans_config_aide') }}</p>
                                    </div>
                                @elseif ($cfg === null)
                                    <p class="rw-avertissement" data-rw="superv-depl-sans-config-generique">{{ __('superv.depl_sans_config_generique') }}</p>
                                @endif
                            </div>
                        @endforeach

                        <div class="rw-panneau-decision" data-rw="superv-panneau-depl" hidden>
                            <div class="rw-panneau-decision__texte">
                                {{-- DEUX POIDS VISUELS, PAS UN. Vu a l'image : l'enonce
                                     du geste et l'avertissement de PRODUCTION portaient la
                                     meme classe, donc le meme fond et la meme bordure. Sur
                                     le geste le plus dangereux du module, rien ne
                                     distinguait « voici ce qui va se passer » de « ce
                                     serveur est en production ». L'enonce devient un encart
                                     neutre ; seul l'avertissement attire l'oeil. --}}
                                <p class="rw-encart" data-rw="superv-depl-cout"></p>
                                <p class="rw-avertissement" data-rw="superv-depl-prod" hidden></p>
                                {{-- LES ETAPES VIENNENT DU SERVEUR, UNE LISTE PAR
                                     PLATEFORME. Pas de gabarit cote script : un
                                     libelle assemble en JS echappe a la parite
                                     FR/EN, et une liste unique afficherait les
                                     etapes de Zabbix pour Telegraf. --}}
                                @foreach ($plateformes as $plateforme)
                                    <ul id="depl-etapes-{{ $plateforme }}"
                                        class="rw-aide rw-prose rw-liste-effets"
                                        data-rw="superv-depl-etapes-{{ $plateforme }}"
                                        @unless($plateforme === $plateformeInitiale) hidden @endunless>
                                        @foreach ($deploiement[$plateforme]['etapes'] ?? [] as $etape)
                                            <li>{{ $etape }}</li>
                                        @endforeach
                                    </ul>
                                @endforeach
                            </div>
                            <div class="rw-panneau-decision__actions">
                                <button type="button" class="rw-bouton rw-bouton--discret"
                                        data-rw="superv-depl-annuler">{{ __('superv.depl_annuler') }}</button>
                                <button type="button" class="rw-bouton rw-bouton--danger"
                                        data-rw="superv-depl-confirmer">{{ __('superv.depl_confirmer') }}</button>
                            </div>
                        </div>

                        <p class="rw-annonce" data-rw="superv-depl-message" aria-live="polite"></p>
                        {{-- DEUX PORTE-MESSAGES DISTINCTS : « la commande a rendu »
                             et « j'ai constate » ne sont pas la meme affirmation.
                             Les confondre ferait passer le succes annonce pour une
                             preuve — c'est precisement ce que fait le legacy. --}}
                        <p class="rw-annonce" data-rw="superv-depl-verif" aria-live="polite"></p>
                        <pre class="rw-journal" data-rw="superv-depl-journal" hidden></pre>
                    </section>

                    {{-- ══ SOUS-LOT V10 : LA RECONFIGURATION ═════════════════
                         QUATRE EFFETS, PAS TROIS — et le decoupage n'en annoncait
                         que trois. La mesure (PARITE E-85) en a trouve un
                         quatrieme : si la configuration globale porte un PSK, la
                         route ECRIT UNE CLE SECRETE sur la machine. Les enumerer
                         est la seule facon de ne pas faire passer « reconfigurer »
                         pour un geste anodin.

                         ET L'ECRITURE FUSIONNE, ELLE NE REMPLACE PAS : la route
                         procede CLE PAR CLE (purge au `sed` puis ajout), donc les
                         lignes qu'elle ne connait pas SURVIVENT — a l'inverse de
                         l'editeur (V9) qui tronque le fichier. Deux gestes
                         voisins, deux semantiques opposees : le dire evite de
                         croire que l'un remplace l'autre. --}}
                    <section class="rw-note" data-rw="superv-reconf">
                        <h4 class="rw-sous-titre">{{ __('superv.reconf_titre') }}</h4>
                        <p class="rw-aide rw-prose">{{ __('superv.reconf_description') }}</p>

                        @php($configZabbix = $configuration['zabbix'] ?? null)
                        @if ($configZabbix === null)
                            {{-- UNE REGLE APPLIQUEE PAR LE BACKEND SE REND VISIBLE.
                                 `zabbix_reconfigure` commence par refuser (400
                                 « Aucune configuration globale ») quand la table est
                                 vide. Laisser cliquer pour se faire refuser fait
                                 decider dans le vide : on le dit AVANT. --}}
                            <div class="rw-vide" data-rw="superv-reconf-indisponible">
                                <p class="rw-vide__titre">{{ __('superv.reconf_sans_config') }}</p>
                                <p class="rw-vide__texte rw-prose">{{ __('superv.reconf_sans_config_aide') }}</p>
                            </div>
                        @endif

                        <div class="rw-panneau-decision" data-rw="superv-panneau-reconf" hidden>
                            <div class="rw-panneau-decision__texte">
                                <p class="rw-avertissement" data-rw="superv-reconf-cout"></p>
                                <ul class="rw-aide rw-prose rw-liste-effets" data-rw="superv-reconf-effets">
                                    <li>{{ __('superv.reconf_effet_sauvegarde') }}</li>
                                    <li data-rw="superv-reconf-effet-fusion">{{ __('superv.reconf_effet_fusion', ['chemin' => $cheminsConfig['zabbix'] ?? '']) }}</li>
                                    <li data-rw="superv-reconf-effet-psk" @unless($configZabbix?->psk_pose) hidden @endunless>{{ __('superv.reconf_effet_psk') }}</li>
                                    <li>{{ __('superv.reconf_effet_redemarrage') }}</li>
                                </ul>
                            </div>
                            <div class="rw-panneau-decision__actions">
                                <button type="button" class="rw-bouton rw-bouton--discret"
                                        data-rw="superv-reconf-annuler">{{ __('superv.reconf_annuler') }}</button>
                                <button type="button" class="rw-bouton rw-bouton--danger"
                                        data-rw="superv-reconf-confirmer">{{ __('superv.reconf_confirmer') }}</button>
                            </div>
                        </div>

                        <p class="rw-annonce" data-rw="superv-reconf-message" aria-live="polite"></p>

                        {{-- LE FLUX EST MONTRE, PAS RESUME. Le verdict du portage
                             vient de ce que le flux a MONTRE, pas de son dernier
                             marqueur — qui annonce `SUCCESS_MACHINE::` deux lignes
                             apres un `code 127`. Donner aussi le journal permet de
                             verifier ce verdict au lieu de le croire. --}}
                        <pre class="rw-journal" data-rw="superv-reconf-journal" hidden></pre>
                    </section>

                    {{-- ══ SOUS-LOT V10a : LES REGLAGES PAR MACHINE ══════════
                         POURQUOI CE FORMULAIRE N'A PAS DE CHAMP DE NOM. La table
                         `supervision_overrides` est libre, et le backend injecte
                         tout nom qu'il ne connait pas directement dans le fichier
                         de configuration. C'est par cette porte qu'un saut de
                         ligne dans la VALEUR produisait une directive autonome —
                         sur un agent Zabbix, un `UserParameter`, donc l'execution
                         d'une commande arbitraire (PARITE E-85, corrige en
                         v1.37.41). Ici les huit champs sont ceux que le backend
                         traite PAR LEUR NOM, et il n'y a pas de neuvieme : la
                         seule facon de ne pas rouvrir cette porte est de ne pas
                         l'installer.

                         ET CE GESTE NE JOINT AUCUNE MACHINE. Ces reglages vivent
                         en base et ne prennent effet qu'a la prochaine
                         reconfiguration : la page le DIT, plutot que de laisser
                         croire qu'enregistrer modifie le serveur. --}}
                    <section class="rw-note" id="reglages" data-rw="superv-reglages">
                        <h4 class="rw-sous-titre">{{ __('superv.reglages_titre') }}</h4>
                        <p class="rw-aide rw-prose">{{ __('superv.reglages_description') }}</p>

                        @if (session('superv_reglages_message'))
                            <p class="rw-confirmation" data-rw="superv-reglages-succes"
                               role="status">{{ session('superv_reglages_message') }}</p>
                        @elseif (session('superv_reglages_erreur'))
                            <p class="rw-erreur" data-rw="superv-reglages-erreur"
                               role="alert">{{ session('superv_reglages_erreur') }}</p>
                        @endif

                        @if ($machineReglee === null)
                            <div class="rw-vide">
                                <p class="rw-vide__titre">{{ __('superv.reglages_aucune_machine') }}</p>
                                <p class="rw-vide__texte rw-prose">{{ __('superv.reglages_aucune_machine_aide') }}</p>
                            </div>
                        @else
                            <p class="rw-encart" data-rw="superv-reglages-machine">
                                {{ __('superv.reglages_pour', ['nom' => $machineReglee->name]) }}
                            </p>
                            <p class="rw-avertissement" data-rw="superv-reglages-effet">
                                {{ __('superv.reglages_effet_differe') }}
                            </p>

                            <form method="POST" action="{{ route('supervision.reglages.enregistrer') }}"
                                  data-rw="superv-reglages-form">
                                @csrf
                                <input type="hidden" name="machine_id" value="{{ $machineReglee->id }}">

                                <div class="rw-grille">
                                    @foreach ($champsOverride as $nom => $champ)
                                        @php($valeur = $overrides[$nom] ?? '')
                                        <label class="rw-etiquette-champ">
                                            <span class="rw-etiquette">{{ __('superv.' . $champ['cle']) }}</span>
                                            @if ($champ['nature'] === 'liste')
                                                {{-- LISTE FERMEE, revalidee cote serveur : un
                                                     champ libre par-dessus une valeur attendue
                                                     dans un jeu fini est un defaut deja paye en V4. --}}
                                                <select class="rw-saisie" name="override_{{ $nom }}"
                                                        data-rw="superv-reglage-{{ $nom }}">
                                                    <option value="">{{ __('superv.reglages_herite') }}</option>
                                                    @foreach ($choix[$champ['colonne']] ?? [] as $option)
                                                        <option value="{{ $option }}" @selected($valeur === $option)>{{ $option }}</option>
                                                    @endforeach
                                                </select>
                                            @else
                                                <input class="rw-saisie" type="text"
                                                       name="override_{{ $nom }}"
                                                       value="{{ $valeur }}"
                                                       data-rw="superv-reglage-{{ $nom }}"
                                                       placeholder="{{ __('superv.reglages_herite') }}"
                                                       @if ($champ['nature'] === 'port') inputmode="numeric" @endif>
                                            @endif
                                            <span class="rw-aide">{{ __('superv.' . $champ['cle'] . '_aide') }}</span>
                                        </label>
                                    @endforeach
                                </div>

                                <div class="rw-actions">
                                    <a class="rw-bouton rw-bouton--discret rw-actions__gauche"
                                       href="{{ route('supervision') }}#reglages"
                                       data-rw="superv-reglages-fermer">{{ __('superv.reglages_fermer') }}</a>
                                    <button type="submit" class="rw-bouton"
                                            data-rw="superv-reglages-enregistrer">{{ __('superv.reglages_enregistrer') }}</button>
                                </div>
                            </form>

                            {{-- UN CHAMP VIDE EFFACE LE REGLAGE, et il faut le dire :
                                 un `param_value` vide serait relu comme une ligne
                                 `Cle=` — une directive sans valeur. --}}
                            <p class="rw-aide rw-prose">{{ __('superv.reglages_vide_efface') }}</p>

                            @if (count(array_diff_key($overrides, $champsOverride)) > 0)
                                {{-- ON N'AFFICHE PAS SEULEMENT CE QU'ON SAIT ECRIRE.
                                     Un reglage pose hors de la liste fermee — par
                                     l'API, ou avant ce portage — existe et agit :
                                     le cacher laisserait croire qu'il n'y en a pas. --}}
                                <p class="rw-avertissement" data-rw="superv-reglages-hors-liste">
                                    {{ __('superv.reglages_hors_liste', [
                                        'champs' => implode(', ', array_keys(array_diff_key($overrides, $champsOverride))),
                                    ]) }}
                                </p>
                            @endif
                        @endif
                    </section>

                    {{-- ══ SOUS-LOT V8 : le releve du parc, en tache de fond ══
                         CE QUE LE LEGACY NE DIT PAS, ET QUE CE BLOC DIT.
                         « Scanner tous les agents » y boucle sur toutes les lignes
                         du tableau x quatre plateformes et lance TOUT en parallele.
                         Mesure : le filtre de la table ne borne PAS ce releve —
                         filtre sur un nom, une ligne visible, trois machines
                         jointes, dont la production. Ici le cout est enonce AVANT
                         le geste, par le SERVEUR, et la production est NOMMEE.

                         LE BOUTON N'ENVOIE RIEN. Il ouvre un panneau de decision :
                         pas de `confirm()` natif, qui recouvre precisement la ligne
                         sur laquelle on decide, ne se style pas, et bloque le test
                         au point de l'empecher de mener l'action au bout. --}}
                    <section class="rw-note" data-rw="superv-releve-bloc">
                        <h4 class="rw-sous-titre">{{ __('superv.releve_titre') }}</h4>
                        <p class="rw-aide rw-prose">{{ __('superv.releve_description') }}</p>

                        {{-- LE BOUTON RESTE AVEC SA PHRASE. La convention « action
                             principale a droite » vaut pour un PIED DE FORMULAIRE,
                             ou l'oeil descend une colonne de champs. Ici c'est une
                             action unique attachee a une explication : vu a l'image
                             sur 1920 px, la version alignee a droite laissait plus
                             de mille pixels vides entre le texte et le bouton, et la
                             chaine explication -> geste se rompait. --}}
                        <div class="rw-actions">
                            <div class="rw-actions__gauche">
                                <button type="button" class="rw-bouton"
                                        data-rw="superv-relever-parc">{{ __('superv.releve_bouton') }}</button>
                            </div>
                        </div>

                        <div class="rw-panneau-decision" data-rw="superv-panneau-releve" hidden>
                            <div class="rw-panneau-decision__texte">
                                {{-- LE COUT, CHIFFRE. Trois nombres, tous venus du
                                     serveur : machines, plateformes, sessions SSH.
                                     Une session par machine et non une par
                                     plateforme — c'est ce que la tache de fond
                                     permet, et c'est mesure au journal paramiko. --}}
                                {{-- NEUTRE, PAS VERT. Un premier jet rendait ce
                                     chiffrage en `rw-confirmation`, donc en vert
                                     de reussite, dans un panneau a bordure rouge :
                                     vu a l'image, l'incoherence saute — le vert
                                     invite a cliquer alors que la phrase enonce un
                                     COUT. Aucune assertion DOM ne voit ca. --}}
                                <p class="rw-encart" data-rw="superv-releve-cout">
                                    {{ __('superv.releve_cout', [
                                        'machines' => $coutReleve['machines'],
                                        'plateformes' => $coutReleve['plateformes'],
                                        'sessions' => $coutReleve['sessions'],
                                    ]) }}
                                </p>
                                @if (count($coutReleve['production']) > 0)
                                    {{-- NOMMER LA PRODUCTION, PAS LA COMPTER.
                                         « 3 machines » ne previent personne ;
                                         « dont srv-zabbix (PROD) » previent. --}}
                                    <p class="rw-avertissement" data-rw="superv-releve-production">
                                        {{ __('superv.releve_production', [
                                            'machines' => implode(', ', $coutReleve['production']),
                                        ]) }}
                                    </p>
                                @endif
                                <p class="rw-aide rw-prose">{{ __('superv.releve_aide_fond') }}</p>
                            </div>
                            <div class="rw-panneau-decision__actions">
                                <button type="button" class="rw-bouton rw-bouton--discret"
                                        data-rw="superv-releve-annuler">{{ __('superv.releve_annuler') }}</button>
                                <button type="button" class="rw-bouton"
                                        data-rw="superv-releve-confirmer">{{ __('superv.releve_confirmer') }}</button>
                            </div>
                        </div>

                        <p class="rw-annonce" data-rw="superv-releve-message" aria-live="polite"></p>
                    </section>
                @endif

                {{--
                    ══ CE BLOC DISAIT QUE TROIS GESTES N'ETAIENT PAS PORTES ═════

                    Il annoncait « Installer, reconfigurer et desinstaller un
                    agent … restent sur l'ancien portail », avec un lien vers le
                    legacy — et il s'affichait a l'ouverture de l'onglet
                    « deploiement », c'est-a-dire au moment ou il etait le plus
                    faux.

                    RETIRE. Les trois gestes sont cables, et c'est mesure par
                    une enumeration OUVERTE — non par une recherche de nom :

                        ce que supervision.js nomme comme route :
                          deploiement · desinstallation · ecriture · lecture ·
                          reconfiguration · restauration · sauvegardes · version
                        ce que SupervisionController construit en URL : les memes

                    ⚠ Et la recherche par nom ANGLAIS ratait : `uninstall` rend
                    ZERO dans ce fichier, `desinstallation` en rend cinq. Le
                    portage nomme en francais.

                    ── POURQUOI IL A SURVECU DIX JOURS ──────────────────────

                    V1 (`c1041f4`, 22/08 03:25) a ecrit la phrase — elle etait
                    VRAIE. V12 (`3e8686a`, 23/08 13:05) a porte le deploiement,
                    et son diff ne touche PAS cette cle.

                    **Une declaration vraie devient fausse sans que personne ne
                    la touche** : il n'y a aucun commit a incriminer, et la
                    relecture du diff qui l'a rendue fausse ne la contient pas.
                    Trois lignes au-dessus, son propre auteur avait ecrit
                    « UN TEXTE PEUT DEVENIR FAUX SANS QU'AUCUN TEST NE LE
                    VOIE » — un avertissement ne protege pas le texte qu'il
                    precede.
                --}}
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
                    <p class="rw-annonce" data-rw="superv-editeur-message" aria-live="polite"></p>

                    {{-- LE CHEMIN VIENT DU SERVEUR, ET DE LA MEME SOURCE QUE CELLE
                         QUE LE BACKEND LIRA (`agent_type` en base). Le legacy
                         affiche un chemin ECRIT EN DUR cote client : des que la
                         configuration globale designe l'agent historique, sa page
                         nomme `zabbix_agent2.conf` alors que le portail lit
                         `zabbix_agentd.conf` — mesure faite, voir PARITE E-79. --}}
                    <p class="rw-aide rw-note">
                        <span data-rw="superv-editeur-chemin-etiquette">{{ __('superv.editeur_chemin') }}</span>
                        {{-- LE PANNEAU DE L'EDITEUR N'EST PAS DANS LA BOUCLE DES
                             PLATEFORMES : y ecrire `$plateforme` reprenait la
                             DERNIERE valeur laissee par le `@foreach` — donc
                             Telegraf — et l'editeur annoncait le chemin d'une
                             plateforme qu'on n'avait pas choisie. Blade laisse
                             fuiter la variable sans broncher. Le chemin part donc
                             de Zabbix, plateforme par defaut, et le script le suit
                             au changement. --}}
                        <code data-rw="superv-editeur-chemin">{{ $cheminsConfig['zabbix'] ?? '' }}</code>
                    </p>

                    {{-- MODIFIABLE DEPUIS V9. V7 laissait ce champ en lecture
                         seule parce que l'enregistrement n'existait pas : un champ
                         editable sans enregistrement laisse croire qu'on peut
                         editer. --}}
                    <label class="rw-etiquette-champ">
                        <span class="rw-etiquette">{{ __('superv.editeur_contenu') }}</span>
                        <textarea class="rw-saisie" rows="16"
                                  data-rw="superv-editeur-contenu"
                                  placeholder="{{ __('superv.editeur_vide') }}"></textarea>
                    </label>

                    {{-- ══ SOUS-LOT V9 : L'ECRITURE ═══════════════════════════
                         LE COUT S'ENONCE AVANT LE GESTE, et il est ENUMERE : le
                         chemin exact ecrit, la sauvegarde creee avant, et le
                         service redemarre apres. Le legacy n'annonce rien du tout
                         et n'a aucune confirmation.

                         L'action principale est a DROITE : ici c'est bien un pied
                         de formulaire — l'oeil descend la zone d'edition puis
                         trouve le bouton. --}}
                    <div class="rw-actions">
                        <button type="button" class="rw-bouton"
                                data-rw="superv-sauver">{{ __('superv.editeur_sauver') }}</button>
                    </div>

                    <div class="rw-panneau-decision" data-rw="superv-panneau-sauver" hidden>
                        <div class="rw-panneau-decision__texte">
                            <p class="rw-encart" data-rw="superv-sauver-cout">
                                {{ __('superv.editeur_sauver_cout', ['chemin' => $cheminsConfig['zabbix'] ?? '']) }}
                            </p>
                            {{-- TROIS EFFETS, ENUMERES. Une phrase qui dit
                                 « enregistrer » cache qu'on redemarre un service. --}}
                            <ul class="rw-aide rw-prose rw-liste-effets" data-rw="superv-sauver-effets">
                                <li>{{ __('superv.editeur_effet_sauvegarde') }}</li>
                                <li>{{ __('superv.editeur_effet_ecriture') }}</li>
                                <li>{{ __('superv.editeur_effet_redemarrage') }}</li>
                            </ul>
                        </div>
                        <div class="rw-panneau-decision__actions">
                            <button type="button" class="rw-bouton rw-bouton--discret"
                                    data-rw="superv-sauver-annuler">{{ __('superv.editeur_sauver_annuler') }}</button>
                            <button type="button" class="rw-bouton rw-bouton--danger"
                                    data-rw="superv-sauver-confirmer">{{ __('superv.editeur_sauver_confirmer') }}</button>
                        </div>
                    </div>

                    <p class="rw-annonce" data-rw="superv-sauver-message" aria-live="polite"></p>

                    {{-- ══ LES SAUVEGARDES, ET LEUR RESTAURATION ══════════════
                         Cote legacy la liste s'ouvre dans une fenetre MODALE et
                         chaque ligne porte un bouton qui, d'un SEUL clic, ecrase
                         la configuration courante et redemarre l'agent : ni
                         `confirm()` natif, ni panneau, rien. Ici la liste est dans
                         la page, et chaque restauration passe par le panneau de
                         decision partage, cible par `data-cible`. --}}
                    <div class="rw-actions">
                        <p class="rw-aide rw-actions__gauche">{{ __('superv.sauvegardes_titre') }}</p>
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="superv-lire-sauvegardes">{{ __('superv.sauvegardes_lister') }}</button>
                    </div>

                    <div data-rw="superv-sauvegardes"></div>

                    <div class="rw-panneau-decision" data-rw="superv-panneau-restaurer" hidden>
                        <div class="rw-panneau-decision__texte">
                            <p class="rw-avertissement" data-rw="superv-restaurer-cout"></p>
                            <p class="rw-aide rw-prose">{{ __('superv.restaurer_aide') }}</p>
                        </div>
                        <div class="rw-panneau-decision__actions">
                            <button type="button" class="rw-bouton rw-bouton--discret"
                                    data-rw="superv-restaurer-annuler">{{ __('superv.restaurer_annuler') }}</button>
                            <button type="button" class="rw-bouton rw-bouton--danger"
                                    data-rw="superv-restaurer-confirmer">{{ __('superv.restaurer_confirmer') }}</button>
                        </div>
                    </div>

                    <p class="rw-annonce" data-rw="superv-restaurer-message" aria-live="polite"></p>
                @endif

                {{-- LE BLOC « PAS ENCORE PORTE » A ETE RETIRE ICI, et c'est le
                     point : l'onglet est COMPLET depuis V9 — lecture (V7),
                     ecriture, liste des sauvegardes et restauration. Le texte
                     annoncait encore « la lecture et l'ecriture arrivent avec les
                     sous-lots suivants » alors que la lecture etait portee depuis
                     V7 : il etait devenu faux d'une moitie sans qu'aucun test ne
                     le voie. Un renvoi vers l'ancien portail sur un onglet acheve
                     y renverrait pour rien. --}}
            </article>
        </div>
    </section>

    <script id="superv-libelles" type="application/json">@json($libelles)</script>
    <script src="{{ asset('js/supervision.js') }}" defer></script>
@endsection
