@extends('layouts.portail', ['titre' => __('plateforme.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('plateforme.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('plateforme.intro') }}</p>

{{--
    L'EN-TETE DU LEGACY MENT, ET CELUI-CI DIT LA GARDE REELLE.

    `platform_keys.php:4` annonce « Acces : superadmin uniquement » ; sa ligne 11
    admet les trois roles et c'est la PERMISSION qui decide. Cinquieme occurrence
    du motif, et la page concernee est celle qui manipule la cle de la flotte.
--}}
<p class="rw-aide rw-prose" data-rw="cle-garde">{{ __('plateforme.garde_reelle') }}</p>

{{--
    ── LE GUIDE DE PROCEDURE, PORTE ET CORRIGE ─────────────────────────────

    Le legacy affiche un guide en quatre etapes (`platform_keys.php:50`, via
    `howto_tip.php`). **Mon premier jet de P1 l'avait laisse tomber** — un acquis
    du legacy perdu sans que rien ne le signale, parce que personne n'ouvre
    `lang/`. Le Lead a nomme le motif : le legacy porte dans ses catalogues une
    reponse contextuelle que le portage laisse tomber module apres module.

    Ce que ce guide apporte est son ORDRE : « deployer la cle » AVANT « effacer le
    mot de passe » n'est pas une preference de presentation, c'est la difference
    entre une migration et un verrouillage. D'ou une liste NUMEROTEE.

    Et DEUX de ses quatre etapes sont corrigees, mesure en main — le porter
    fidelement aurait porte deux affirmations fausses, dont une dans le sens
    rassurant. La correction est DITE sous le guide plutot que faite en silence :
    un exploitant qui a lu l'ancien texte doit savoir lequel des deux croire.
--}}
<div class="rw-encart" data-rw="cle-guide">
    <p class="rw-sous-titre-fort">{{ __('plateforme.guide_titre') }}</p>
    <ol class="rw-liste-effets rw-liste-effets--ordonnee">
        <li>{{ __('plateforme.guide_etape1') }}</li>
        <li>{{ __('plateforme.guide_etape2') }}</li>
        <li>{{ __('plateforme.guide_etape3') }}</li>
        <li>{{ __('plateforme.guide_etape4') }}</li>
    </ol>
    <p class="rw-note rw-prose">{{ __('plateforme.guide_corrige') }}</p>
</div>

@if ($compteurs['total'] === 0)
    <div class="rw-vide" data-rw="cle-vide">
        <p class="rw-vide__titre">{{ __('plateforme.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('plateforme.vide_texte') }}</p>
    </div>
@else

{{--
    ── LA CLE PUBLIQUE ────────────────────────────────────────────────────

    Trois issues, pas deux : la lecture echoue, aucune paire n'existe encore
    (le backend rend 404 avec un message — c'est un VERDICT), ou la cle est la.
    Le legacy n'en distingue aucune : il pose la reponse dans un `<div>` et
    laisse « Chargement… » en cas d'echec.
--}}
<div class="rw-section" data-rw="cle-bloc">
    <div class="rw-section__tete">
        <h2 class="rw-section__entete">{{ __('plateforme.cle_titre') }}</h2>
        <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                data-rw="cle-copier" hidden>{{ __('plateforme.cle_copier') }}</button>
    </div>
    <p class="rw-aide rw-prose">{{ __('plateforme.cle_aide') }}</p>
    <div data-rw="cle-message"></div>
    {{-- `.rw-fichier` et non `.rw-code` : c'est une valeur d'une piece qu'on
         copie, pas une commande qui peut se couper n'importe ou. --}}
    <pre class="rw-fichier" data-rw="cle-valeur" hidden></pre>
    <p class="rw-aide" role="status" aria-live="polite" data-rw="cle-annonce"></p>
</div>

{{--
    ── CE QUE « MIGRATION TERMINEE » VEUT DIRE ────────────────────────────

    Toute la page du legacy POUSSE vers l'effacement des mots de passe : une
    barre de progression, un libelle « Migration terminee ! » atteint quand le
    compte y arrive, un bouton de masse, et une pastille verte reservee aux
    machines sans mot de passe. Or cet etat est EXACTEMENT celui ou la rotation
    de la cle est sans retour — et rien ne le dit.

    L'avertissement vient donc AVANT la barre, pas apres : on lit ce que
    l'aboutissement engage avant de voir le chemin qui y mene.
--}}
<div class="rw-encart" data-rw="cle-avert">
    <p class="rw-sous-titre-fort">{{ __('plateforme.avert_titre') }}</p>
    <p class="rw-prose">{{ __('plateforme.avert_texte') }}</p>
</div>

<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('plateforme.progression_titre') }}</h2>
    <p class="rw-aide" data-rw="cle-progression-etat">
        @if ($compteurs['sans_mot_de_passe'] === $compteurs['total'])
            {{ __('plateforme.progression_finie') }}
        @elseif ($compteurs['cle'] === $compteurs['total'])
            {{ __('plateforme.progression_cle_ok') }}
        @else
            {{ __('plateforme.progression_reste', ['nb' => $compteurs['en_attente']]) }}
        @endif
    </p>
    {{--
        LA BARRE EST EN DEUX SEGMENTS, ET SA LARGEUR VIENT DU CSS DU SOCLE.
        Le legacy exprime la seconde largeur par une SOUSTRACTION de pourcentages
        arrondis — `$pctDeployed - $pctClean` — ce qui peut rendre un negatif
        quand les deux arrondis se croisent. Ici chaque segment porte sa propre
        valeur, bornee a zero.
    --}}
    <div class="rw-frise" data-rw="cle-barre">
        <div class="rw-jauge">
            <span class="rw-jauge__part rw-jauge__part--ok"
                  style="width: {{ $compteurs['pct_sans_mdp'] }}%"
                  title="{{ __('plateforme.legende_cle') }}"></span>
            <span class="rw-jauge__part rw-jauge__part--attente"
                  style="width: {{ max(0, $compteurs['pct_cle'] - $compteurs['pct_sans_mdp']) }}%"
                  title="{{ __('plateforme.legende_les_deux') }}"></span>
        </div>
    </div>
    <p class="rw-frise__legende">
        <span class="rw-frise__cle rw-frise__cle--ban"></span>{{ __('plateforme.legende_mot_de_passe') }}
        <span class="rw-frise__cle rw-frise__cle--unban"></span>{{ __('plateforme.legende_les_deux') }}
        <span class="rw-frise__cle rw-frise__cle--ok"></span>{{ __('plateforme.legende_cle') }}
    </p>

    <div class="rw-grille rw-grille--compacte">
        @foreach ([
            ['stat_cle', $compteurs['cle'] . '/' . $compteurs['total']],
            ['stat_compte_service', $compteurs['compte_service'] . '/' . $compteurs['total']],
            ['stat_en_attente', (string) $compteurs['en_attente']],
            ['stat_sans_mot_de_passe', (string) $compteurs['sans_mot_de_passe']],
        ] as $tuile)
            <div class="rw-tuile" data-rw="cle-{{ $tuile[0] }}">
                <span class="rw-tuile__titre">{{ __('plateforme.' . $tuile[0]) }}</span>
                <span class="rw-tuile__valeur">{{ $tuile[1] }}</span>
            </div>
        @endforeach
    </div>
</div>

{{--
    ── LES MACHINES DONT LA CLE EST LE SEUL ACCES ─────────────────────────

    Le nombre est CALCULE, jamais suppose : une machine dont la cle est deployee
    et dont RootWarden ne detient plus aucun mot de passe n'a plus qu'une voie
    d'acces. Aujourd'hui il vaut zero — et l'ecrire en dur aurait fabrique un
    texte qui devient faux au premier effacement.
--}}
<div class="rw-section" data-rw="cle-sans-retour">
    <h2 class="rw-section__entete">{{ __('plateforme.sans_retour_titre') }}</h2>
    @if ($compteurs['sans_retour'] === 0)
        <p class="rw-aide rw-prose">{{ __('plateforme.sans_retour_aucune') }}</p>
    @else
        <p class="rw-annonce rw-annonce--attention">
            {{ __('plateforme.sans_retour_liste', [
                'nb' => $compteurs['sans_retour'],
                'noms' => implode(', ', $compteurs['noms_sans_retour']),
            ]) }}
        </p>
    @endif
</div>

{{--
    ── LE COMPTEUR DE L'ANCIEN PORTAIL EST FAUX, ET ON DIT POURQUOI ───────

    Il compte `ssh_password_required`, un DRAPEAU. La page Serveurs est le seul
    chemin qui REMPLIT `root_password`, et elle ne touche pas ce drapeau :
    restaurer un mot de passe la-bas laisse cette ligne annoncee comme effacee.
    Mesure du 2026-08-27 : une machine sur trois est dans ce cas.

    Un exploitant qui compare les deux portails verra deux nombres differents ;
    il doit savoir lequel compte quoi.
--}}
@if ($compteurs['divergentes'] > 0)
    <div class="rw-encart" data-rw="cle-divergence">
        <p class="rw-sous-titre-fort">{{ __('plateforme.divergence_titre') }}</p>
        <p class="rw-prose">{{ __('plateforme.divergence_texte', [
            'nb' => $compteurs['divergentes'],
            'noms' => implode(', ', $compteurs['noms_divergentes']),
        ]) }}</p>
    </div>
@endif

<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('plateforme.th_machine') }}</h2>
    <div class="rw-tableau-cadre">
        <table class="rw-tableau" data-rw="cle-tableau">
            <thead>
                <tr>
                    <th>{{ __('plateforme.th_machine') }}</th>
                    <th class="rw-colonne-secondaire">{{ __('plateforme.th_adresse') }}</th>
                    <th>{{ __('plateforme.th_auth') }}</th>
                    <th>{{ __('plateforme.th_compte_service') }}</th>
                    <th>{{ __('plateforme.th_mot_de_passe') }}</th>
                    <th class="rw-colonne-secondaire">{{ __('plateforme.th_depuis') }}</th>
                    <th>{{ __('plateforme.th_actions') }}</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($lignes as $l)
                    @php $m = $l['machine']; @endphp
                    <tr @class(['rw-ligne-sensible' => $l['sensible']])
                        data-rw="cle-ligne-{{ $m->id }}">
                        <td>
                            <span class="rw-tableau__fort">{{ $m->name }}</span>
                            @if ($l['sensible'])
                                <span class="rw-badge rw-badge--alerte">{{ __('plateforme.sensible') }}</span>
                            @endif
                        </td>
                        <td class="rw-colonne-secondaire rw-tableau__mono">{{ $m->ip }}:{{ $m->port }}</td>
                        <td>
                            {{-- L'ETAT S'ECRIT EN MOT. Le legacy le rend par une
                                 pastille coloree calculee sur le DRAPEAU ; ici il
                                 vient des colonnes, et il se lit. --}}
                            <span class="rw-pastille rw-pastille--{{ $l['auth'] === 'cle_seule' ? 'ok' : ($l['auth'] === 'mot_de_passe_seul' ? 'echec' : 'attente') }}"
                                  data-rw="cle-auth-{{ $m->id }}">
                                {{ __('plateforme.etat_' . $l['auth']) }}
                            </span>
                        </td>
                        <td>
                            @if ((int) $m->service_account_deployed)
                                <span class="rw-badge rw-badge--alerte"
                                      data-rw="cle-compte-service-{{ $m->id }}"
                                      title="{{ __('plateforme.compte_service_aide') }}">{{ __('plateforme.compte_service_pose') }}</span>
                            @else
                                <span class="rw-tableau__discret">{{ __('plateforme.compte_service_absent') }}</span>
                            @endif
                        </td>
                        <td>
                            <span data-rw="cle-mdp-{{ $m->id }}">{{ __('plateforme.mdp_' . $l['mots_de_passe']) }}</span>
                        </td>
                        <td class="rw-colonne-secondaire rw-tableau__discret">
                            {{ $m->platform_key_deployed_at ?: __('plateforme.jamais') }}
                        </td>
                        <td>
                            {{-- P2 : LE TEST EST OFFERT MEME AVANT DEPLOIEMENT, et
                                 c'est fidele — le backend repond alors « rien a
                                 tester », ce qui est une information utile. Le
                                 masquer forcerait a deviner l'ordre des etapes. --}}
                            <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                                    data-rw="cle-tester-{{ $m->id }}"
                                    data-machine="{{ $m->id }}" data-nom="{{ $m->name }}">
                                {{ __('plateforme.tester') }}
                            </button>
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
    <p class="rw-aide rw-prose">{{ __('plateforme.tester_aide') }}</p>

    {{--
        ── LE JOURNAL DES TESTS, AU NIVEAU DE LA SECTION ───────────────────

        Une region persistante et non une bulle : une bulle disparue ne dit plus
        si le verdict qu'on relit est celui d'avant ou celui d'apres. Vide, le
        cadre DIT qu'il est vide.
    --}}
    <h3 class="rw-sous-titre-fort rw-titre--espace">{{ __('plateforme.test_journal') }}</h3>
    <div class="rw-journal__general rw-journal--vide" data-rw="cle-test-journal"
         aria-live="polite" aria-label="{{ __('plateforme.test_journal_vide') }}"></div>

    {{-- CE QUE LE COMPTE D'ADMINISTRATION ACCORDE, DIT UNE FOIS SOUS LE
         TABLEAU plutot que cache dans une infobulle : « NOPASSWD: ALL ». --}}
    <p class="rw-aide rw-prose">{{ __('plateforme.compte_service_aide') }}</p>
    {{-- ET L'ASYMETRIE DU RETOUR : effacer retire les DEUX mots de passe,
         « Ressaisir » n'en rend qu'un. --}}
    <p class="rw-aide rw-prose">{{ __('plateforme.mdp_aide_partiel') }}</p>
</div>

<div class="rw-encart" data-rw="cle-non-porte">
    <p class="rw-sous-titre-fort">{{ __('plateforme.non_porte_titre') }}</p>
    <p class="rw-prose">{{ __('plateforme.non_porte_texte') }}</p>
    <a class="rw-bouton" data-rw="cle-lien-legacy"
       href="{{ rtrim(config('app.url_legacy'), '/') }}/adm/platform_keys.php"
       target="_blank" rel="noopener">{{ __('plateforme.non_porte_lien') }} ↗</a>
</div>
@endif

    <script id="cle-textes" type="application/json">@json($textes)</script>
    <script src="/js/cle-plateforme.js?v={{ @filemtime(public_path('js/cle-plateforme.js')) ?: '0' }}"></script>
@endsection
