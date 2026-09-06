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
                    {{-- `data-mdp` porte CE QUE LE SERVEUR A CALCULE sur les
                         colonnes. Le script le compare a la reponse du detenteur
                         de la cle : sans cette valeur il ne pourrait pas dire
                         qu'il y a DIVERGENCE, seulement afficher un etat de plus
                         sans dire lequel des deux se trompe. --}}
                    <tr @class(['rw-ligne-sensible' => $l['sensible']])
                        data-rw="cle-ligne-{{ $m->id }}" data-mdp="{{ $l['mots_de_passe'] }}">
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
                                    data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}">
                                {{ __('plateforme.tester') }}
                            </button>

                            {{-- ── P3 : LES GESTES QUI ECRIVENT ─────────────

                                 Chacun n'est rendu que lorsqu'il a un objet, et
                                 la condition est celle du BACKEND, pas celle de
                                 l'apparence. Un bouton toujours visible qui
                                 repond « rien a faire » se clique pour savoir ;
                                 un bouton absent a deja repondu.

                                 Aucun de ces boutons n'agit : ils OUVRENT le
                                 panneau de decision, qui nomme la machine et la
                                 consequence. `confirm()` est proscrit. --}}
                            @if (! (int) $m->platform_key_deployed)
                                <button type="button" class="rw-bouton rw-bouton--minuscule"
                                        data-rw="cle-deployer-{{ $m->id }}"
                                        data-geste="deployer"
                                        data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}">
                                    {{ __('plateforme.btn_deployer') }}
                                </button>
                            @endif

                            @if ((int) $m->platform_key_deployed && ! (int) $m->service_account_deployed)
                                {{-- REPRISE et non etape suivante : le deploiement
                                     de la cle a DEJA tente ce compte et a echoue. --}}
                                <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                                        data-rw="cle-compte-service-poser-{{ $m->id }}"
                                        data-geste="compte_service"
                                        data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}">
                                    {{ __('plateforme.btn_compte_service') }}
                                </button>
                            @endif

                            @if ((int) $m->platform_key_deployed && (int) $m->service_account_deployed
                                 && ($l['mots_de_passe'] !== 'aucun'))
                                <button type="button" class="rw-bouton rw-bouton--danger rw-bouton--minuscule"
                                        data-rw="cle-effacer-{{ $m->id }}"
                                        data-geste="effacer"
                                        data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}">
                                    {{ __('plateforme.btn_effacer') }}
                                </button>
                            @endif

                            @if ($estSuperadmin && (int) $m->service_account_deployed)
                                {{-- LA CONTREPARTIE DE L'OCTROI. Rendue au role 3
                                     seulement : `ssh.py:896` exige `@require_role(3)`
                                     alors que cette page s'ouvre des le role 1 avec
                                     la permission. Rendre le bouton plus largement
                                     promettrait un geste qui finirait en 403. --}}
                                <button type="button" class="rw-bouton rw-bouton--danger rw-bouton--minuscule"
                                        data-rw="cle-revoquer-{{ $m->id }}"
                                        data-geste="revoquer"
                                        data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}">
                                    {{ __('plateforme.btn_revoquer') }}
                                </button>
                            @endif

                            @if ((int) $m->platform_key_deployed && $l['mots_de_passe'] !== 'les_deux')
                                {{-- « RESSAISIR » EST OFFERT DES QU'UN MOT DE PASSE
                                     MANQUE, et non seulement quand le drapeau dit
                                     « supprime » : c'est le FAIT qui decide, comme
                                     partout ailleurs sur cette page. Le legacy
                                     testait `! $pwRequired` et manquait donc le cas
                                     ou le drapeau et les colonnes divergent. --}}
                                <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                                        data-rw="cle-ressaisir-{{ $m->id }}"
                                        data-geste="ressaisir"
                                        data-machine="{{ $m->id }}" data-nom="{{ $m->name }}"
                                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                                        data-manquant="{{ $l['mots_de_passe'] }}">
                                    {{ __('plateforme.btn_ressaisir') }}
                                </button>
                            @endif
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

    {{--
        ═══ P3 — LES GESTES A L'ECHELLE DU PARC ════════════════════════════

        Trois portees, TROIS NOMBRES, chacun celui de la liste sur laquelle son
        bouton agit. Le legacy affichait des soustractions de compteurs calcules
        sur d'autres predicats : le nombre annonce et le nombre agi pouvaient
        differer sans que rien ne le dise.

        Un bouton dont la portee est vide n'est PAS rendu : il n'y a rien a
        decider. Le cas « rien a faire » s'enonce en toutes lettres a la place.
    --}}
    <h3 class="rw-sous-titre-fort rw-titre--espace">{{ __('plateforme.parc_titre') }}</h3>
    <p class="rw-aide rw-prose">{{ __('plateforme.parc_aide') }}</p>

    <div class="rw-actions" data-rw="cle-parc">
        @foreach (['deployer' => 'rw-bouton', 'compte_service' => 'rw-bouton rw-bouton--discret', 'effacer' => 'rw-bouton rw-bouton--danger', 'revoquer' => 'rw-bouton rw-bouton--danger'] as $geste => $classe)
            @if (count($portees[$geste]['ids'] ?? []) > 0)
                <button type="button" class="{{ $classe }}"
                        data-rw="cle-parc-{{ $geste }}"
                        data-geste="{{ $geste }}" data-portee="parc">
                    {{ __('plateforme.parc_btn_' . $geste, ['n' => count($portees[$geste]['ids'])]) }}
                </button>
            @endif
        @endforeach
    </div>

    @if (count($portees['deployer']['ids']) === 0 && count($portees['compte_service']['ids']) === 0
         && count($portees['effacer']['ids']) === 0 && count($portees['revoquer']['ids'] ?? []) === 0)
        <p class="rw-aide" data-rw="cle-parc-rien">{{ __('plateforme.parc_rien') }}</p>
    @endif

    {{--
        ── CE QUE L'EFFACEMENT DE MASSE ECARTE, ET POURQUOI ────────────────

        Le legacy proposait ces machines et le backend les REFUSAIT une par une
        (400, « Service account non deploye »), sans que la boucle ne le dise :
        elle comptait les reussites et avalait le reste. Ici elles sortent de la
        portee — et elles sont NOMMEES, avec le geste qui les debloque.

        Une portee qui retrecit en silence se lit comme une portee complete.
    --}}
    @if (count($effacementRefusees['ids']) > 0)
        <div class="rw-encart" data-rw="cle-effacement-refusees">
            <p class="rw-sous-titre-fort">{{ __('plateforme.refusees_titre', ['n' => count($effacementRefusees['ids'])]) }}</p>
            <p class="rw-prose">{{ __('plateforme.refusees_texte') }}</p>
            <p class="rw-tableau__mono">{{ implode(', ', $effacementRefusees['noms']) }}</p>
        </div>
    @endif

    {{--
        ═══ P4 — LA ROTATION : PORTEE, ET JAMAIS EXERCEE ═══════════════════

        Le geste le plus large du portail. Il ne prend AUCUN `machine_id` : son
        corps est vide et il fait un `UPDATE machines SET platform_key_deployed
        = FALSE` **sans clause de restriction**. C'est pourquoi
        `@require_machine_access` ne serait pas une garde ici mais un decor : un
        decorateur qui cherche un identifiant dans un corps qui n'en a pas
        laisserait tout passer. La garde juste est celle qui est la,
        `@require_role(3)`, plus la porte a quatre yeux.

        LA SECTION N'EST RENDUE QU'AU ROLE 3, pour la meme raison que la
        suppression du compte d'administration : offrir un geste qui finira en
        403 n'est pas une garde, c'est une promesse fausse.

        CE QUE LE BOUTON FAIT AU CLIC : il OUVRE le panneau. Il n'emet AUCUNE
        requete. C'est la propriete que la suite mesure — au reseau, par
        interception — et c'est aussi la raison pour laquelle ce geste peut etre
        porte sans jamais etre execute.
    --}}
    @if ($estSuperadmin)
        <section class="rw-carte rw-carte--pleine" data-rw="cle-rotation">
            <p class="rw-etiquette">{{ __('plateforme.rotation_titre') }}</p>
            <p class="rw-aide rw-prose">{{ __('plateforme.rotation_aide') }}</p>

            {{-- LE REMEDE EST NOMME ICI, ET C'EST LE SEUL ENDROIT OU IL ARRIVE
                 AU MOMENT OU IL SERT. Corriger le libelle de la suppression du
                 compte sans dire ou est le vrai remede aurait rendu la
                 desinformation muette au lieu de la corriger. --}}
            {{-- TROIS AFFIRMATIONS, ET LA DEUXIEME EST CELLE QUI MANQUAIT.

                 Mon premier jet disait que le geste de retrait « n'a aucune
                 interface de parc ici », ce qui laissait entendre qu'il n'existe
                 pas. C'est le pire des deux mensonges possibles sur un ecran
                 d'incident : il envoie chercher ailleurs, ou conclure qu'il n'y
                 a rien a faire.

                 Le geste EXISTE, il est soigneux — sauvegarde, empreintes
                 recalculees par `ssh-keygen -lf` ligne par ligne, code de sortie
                 lu — et il REFUSE par defaut de retirer la cle de plateforme.
                 Ce refus est ce qu'on veut pendant un incident, et l'appel du
                 legacy ne passe pas `force` : la protection s'applique.

                 J'avais confondu cette route avec `remove_user_keys`, sa voisine
                 du meme fichier, qui vide `authorized_keys` et atteste sans
                 verifier. Celle-la n'est PAS nommee ici : diriger quelqu'un vers
                 un geste qui ment sur son propre effet serait refaire le motif a
                 l'etage au-dessus. --}}
            <div class="rw-encart" data-rw="cle-rotation-remede">
                <p class="rw-prose">{{ __('plateforme.rotation_remede') }}</p>
                <p class="rw-prose" data-rw="cle-rotation-remede-ou">{{ __('plateforme.rotation_remede_ou') }}</p>
                <p class="rw-aide rw-prose" data-rw="cle-rotation-remede-parc">{{ __('plateforme.rotation_remede_parc') }}</p>
            </div>

            {{-- LES MACHINES POUR LESQUELLES LA ROTATION EST SANS RETOUR AU SENS
                 STRICT. Le nombre est CALCULE (cf. `compteurs()`), jamais ecrit
                 en dur : il vaut zero aujourd'hui et changera au premier
                 effacement de mot de passe. Un compteur a zero s'enonce. --}}
            @if ($compteurs['sans_retour'] > 0)
                <p class="rw-annonce rw-annonce--attention" data-rw="cle-rotation-sans-retour">
                    {{ __('plateforme.rotation_sans_retour', [
                        'n' => $compteurs['sans_retour'],
                        'noms' => implode(', ', $compteurs['noms_sans_retour']),
                    ]) }}
                </p>
            @else
                <p class="rw-aide rw-prose" data-rw="cle-rotation-sans-retour-aucune">
                    {{ __('plateforme.rotation_sans_retour_aucune') }}
                </p>
            @endif

            <p class="rw-aide rw-prose" data-rw="cle-rotation-jamais">{{ __('plateforme.rotation_jamais_exercee') }}</p>

            <div class="rw-actions">
                <button type="button" class="rw-bouton rw-bouton--danger"
                        data-rw="cle-rotation-lancer"
                        data-geste="rotation" data-portee="flotte"
                        data-total="{{ $compteurs['total'] }}">
                    {{ __('plateforme.btn_rotation') }}
                </button>
            </div>
        </section>
    @endif

    {{--
        ═══ LE PANNEAU DE DECISION, UN SEUL POUR TOUS LES GESTES ═══════════

        Il nait `hidden`, il NOMME sa cible, et il porte le champ de ressaisie —
        `type="password"`, la ou le legacy ouvrait un `prompt()` natif qui
        affiche le mot de passe en clair et le laisse dans l'historique du
        dialogue du navigateur.

        Les machines de PRODUCTION de la portee sont annoncees a part : un
        nombre ne dit pas qu'on est sur le point d'ecrire en root sur la
        production.
    --}}
    <div class="rw-panneau-decision" data-rw="cle-panneau" hidden>
        <p class="rw-panneau-decision__texte" data-rw="cle-panneau-titre"></p>
        <p class="rw-prose" data-rw="cle-panneau-texte"></p>

        <ul class="rw-liste-effets" data-rw="cle-panneau-effets"></ul>

        <p class="rw-tableau__mono" data-rw="cle-panneau-cibles"></p>

        <p class="rw-annonce rw-annonce--attention" data-rw="cle-panneau-prod" hidden></p>

        {{-- Le champ n'existe que pour la ressaisie : il est devoile par le
             script, jamais rendu conditionnellement — un panneau unique reste un
             seul contrat DOM pour les suites. --}}
        {{-- Le motif : obligatoire, et journalise avec le nom de la machine.
             Le legacy demandait ses motifs par `prompt()` ailleurs dans ce
             module ; ici c'est un champ, comme le mot de passe. --}}
        {{-- LA RECOPIE. Le bouton de confirmation naît DÉSACTIVÉ pour les
             gestes qui l'exigent, et ne s'active qu'à l'égalité EXACTE. Le
             legacy demandait deux `confirm()` pour la rotation ; le portage
             avait remplacé deux réflexes par un seul clic, ce qui est moins
             exigeant que ce qu'il remplaçait. Le nombre à recopier est celui
             que le panneau vient d'afficher : on ne demande rien qu'il ne
             montre.

             ⚠ CE CHAMP N'EST PAS LA SÉCURITÉ, C'EST L'ANNONCE. Il rend la
             règle lisible AVANT le geste. La sécurité est la revérification
             faite au moment de confirmer, dans le script — `disabled` est un
             état du DOM, il se retire depuis la console et ne survit pas à un
             `click()` programmatique. Écrit ici pour que personne ne retire un
             jour le second contrôle en le croyant redondant. --}}
        <label class="rw-champ" data-rw="cle-panneau-recopie" hidden>
            <span class="rw-etiquette">{{ __('plateforme.champ_recopie') }}</span>
            <input type="text" inputmode="numeric" class="rw-saisie rw-saisie--court"
                   data-rw="cle-panneau-recopie-valeur" autocomplete="off" spellcheck="false">
            <span class="rw-aide">{{ __('plateforme.champ_recopie_aide') }}</span>
        </label>

        <label class="rw-champ" data-rw="cle-panneau-motif" hidden>
            <span class="rw-etiquette">{{ __('plateforme.champ_motif') }}</span>
            <input type="text" class="rw-saisie" data-rw="cle-panneau-motif-valeur"
                   maxlength="200" autocomplete="off" spellcheck="false">
            <span class="rw-aide">{{ __('plateforme.champ_motif_aide') }}</span>
        </label>

        {{-- Le texte vient du script, depuis la carte `bornes` : deux gestes
             butent sur la meme cause backend, et le paragraphe reste vide (et
             `hidden`) pour ceux qui n'en ont pas. Le figer ici aurait dit « la
             reprise » a qui clique « redeployer ». --}}
        <p class="rw-aide rw-prose" data-rw="cle-panneau-borne" hidden></p>

        <label class="rw-champ" data-rw="cle-panneau-champ" hidden>
            <span class="rw-etiquette">{{ __('plateforme.champ_mdp') }}</span>
            <input type="password" class="rw-saisie" data-rw="cle-panneau-mdp"
                   autocomplete="new-password" spellcheck="false">
            <span class="rw-aide">{{ __('plateforme.champ_mdp_aide') }}</span>
        </label>

        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="cle-panneau-annuler">{{ __('plateforme.annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="cle-panneau-confirmer">{{ __('plateforme.confirmer') }}</button>
        </div>
    </div>

    {{-- LE JOURNAL DES GESTES est distinct de celui des tests : un test ne
         change rien, un geste ecrit. Les melanger ferait relire un verdict de
         lecture comme la preuve d'une ecriture. --}}
    <h3 class="rw-sous-titre-fort rw-titre--espace">{{ __('plateforme.geste_journal') }}</h3>
    <div class="rw-journal__general rw-journal--vide" data-rw="cle-geste-journal"
         aria-live="polite" aria-label="{{ __('plateforme.geste_journal_vide') }}"></div>

    {{-- ── PAS DE RECHARGEMENT AUTOMATIQUE ────────────────────────────────

         Le legacy fait `location.reload()` 1,5 s apres chaque geste — et
         effface donc le journal qu'il vient d'ecrire. Sur un geste de parc, ces
         1,5 s sont tout ce dont on dispose pour lire N lignes dont certaines
         disent « echoue ». Le rechargement devient un GESTE, offert quand il y
         a quelque chose de neuf a relire. --}}
    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="cle-recharger" hidden>{{ __('plateforme.recharger') }}</button>
    </div>

    {{--
        ═══ E-219 — CE QUE SEUL LE DETENTEUR DE LA CLE PEUT DIRE ═══════════

        Les compteurs de cette page et la colonne « Mot de passe » se calculent
        sur `(password <> '')`. Ce test est FAUX comme predicat de « cette
        machine a un mot de passe » : PHP chiffre la chaine vide en `sodium:…`
        (63 octets mesures) la ou Python rend `''`. La colonne est donc NON VIDE
        pour un mot de passe REELLEMENT vide.

        Le portage ne peut pas trancher, et ne DOIT pas : recopier le
        dechiffrement ici serait recopier une regle de securite. Il interroge
        donc `GET /machines/credential-status`, qui rend TROIS etats — vide,
        non vide, et INDETERMINE quand le dechiffrement a echoue.

        L'encart nait `hidden` : il n'a rien a dire avant la reponse, et une
        boite vide inviterait au clic. En cas d'echec de la requete il DIT que
        les compteurs restent approximatifs — il ne les declare pas justes.
    --}}
    <div class="rw-encart" data-rw="cle-credential" hidden>
        <p class="rw-sous-titre-fort">{{ __('plateforme.credential_titre') }}</p>
        <p class="rw-prose">{{ __('plateforme.credential_aide') }}</p>
        <p class="rw-prose" data-rw="cle-credential-verdict" role="status" aria-live="polite"></p>
        <p class="rw-aide rw-prose">{{ __('plateforme.credential_borne_root') }}</p>
    </div>

    {{-- ── L'ASYMETRIE DE ROLE, DITE A CEUX QU'ELLE CONCERNE ──────────────

         Un compte role 1 ou 2 porteur de `can_manage_platform_key` peut
         ACCORDER `NOPASSWD: ALL` et ne peut pas le reprendre. Le lui cacher
         lui laisserait croire que l'octroi est reversible depuis cette page.
         L'encart n'apparait donc QUE pour ces comptes, et seulement s'il y a
         au moins une machine concernee — sinon il parlerait dans le vide. --}}
    @if (! $estSuperadmin && $revocationPossible)
        <div class="rw-encart" data-rw="cle-revoquer-asymetrie">
            <p class="rw-prose">{{ __('plateforme.revoquer_asymetrie') }}</p>
        </div>
    @endif

    {{-- CE QUE LE COMPTE D'ADMINISTRATION ACCORDE, DIT UNE FOIS SOUS LE
         TABLEAU plutot que cache dans une infobulle : « NOPASSWD: ALL ». --}}
    <p class="rw-aide rw-prose">{{ __('plateforme.compte_service_aide') }}</p>
    {{-- ET L'ASYMETRIE DU RETOUR : effacer retire les DEUX mots de passe,
         « Ressaisir » n'en rend qu'un. --}}
    <p class="rw-aide rw-prose">{{ __('plateforme.mdp_aide_partiel') }}</p>
</div>

{{-- ── LE LIEN VERS L'ANCIEN PORTAIL RESTE, MAIS IL NE DIT PLUS
     « NON PORTE » ──────────────────────────────────────────────────────

     Tous les gestes de cette page sont portes, la rotation comprise. Le lien
     subsiste parce que la comparaison entre les deux portails a une valeur
     pendant la migration — mais l'annoncer comme une capacite manquante serait
     desormais faux, et c'est exactement le motif que ce module a passe la
     journee a corriger. --}}
        {{-- LA TUILE « Comparer avec l'ancien portail » A ETE RETIREE le 2026-09-05.
             Son propre texte disait « Tous les gestes de cette page sont portes ici,
             la rotation de la cle comprise » — et proposait quand meme un renvoi vers
             `/adm/platform_keys.php`, qui rend 404 depuis l'archivage du jour.
             Il n'y a plus rien a comparer, et le lien ne menait nulle part. --}}
@endif

    <script id="cle-textes" type="application/json">@json($textes)</script>
    <script id="cle-portees" type="application/json">@json($portees)</script>
    <script src="/js/cle-plateforme.js?v={{ @filemtime(public_path('js/cle-plateforme.js')) ?: '0' }}"></script>
@endsection
