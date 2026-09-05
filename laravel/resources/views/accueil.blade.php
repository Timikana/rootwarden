@extends('layouts.portail', ['titre' => __('nav.dashboard')])

@section('corps')
    <h1 class="rw-titre">{{ __('accueil.bienvenue', ['nom' => session('utilisateur_nom')]) }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('accueil.orientation') }}</p>

    {{--
        ═══ L'ASSISTANT DE PREMIERE CONFIGURATION ═══════════════════════════

        AVANT les alertes, et c'est le seul endroit ou il a un sens : il ne
        s'affiche que sur une installation qui n'est pas encore configuree, et
        dans ce cas il EST la premiere chose a faire. Une fois masque ou
        termine, il disparait et la page reprend sa forme habituelle.

        Le predicat vit dans le controleur (`$onboarding === null`), pas ici :
        role minimal, drapeau de masquage et absence de session y sont decides
        une fois. **Un gabarit qui recopierait la garde en donnerait une seconde
        version, et c'est ce que ce portage refuse partout.**
    --}}
    @if (($onboarding ?? null) !== null)
        @include('composants.onboarding')
    @endif

    {{--
        ═══ E-264 — CE QUI DEMANDE L'ATTENTION ══════════════════════════════

        En TETE de page, avant les tuiles : une alerte placee sous douze tuiles
        n'est plus une alerte. Le legacy la met au meme endroit, c'est le seul
        point ou son ecran a raison sur cette region.

        TROIS CHOSES QUE LE LEGACY NE FAIT PAS :

        1. LE NOMBRE EST CELUI DES TUILES. Cinq des huit alertes sont derivees
           des indicateurs affiches plus bas, et non relues : le legacy relit
           sans borne, si bien que sa tuile et son alerte pouvaient annoncer
           deux nombres differents pour le meme fait.

        2. AUCUN NOM. `legacy/index.php:125` nomme jusqu'a cinq comptes et l'age
           de leur cle, dans le message ET dans le `title=` du rendu (`:213`).
           Une alerte n'a pas besoin de nommer pour etre actionnable — le lien
           mene a la page, qui a ses propres droits.

        3. « RIEN » NE SE DIT QUE SI TOUT A ETE LU. Le legacy avale trois de ses
           lectures dans des `catch` vides : sur une base muette sa region est
           vide, et une region vide se lit « tout va bien ». Sur un tableau de
           bord de securite c'est le mensonge le plus couteux qui soit.

        La COULEUR n'est pas le seul canal : la forme du marqueur change avec le
        ton, et le texte nomme le fait sans dependre de la teinte.
    --}}
    <section class="rw-alertes" data-rw="accueil-alertes" aria-labelledby="rw-alertes-titre">
        <h2 class="rw-alertes__titre" id="rw-alertes-titre">{{ __('accueil.alertes_titre') }}</h2>

        @if ($alertes['illisibles'] !== [])
            <p class="rw-alertes__illisible" data-rw="accueil-alertes-illisible">
                {{ __('accueil.alertes_illisible') }}
                {{ __('accueil.alertes_illisible_familles', ['familles' => implode(', ', array_map(fn ($f) => __('accueil.alertes_famille_' . $f), $alertes['illisibles']))]) }}
            </p>
        @endif

        @forelse ($alertes['alertes'] as $a)
            @php
                // Une balise et non deux blocs recopies : le contenu est le meme,
                // seule la nature de l'element change selon qu'il y a une porte.
                $balise = $a['lien'] !== null ? 'a' : 'div';
                $marque = ['grave' => '✕', 'attention' => '⚠', 'info' => 'ℹ'][$a['ton']];
            @endphp
            <{{ $balise }} class="rw-alerte rw-alerte--{{ $a['ton'] }}"
                data-rw="accueil-alerte-{{ $a['cle'] }}"
                @if ($a['lien'] !== null) href="{{ $a['lien'] }}" @endif
                @if ($a['externe']) target="_blank" rel="noopener" @endif>
                <span class="rw-alerte__marque" aria-hidden="true">{{ $marque }}</span>
                <span class="rw-alerte__nombre">{{ $a['nombre'] }}</span>
                <span class="rw-alerte__texte">{{ trans_choice('accueil.alerte_' . $a['cle'], $a['nombre']) }}</span>
                @if ($a['lien'] !== null)
                    {{-- MEME MARQUEUR QUE LE MENU : `↗` quand la page n'est pas
                         encore portee et qu'on change de portail. --}}
                    <span class="rw-alerte__lien">{{ __('accueil.alertes_voir') }} {{ $a['externe'] ? '↗' : '→' }}</span>
                @endif
            </{{ $balise }}>
        @empty
            @if ($alertes['illisibles'] === [])
                {{-- Le calme ne s'annonce QUE si rien n'a manque a la lecture. --}}
                <p class="rw-alertes__vide" data-rw="accueil-alertes-aucune">{{ __('accueil.alertes_aucune') }}</p>
                <p class="rw-alertes__vide">{{ __('accueil.alertes_aucune_aide') }}</p>
            @endif
        @endforelse
    </section>

    {{-- La grille remplit la largeur disponible : `auto-fit` avec un minimum de
         280 px donne 2 colonnes sur un ecran moyen, 4 ou 5 sur un grand. --}}
    <div class="rw-grille">

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.acces_titre') }}</span>
            <span class="rw-tuile__valeur">{{ $modulesAccessibles }}</span>
            <p class="rw-tuile__texte">{{ trans_choice('accueil.acces_texte', $modulesAccessibles, ['role' => $libelleRole]) }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.portes_titre') }}</span>
            <span class="rw-tuile__valeur">{{ $modulesPortes }} / {{ $modulesAccessibles }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.portes_texte') }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.securite_titre') }}</span>
            <span class="rw-tuile__valeur">{{ __('accueil.securite_valeur') }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.securite_texte') }}</p>
        </div>

        {{-- LA TUILE « Ancien portail » A ETE RETIREE le 2026-09-05.
             Son texte disait « Toujours en service, avec les memes identifiants ».
             MESURE : `/index.php` du legacy rend 404 depuis l'archivage du jour.
             Un ecran qui annonce un portail en service et pointe vers un 404 est
             le defaut corrige deux fois ailleurs (supervision 03/09, /profil 05/09). --}}


    {{--
        ═══ E-208 — LE PARC, BORNE AU PERIMETRE DU COMPTE ══════════════════

        `legacy/index.php` sert la taille du parc a tout le monde, sans filtrer
        selon les machines attribuees. L'arbitrage rendu est de BORNER dans le
        portage, et de DIRE le total avec.

        Les deux nombres vont ensemble : « 1 de vos machines » seul laisserait
        croire que le parc en compte une ; « 3 au parc » seul serait la fuite.
        *Un compte qui ne voit qu'une machine sur trois doit savoir que le parc
        en compte trois, sinon le tableau de bord mentirait par omission au lieu
        de fuir.*

        La reserve n'apparait QUE si la borne mord : un role >= 2 voit le parc
        entier, et lui afficher « vous ne voyez que vos machines » serait une
        reserve sans objet — celles-la deviennent un decor qu'on ne lit plus.
    --}}
    <div class="rw-tuile" data-rw="accueil-parc">
        {{-- Le titre suit le MEME discriminant que la valeur : le corriger en bas
             et laisser « Vos machines » en haut ne ferait que remonter le
             possessif d'une ligne. --}}
        <span class="rw-tuile__titre" data-rw="accueil-parc-titre">{{ __($parc['mord'] ? 'accueil.parc_compteur_titre' : 'accueil.parc_compteur_titre_neutre') }}</span>
        @if (! $parc['lisible'])
            {{-- UNE BASE INJOIGNABLE N'EST PAS UN PARC VIDE. Afficher « 0 · 0 »
                 se lirait comme un fait. --}}
            <p class="rw-tuile__texte" data-rw="accueil-parc-illisible">{{ __('accueil.parc_illisible') }}</p>
        @else
            {{-- ══ E-263 : LE DISCRIMINANT EST « MORD », PAS « BORNE » ══════════
                 Le possessif et la reserve existent pour SIGNALER une
                 restriction. Les rendre quand rien n'est retire les fait
                 signaler une restriction qui n'existe pas — au role >= 2 le
                 possessif mentait (« 3 de vos machines » alors que ce sont
                 TOUTES les machines), au role 1 tout-attribue c'est la reserve
                 qui mentait, avec le nombre affiche deux fois par-dessus.

                 Deux ancres POSITIVES et exclusives : une suite qui ne viserait
                 que `accueil-parc-valeur` ne saurait pas laquelle des deux
                 variantes a ete rendue, et passerait au vert par absence. --}}
            <span class="rw-tuile__valeur" data-rw="accueil-parc-valeur">
                @if ($parc['mord'])
                    <span data-rw="accueil-parc-possessif">{{ trans_choice('accueil.parc_perimetre', $parc['perimetre']) }}</span>
                    <span class="rw-tuile__appoint" data-rw="accueil-parc-appoint">· {{ trans_choice('accueil.parc_total', $parc['parc']) }}</span>
                @else
                    <span data-rw="accueil-parc-neutre">{{ trans_choice('accueil.parc_neutre', $parc['parc']) }}</span>
                @endif
            </span>
            @if ($parc['mord'])
                <p class="rw-tuile__texte" data-rw="accueil-parc-borne">{{ __('accueil.parc_borne_aide') }}</p>
            @endif
        @endif
    </div>

    </div>{{-- fin de la grille des tuiles d'etat --}}

    {{--
        ═══ LES NEUF INDICATEURS DU LEGACY, BORNES ═════════════════════════

        `legacy/index.php:78-104` les calcule SANS borne : un compte qui n'a
        acces a aucune machine y lit la taille du parc, le nombre de CVE
        critiques et la date du dernier scan. C'est la fuite tranchee par
        l'arbitrage, et la raison pour laquelle ces neuf-la n'avaient pas suivi
        les tuiles.

        TROIS FAMILLES, TROIS BORNES — et c'est la moitie que l'arbitrage ne
        couvrait pas : un perimetre de MACHINES ne borne pas une population
        d'UTILISATEURS.
    --}}
    <h2 class="rw-section__entete rw-titre--espace" data-rw="accueil-ind-parc-titre">{{ __($indicateurs['borne'] ? 'accueil.ind_parc_titre' : 'accueil.ind_parc_titre_neutre') }}</h2>

    @if (! $indicateurs['lisible'])
        {{-- UNE LECTURE ECHOUEE N'EST PAS UN PARC VIDE. Afficher des zeros les
             ferait lire comme des faits. --}}
        <p class="rw-annonce rw-annonce--attention" data-rw="accueil-ind-illisible">
            {{ __('accueil.ind_illisible') }}
        </p>
    @else
        <div class="rw-grille" data-rw="accueil-indicateurs">
            @foreach ([
                ['machines', $indicateurs['machines'], 'ind_machines', null],
                ['en-ligne', $indicateurs['en_ligne'], 'ind_en_ligne', null],
                ['hors-ligne', $indicateurs['hors_ligne'], 'ind_hors_ligne', null],
                ['inconnu', $indicateurs['inconnu'], 'ind_inconnu', 'ind_inconnu_aide'],
                ['cle', $indicateurs['cle'], 'ind_cle', null],
            ] as [$cle, $valeur, $libelle, $aide])
                <div class="rw-tuile" data-rw="accueil-ind-{{ $cle }}">
                    <span class="rw-tuile__valeur">{{ $valeur }}</span>
                    <p class="rw-tuile__texte">{{ __('accueil.' . $libelle) }}</p>
                    @if ($aide)
                        {{-- L'ETAT INCONNU PORTE SON EXPLICATION. Un compteur
                             nomme « etat inconnu » sans dire ce que l'ancien
                             portail en faisait laisserait croire a un ajout
                             cosmetique. --}}
                        <p class="rw-aide" data-rw="accueil-ind-{{ $cle }}-aide">{{ __('accueil.' . $aide) }}</p>
                    @endif
                </div>
            @endforeach
        </div>

        @if ($indicateurs['borne'])
            {{-- LA RESERVE NE S'AFFICHE QUE SI LA BORNE MORD. Un role >= 2 voit
                 le parc : lui dire « seulement vos machines » serait une reserve
                 sans objet, et celles-la deviennent un decor qu'on ne lit plus. --}}
            <p class="rw-aide rw-prose" data-rw="accueil-ind-borne">{{ __('accueil.ind_borne') }}</p>
        @endif
    @endif

    {{-- ── LES VULNERABILITES : TROIS ISSUES, PAS DEUX ─────────────────────

         `cve_scans` porte `machine_id` (mesure) : ces trois valeurs se bornent
         donc au perimetre, contrairement a ce qu'annoncait l'arbitrage. La seule
         ligne de cette installation porte 1458 CVE sur la production — un role 1
         qui n'a pas cette machine ne doit pas la lire.

         « Aucun scan » n'est ni « zero CVE » ni « je n'ai pas su lire », et les
         trois se disent separement. --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('accueil.ind_cve_titre') }}</h2>

    @if (! $cve['lisible'])
        <p class="rw-annonce rw-annonce--attention" data-rw="accueil-cve-illisible">
            {{ __('accueil.ind_cve_illisible') }}
        </p>
    @elseif ($cve['aucun_scan'])
        <p class="rw-aide rw-prose" data-rw="accueil-cve-aucun-scan">
            {{ __('accueil.ind_cve_aucun_scan') }}
        </p>
    @else
        <div class="rw-grille" data-rw="accueil-cve">
            {{-- ══ E-269 : CES DEUX-LA VIENNENT D'UNE SEULE MACHINE ═══════════
                 `date` et `cve` sont lus sur UNE ligne de scan, donc sur une
                 machine — quel que soit le perimetre. Sous un titre de section
                 qui porte le parc, « 1458 CVE au dernier scan » se lit comme un
                 total de parc. On nomme donc la machine DES QU'ON LA CONNAIT,
                 avec repli sans nom : un libelle ne doit pas rendre « de »
                 suivi d'un trou. `critiques`, lui, agrege le perimetre et ne
                 nomme personne. --}}
            <div class="rw-tuile" data-rw="accueil-cve-date">
                <span class="rw-tuile__valeur">{{ $cve['date'] }}</span>
                <p class="rw-tuile__texte" data-rw="accueil-cve-date-libelle">{{ $cve['machine'] !== '' ? __('accueil.ind_cve_date_machine', ['machine' => $cve['machine']]) : __('accueil.ind_cve_date') }}</p>
            </div>
            <div class="rw-tuile" data-rw="accueil-cve-nombre">
                <span class="rw-tuile__valeur">{{ $cve['cve'] }}</span>
                <p class="rw-tuile__texte" data-rw="accueil-cve-nombre-libelle">{{ $cve['machine'] !== '' ? __('accueil.ind_cve_nombre_machine', ['machine' => $cve['machine']]) : __('accueil.ind_cve_nombre') }}</p>
            </div>
            <div class="rw-tuile" data-rw="accueil-cve-critiques">
                <span class="rw-tuile__valeur">{{ $cve['critiques'] }}</span>
                <p class="rw-tuile__texte">{{ __('accueil.ind_cve_critiques') }}</p>
            </div>
        </div>
    @endif

    {{-- ── LES COMPTES : BORNES PAR ROLE, ET LE GEL EST DIT ────────────────

         `null` veut dire « pas montre a ce role », jamais « zero ». Le gel vit
         dans le service, pas ici : une garde posee dans la vue serait a
         reecrire a chaque vue. --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('accueil.ind_comptes_titre') }}</h2>

    @if (! $comptes['lisible'])
        <p class="rw-annonce rw-annonce--attention" data-rw="accueil-comptes-illisible">
            {{ __('accueil.ind_illisible') }}
        </p>
    @elseif ($comptes['actifs'] === null)
        {{-- LE GEL SE DIT, AVEC SA RAISON. Un compteur absent sans explication
             se lit comme un defaut d'affichage. --}}
        <p class="rw-aide rw-prose" data-rw="accueil-comptes-reserve">
            {{ __('accueil.ind_comptes_reserve') }}
        </p>
    @else
        <div class="rw-grille" data-rw="accueil-comptes">
            <div class="rw-tuile" data-rw="accueil-comptes-actifs">
                <span class="rw-tuile__valeur">{{ $comptes['actifs'] }}</span>
                <p class="rw-tuile__texte">{{ __('accueil.ind_actifs') }}</p>
            </div>
            <div class="rw-tuile" data-rw="accueil-comptes-sans-cle">
                <span class="rw-tuile__valeur">{{ $comptes['sans_cle'] }}</span>
                <p class="rw-tuile__texte">{{ __('accueil.ind_sans_cle') }}</p>
                @if ($comptes['actifs'] > 0 && $comptes['sans_cle'] === $comptes['actifs'])
                    {{-- UN INDICATEUR SATURE SE DIT, sinon on le prend pour un
                         defaut de lecture. Il est porte quand meme : c'est le
                         seul moyen de voir qu'il cesse de l'etre. --}}
                    <p class="rw-aide" data-rw="accueil-comptes-sans-cle-sature">{{ __('accueil.ind_sans_cle_sature') }}</p>
                @endif
            </div>
            @if ($comptes['sans_2fa'] !== null)
                <div class="rw-tuile" data-rw="accueil-comptes-sans-2fa">
                    <span class="rw-tuile__valeur">{{ $comptes['sans_2fa'] }}</span>
                    <p class="rw-tuile__texte">{{ __('accueil.ind_sans_2fa') }}</p>
                    <p class="rw-aide" data-rw="accueil-comptes-sans-2fa-aide">{{ __('accueil.ind_sans_2fa_aide') }}</p>
                </div>
            @endif
        </div>
    @endif

    {{--
        ═══ LES DOUZE RACCOURCIS ═══════════════════════════════════════════

        Portes de `legacy/index.php:363-385`, dans le MEME ORDRE — un exploitant
        qui connait la page retrouve ses reperes au meme endroit.

        Le legacy recopie ONZE tests de permission pour ces douze tuiles, les
        memes que son propre menu. Ici la liste est FILTREE depuis
        `Navigation::pour()`, qui a deja applique le role, les permissions et le
        drapeau de fonctionnalite : une tuile ne peut donc pas apparaitre sans
        son entree de menu, ni viser l'ancien portail quand la page est portee.

        Le libelle vient de `nav.<cle>`, la meme cle que le menu. Le legacy en a
        deux jeux qui disent la meme chose — et deux jeux divergent.
    --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('accueil.raccourcis_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('accueil.raccourcis_aide') }}</p>

    @if (count($raccourcis) === 0)
        {{-- UN ETAT VIDE DIT CE QUI MANQUE ET POURQUOI. Une grille vide se lit
             comme un defaut d'affichage. --}}
        <div class="rw-vide" data-rw="accueil-raccourcis-vide">
            <p class="rw-prose">{{ __('accueil.raccourcis_aucun') }}</p>
        </div>
    @else
        <div class="rw-grille" data-rw="accueil-raccourcis">
            @foreach ($raccourcis as $r)
                @if (isset($r['route']))
                    <a class="rw-tuile rw-tuile--lien" data-rw="accueil-raccourci-{{ $r['cle'] }}"
                       href="{{ route($r['route']) }}">
                        <span class="rw-tuile__titre">{{ __('nav.' . $r['cle']) }}</span>
                        <p class="rw-tuile__texte">{{ __('accueil.desc_' . $r['cle']) }}</p>
                    </a>
                @else
                    {{-- MEME MARQUEUR QUE LE MENU. Un lien qui change de portail
                         sans le dire trahit celui qui clique. --}}
                    <a class="rw-tuile rw-tuile--lien" data-rw="accueil-raccourci-{{ $r['cle'] }}"
                       href="{{ rtrim(config('app.url_legacy'), '/') }}{{ $r['legacy'] }}"
                       target="_blank" rel="noopener"
                       title="{{ __('nav.' . $r['cle']) }} — {{ __('nav.non_porte_titre') }}">
                        <span class="rw-tuile__titre">{{ __('nav.' . $r['cle']) }}
                            <span aria-label="{{ __('nav.non_porte') }}">↗</span>
                        </span>
                        <p class="rw-tuile__texte">{{ __('accueil.desc_' . $r['cle']) }}</p>
                    </a>
                @endif
            @endforeach
        </div>
    @endif

    {{--
        ═══ LA SEQUENCE, DITE A L'ENDROIT OU L'ON ARRIVE ═══════════════════

        Demande de l'exploitant : « quand on ajoute un serveur, les menus ou
        aller ensuite ne sont pas evidents, et un nouvel utilisateur ne le sait
        pas. »

        LISTE NUMEROTEE, et non `rw-etapes` : ses etats `--fait`/`--courant`
        annoncent une progression, et ce guide ne suit personne. Reemployer un
        composant dont les etats mentent est le meme defaut en plus petit.

        L'ordre est l'ACQUIS : effacer le mot de passe avant d'avoir verifie la
        cle retire a RootWarden son unique moyen de revenir. C'est la meme
        correction que celle portee sur la page de la cle de plateforme, dite
        ici a l'endroit ou la question se pose pour la premiere fois.
    --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('accueil.sequence_titre') }}</h2>
    <ol class="rw-liste-effets rw-liste-effets--ordonnee rw-prose" data-rw="accueil-sequence">
        <li>{{ __('accueil.sequence_1') }}</li>
        <li>{{ __('accueil.sequence_2') }}</li>
        <li>{{ __('accueil.sequence_3') }}</li>
        <li>{{ __('accueil.sequence_4') }}</li>
    </ol>
    <p class="rw-aide rw-prose" data-rw="accueil-sequence-aide">{{ __('accueil.sequence_aide') }}</p>
@endsection
