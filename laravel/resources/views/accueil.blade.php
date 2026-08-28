@extends('layouts.portail', ['titre' => __('nav.dashboard')])

@section('corps')
    <h1 class="rw-titre">{{ __('accueil.bienvenue', ['nom' => session('utilisateur_nom')]) }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('accueil.orientation') }}</p>

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

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('accueil.ancien_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('accueil.ancien_texte') }}</p>
            <p class="rw-tuile__lien">
                <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/index.php"
                   target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
            </p>
        </div>


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
        <span class="rw-tuile__titre">{{ __('accueil.parc_compteur_titre') }}</span>
        @if (! $parc['lisible'])
            {{-- UNE BASE INJOIGNABLE N'EST PAS UN PARC VIDE. Afficher « 0 · 0 »
                 se lirait comme un fait. --}}
            <p class="rw-tuile__texte" data-rw="accueil-parc-illisible">{{ __('accueil.parc_illisible') }}</p>
        @else
            <span class="rw-tuile__valeur" data-rw="accueil-parc-valeur">
                {{ trans_choice('accueil.parc_perimetre', $parc['perimetre']) }}
                @if ($parc['borne'])
                    <span class="rw-tuile__appoint">· {{ trans_choice('accueil.parc_total', $parc['parc']) }}</span>
                @endif
            </span>
            @if ($parc['borne'])
                <p class="rw-tuile__texte" data-rw="accueil-parc-borne">{{ __('accueil.parc_borne_aide') }}</p>
            @endif
        @endif
    </div>

    </div>{{-- fin de la grille des tuiles d'etat --}}

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
