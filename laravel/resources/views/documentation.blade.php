@extends('layouts.portail', ['titre' => __('nav.documentation')])

@section('corps')
    <h1 class="rw-titre">{{ __('documentation.titre') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('documentation.desc') }}</p>

    {{--
        ⚠ LA GARDE DE CETTE PAGE EST UN SEUIL DE ROLE, PAS UNE PERMISSION.

        L'entree de menu porte `'garde' => 'tous'` : vrai de la PAGE, faux de
        son CONTENU. Le legacy n'a AUCUN `checkPermission` — sa seule
        occurrence est dans un exemple de code — et cloisonne cinq sections
        par `$isAdmin = $role >= 2`.

        Le dire est le seul moyen que la garde se lise la ou elle est : un
        lecteur qui cherche une permission n'en trouvera pas, et conclura que
        tout est ouvert.
    --}}
    <div class="rw-carte rw-carte--pleine" data-rw="doc-seuil">
        <h2 class="rw-sous-titre-fort">{{ __('documentation.seuil_titre') }}</h2>
        <p class="rw-prose">
            {{ $administration ? __('documentation.seuil_admin') : __('documentation.seuil_role1') }}
        </p>
    </div>

    {{-- ══ LE GUIDE — la seule partie TRADUITE des 1 756 lignes du legacy ══ --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('documentation.title') }}</h2>
    <p class="rw-prose">{{ __('documentation.intro') }}</p>

    <ol class="rw-liste-guide" data-rw="doc-guide">
        @foreach (range(1, 7) as $n)
            <li>
                <strong>{{ __('documentation.step' . $n . '_title') }}</strong>
                <p class="rw-prose">{{ __('documentation.step' . $n . '_text') }}</p>
            </li>
        @endforeach
    </ol>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('documentation.security_title') }}</h2>
    <ul class="rw-liste-effets" data-rw="doc-securite">
        @foreach (range(1, 5) as $n)
            <li>{{ __('documentation.sec_' . $n) }}</li>
        @endforeach
    </ul>

    {{--
        ══ LA DERIVATION, PLUTOT QUE L'AFFIRMATION ══════════════════════════

        Le legacy ecrit ses listes de routes et de droits a la main. Cette
        page-ci n'en recopie aucune : elle renvoie vers la page qui les DERIVE
        de la liste blanche reelle de la passerelle.

        La reserve qui suit n'est pas une precaution de style : une
        affirmation d'autorisation dérivée d'UNE seule couche serait fausse.
        Le produit en a trois — les decorateurs du backend, la liste blanche
        du proxy, sa liste d'administration — et elles ne coincident pas
        toujours.
    --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('documentation.derive_titre') }}</h2>
    <p class="rw-prose">{{ __('documentation.derive_texte') }}</p>
    <p class="rw-aide rw-prose" data-rw="doc-derive-reserve">{{ __('documentation.derive_reserve') }}</p>
    {{-- Le lien n'est offert que si la page qu'il vise est OUVERTE a ce
         compte — elle est gardee `role:3`, pas `role:2`. La condition vient
         du menu, pas du seuil de cette page-ci : offrir une porte qui refuse
         est le defaut qu'on evite ailleurs par la meme derivation. --}}
    @if ($lienDerive !== null)
        <p class="rw-tuile__lien">
            <a class="rw-lien" href="{{ $lienDerive }}"
               data-rw="doc-derive-lien">{{ __('documentation.derive_lien') }}</a>
        </p>
    @endif

    {{-- ══ CE QUI N'EST PAS RECOPIE, ET LA MESURE QUI LE JUSTIFIE ══════════ --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('documentation.reste_titre') }}</h2>
    <p class="rw-prose">{{ __('documentation.reste_texte') }}</p>
    <p class="rw-prose" data-rw="doc-reste-perime">{{ __('documentation.reste_perime') }}</p>
    <p class="rw-prose" data-rw="doc-reste-cache">{{ __('documentation.reste_cache') }}</p>
    <p class="rw-tuile__lien">
        @if ($lienLegacy)
            <a class="rw-lien" href="{{ $lienLegacy }}" target="_blank" rel="noopener"
               data-rw="doc-reste-lien">{{ __('documentation.reste_ouvrir') }} ↗</a>
        @endif
    </p>

    @if ($administration)
        {{--
            LA CONSOLE D'API N'EST PAS REPRISE — decision rendue, pas un oubli.

            Elle n'eleve AUCUN privilege : le proxy applique sa liste blanche
            et sa reserve d'administration, le backend ses decorateurs. Ce
            qu'elle contourne est l'INTERFACE — aucun panneau de decision,
            aucune machine nommee, pour des gestes qui en portent un sur leurs
            pages propres.

            Visible au seul role >= 2, parce que la section qu'elle remplace
            l'etait aussi : annoncer a un role 1 le retrait d'une chose qu'il
            n'a jamais vue ne lui apprend rien.
        --}}
        <h2 class="rw-section__entete rw-titre--espace">{{ __('documentation.console_titre') }}</h2>
        <p class="rw-prose" data-rw="doc-console">{{ __('documentation.console_texte') }}</p>
    @endif
@endsection
