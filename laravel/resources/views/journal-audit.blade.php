@extends('layouts.portail', ['titre' => __('audit.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('audit.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('audit.desc') }}</p>
            {{-- Le gabarit est SUBSTITUE. Le legacy affiche « 4 179 :count
                 entrees au total » — sa fonction `t()` ne remplace rien, et les
                 deux langues portaient le defaut. Voir PARITE E-105. --}}
            <p class="rw-sous-titre" data-rw="audit-total">
                {{ __('audit.entries_total', ['nombre' => $nombreFormate]) }}
                @if ($filtre)
                    <span class="rw-badge rw-badge--neutre">{{ __('audit.filtered') }}</span>
                @endif
            </p>
        </div>

        <div class="rw-entete-page__actions">
            @if ($peutSceller)
                {{-- Reserve au role 3, comme le legacy. Ici la reserve est aussi
                     posee sur les ROUTES : le legacy ne cache que les boutons. --}}
                <button type="button" class="rw-bouton" data-rw="audit-verifier"
                        title="{{ __('audit.btn_verify_tip') }}">{{ __('audit.btn_verify') }}</button>
                {{-- Le bouton « Sceller » a ete RETIRE le 2026-09-05 (arbitrage E-415).
                     Les lignes non chainees le sont PAR CONSTRUCTION : les rattacher
                     exigerait de reecrire le `prev_hash` de toutes les autres, donc de
                     detruire la propriete que la chaine porte. L'etat se DIT ; il ne se
                     repare pas. --}}
                <span class="rw-etiquette rw-etiquette--neutre" data-rw="audit-scellement-etat"
                      title="{{ __('audit.scellement_impossible_tip') }}">{{ __('audit.scellement_impossible') }}</span>
            @endif
            <a class="rw-bouton rw-bouton--discret" data-rw="audit-export-csv"
               href="{{ route('journal-audit.csv', array_filter([
                        'user' => $filtres['utilisateur'], 'action' => $filtres['action'],
                        'from' => $filtres['du'], 'to' => $filtres['au'],
                    ], static fn ($v) => $v !== '')) }}"
               title="{{ __('audit.export_hint') }}">{{ __('audit.btn_export_csv') }}</a>
        </div>
    </div>

    {{-- Region d'annonce persistante : une bulle fugace ne dit plus, quand on
         relit les valeurs, si elles datent d'avant ou d'apres. --}}
    <p class="rw-annonce" data-rw="audit-resultat" role="status" aria-live="polite"></p>

    {{-- Le panneau de decision du scellement a ete retire avec le bouton.
         `journal-audit.js` garde ses deux acces (`if (btnSceller)`, `if (panneau)`),
         donc la page se degrade sans erreur. --}}

    {{-- Un vrai formulaire GET : les filtres vivent dans l'adresse, donc une
         page filtree se partage et se recharge. Les noms de champ sont ceux du
         legacy (`user`, `action`, `from`, `to`) — le MEME test vise les deux
         cibles, il ne peut pas connaitre deux jeux de noms. --}}
    <form method="get" action="{{ route('journal-audit') }}" class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('audit.filter_user') }}</span>
            <input type="text" name="user" value="{{ $filtres['utilisateur'] }}"
                   class="rw-saisie rw-saisie--compacte" data-rw="audit-filtre-utilisateur"
                   placeholder="{{ __('audit.placeholder_name') }}">
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('audit.filter_action') }}</span>
            <input type="text" name="action" value="{{ $filtres['action'] }}"
                   class="rw-saisie rw-saisie--compacte" data-rw="audit-filtre-action"
                   placeholder="{{ __('audit.placeholder_action') }}">
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('audit.filter_from') }}</span>
            <input type="date" name="from" value="{{ $filtres['du'] }}"
                   class="rw-saisie rw-saisie--compacte" data-rw="audit-filtre-du">
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('audit.filter_to') }}</span>
            <input type="date" name="to" value="{{ $filtres['au'] }}"
                   class="rw-saisie rw-saisie--compacte" data-rw="audit-filtre-au">
        </label>
        <button type="submit" class="rw-bouton" data-rw="audit-filtrer">{{ __('audit.filtrer') }}</button>
        <a class="rw-bouton rw-bouton--discret" data-rw="audit-reinitialiser"
           href="{{ route('journal-audit') }}">{{ __('audit.reinitialiser') }}</a>
    </form>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    {{-- Sous 720 px, l'identifiant CEDE : c'est une poignee, pas
                         une donnee de lecture, et c'est la colonne ACTION qui
                         porte le sens d'un journal d'audit. Meme motif que la
                         colonne IP du rapport de conformite. --}}
                    <th class="rw-colonne-secondaire">{{ __('audit.col_id') }}</th>
                    <th>{{ __('audit.col_date') }}</th>
                    <th>{{ __('audit.col_utilisateur') }}</th>
                    <th>{{ __('audit.col_action') }}</th>
                </tr>
            </thead>
            <tbody data-rw="audit-corps">
                @forelse ($lignes as $ligne)
                    <tr>
                        <td class="rw-tableau__discret rw-colonne-secondaire">#{{ $ligne['id'] }}</td>
                        <td class="rw-tableau__fort">{{ $ligne['created_at'] }}</td>
                        <td>{{ $ligne['utilisateur'] }}</td>
                        <td>{{ $ligne['action'] }}</td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="4" class="rw-tableau__message">
                            <span class="rw-tableau__message-titre">{{ __('audit.empty') }}</span>
                            <span class="rw-tableau__message-aide">{{ __('audit.empty_aide') }}</span>
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>

    @if ($pages > 1)
        <nav class="rw-pagination" data-rw="audit-pagination" aria-label="{{ __('audit.pagination') }}">
            @php($lien = static fn (int $p): string => route('journal-audit', array_filter([
                'user' => $filtres['utilisateur'], 'action' => $filtres['action'],
                'from' => $filtres['du'], 'to' => $filtres['au'], 'page' => $p,
            ], static fn ($v) => $v !== '' && $v !== 1)))
            @if ($page > 1)
                <a class="rw-bouton rw-bouton--discret" data-rw="audit-page-precedente"
                   href="{{ $lien($page - 1) }}">{{ __('audit.precedent') }}</a>
            @endif
            <span class="rw-sous-titre">{{ __('audit.page_sur', ['page' => $page, 'total' => $pages]) }}</span>
            @if ($page < $pages)
                <a class="rw-bouton rw-bouton--discret" data-rw="audit-page-suivante"
                   href="{{ $lien($page + 1) }}">{{ __('audit.suivant') }}</a>
            @endif
        </nav>
    @endif

    {{-- Les libelles que le script rend sont poses ICI, en donnees : une chaine
         ecrite en dur dans le JS echappe a la parite FR/EN — c'est exactement le
         defaut E-107 du legacy, dont les six verdicts sont en francais fixe. --}}
    @php($libelles = ['verif_en_cours' => __('audit.verif_en_cours'), 'chaine_intacte' => __('audit.chaine_intacte'), 'chaine_rompue' => __('audit.chaine_rompue'), 'sceller_titre' => __('audit.sceller_titre'), 'sceller_rien' => __('audit.sceller_rien'), 'sceller_consigne' => __('audit.sceller_consigne'), 'sceller_en_cours' => __('audit.sceller_en_cours'), 'sceller_fait' => __('audit.sceller_fait'), 'sceller_refus' => __('audit.sceller_refus'), 'err_reseau' => __('audit.err_reseau')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="audit-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/journal-audit.js?v={{ @filemtime(public_path('js/journal-audit.js')) ?: '0' }}"></script>
@endsection
