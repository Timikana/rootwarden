@extends('layouts.portail', ['titre' => __('notif.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('notif.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('notif.desc') }}</p>
            <p class="rw-sous-titre" data-rw="notif-resume">
                {{ __('notif.resume', ['nonLues' => $nonLues, 'total' => $total]) }}
            </p>
        </div>
        <div class="rw-entete-page__actions">
            <button type="button" class="rw-bouton" data-rw="notif-tout-lire"
                    @disabled($nonLues === 0)
                    title="{{ __('notif.tout_lire_tip') }}">{{ __('notif.tout_lire') }}</button>
        </div>
    </div>

    {{-- Region persistante : une bulle fugace ne dit plus, quand on relit les
         lignes, si elles datent d'avant ou d'apres. --}}
    <p class="rw-annonce" data-rw="notif-annonce" role="status" aria-live="polite"></p>

    {{-- Filtres en GET : une vue filtree se partage et se recharge. Le `type`
         est une liste FERMEE, pas une entree libre — la colonne est un
         `varchar(50)` sans contrainte, et une entree libre s'y contournerait. --}}
    <form method="get" action="{{ route('notifications') }}" class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('notif.filtre_type') }}</span>
            <select name="type" class="rw-saisie rw-saisie--compacte" data-rw="notif-filtre-type">
                <option value="">{{ __('notif.tous_types') }}</option>
                @foreach ($types as $type)
                    <option value="{{ $type }}" @selected($filtres['type'] === $type)>{{ __('notif.type_' . $type) }}</option>
                @endforeach
            </select>
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('notif.filtre_etat') }}</span>
            <select name="status" class="rw-saisie rw-saisie--compacte" data-rw="notif-filtre-etat">
                <option value="">{{ __('notif.toutes') }}</option>
                <option value="unread" @selected($filtres['etat'] === 'unread')>{{ __('notif.non_lues') }}</option>
                <option value="read" @selected($filtres['etat'] === 'read')>{{ __('notif.lues') }}</option>
            </select>
        </label>
        <button type="submit" class="rw-bouton" data-rw="notif-filtrer">{{ __('notif.filtrer') }}</button>
        <a class="rw-bouton rw-bouton--discret" href="{{ route('notifications') }}">{{ __('notif.reinitialiser') }}</a>
    </form>

    <div data-rw="notif-corps">
        @forelse ($lignes as $n)
            <article class="rw-carte rw-carte--pleine" data-rw="notif-ligne-{{ $n['id'] }}"
                     @class(['rw-notif--non-lue' => $n['read_at'] === null])>
                <div class="rw-section__entete">
                    <div>
                        {{-- Le type est NOMME. Le legacy affiche « Autre » pour les
                             trois types que les preferences gouvernent, parce que sa
                             table de libelles ne connait que ceux du chemin direct.
                             Ici la liste porte les douze, et un type inconnu sort
                             sous son nom brut : diagnosticable, contrairement a
                             « Autre ». Voir PARITE E-111. --}}
                        <span class="rw-badge rw-badge--neutre" data-rw="notif-type-{{ $n['id'] }}">
                            {{ __('notif.type_' . $n['type']) === 'notif.type_' . $n['type']
                               ? $n['type'] : __('notif.type_' . $n['type']) }}
                        </span>
                        <strong>{{ $n['title'] }}</strong>
                    </div>
                    <span class="rw-tableau__discret">{{ $n['created_at'] }}</span>
                </div>
                <p class="rw-prose">{{ $n['message'] }}</p>
                <div class="rw-actions">
                    @if ($n['read_at'] === null)
                        <span class="rw-pastille rw-pastille--info"
                              data-rw="notif-etat-{{ $n['id'] }}">{{ __('notif.non_lue') }}</span>
                    @else
                        <span class="rw-pastille rw-pastille--neutre"
                              data-rw="notif-etat-{{ $n['id'] }}">{{ __('notif.lue') }}</span>
                    @endif
                    @if ($n['link'])
                        {{-- Le chemin vient de la base : on ne pose que ce qui commence
                             par une barre, et par `setAttribute` — jamais par
                             interpolation. Un `javascript:` ne peut pas passer. --}}
                        @php($cible = preg_match('#^/[A-Za-z0-9_\-./?=&%]*$#', (string) $n['link']) === 1 ? $n['link'] : null)
                        @if ($cible)
                            <a class="rw-bouton rw-bouton--discret" href="{{ $cible }}"
                               data-rw="notif-lien-{{ $n['id'] }}">{{ __('notif.ouvrir') }}</a>
                        @endif
                    @endif
                    @if ($n['read_at'] === null)
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="notif-lire-{{ $n['id'] }}"
                                data-id="{{ $n['id'] }}">{{ __('notif.marquer_lue') }}</button>
                    @endif
                </div>
            </article>
        @empty
            <div class="rw-vide" data-rw="notif-vide">
                <p class="rw-vide__titre">{{ __('notif.vide') }}</p>
                <p class="rw-vide__texte">{{ __('notif.vide_aide') }}</p>
            </div>
        @endforelse
    </div>

    @if ($pages > 1)
        <nav class="rw-pagination" aria-label="{{ __('notif.pagination') }}">
            @php($lien = static fn (int $p): string => route('notifications', array_filter([
                'type' => $filtres['type'], 'status' => $filtres['etat'], 'page' => $p,
            ], static fn ($v) => $v !== '' && $v !== 1)))
            @if ($page > 1)
                <a class="rw-bouton rw-bouton--discret" href="{{ $lien($page - 1) }}">{{ __('notif.precedent') }}</a>
            @endif
            <span class="rw-sous-titre">{{ __('notif.page_sur', ['page' => $page, 'total' => $pages]) }}</span>
            @if ($page < $pages)
                <a class="rw-bouton rw-bouton--discret" href="{{ $lien($page + 1) }}">{{ __('notif.suivant') }}</a>
            @endif
        </nav>
    @endif

    @php($libelles = ['err_reseau' => __('notif.err_reseau'), 'tout_lu' => __('notif.tout_lu'), 'lue' => __('notif.lue'), 'rien_a_lire' => __('notif.rien_a_lire')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="notif-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/notifications.js?v={{ @filemtime(public_path('js/notifications.js')) ?: '0' }}"></script>
@endsection
