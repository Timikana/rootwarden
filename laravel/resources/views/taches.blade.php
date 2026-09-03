@extends('layouts.portail', ['titre' => __('tasks.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('tasks.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('tasks.desc') }}</p>
        </div>

        {{-- Ces deux commandes ne sont pas des actions : elles reglent la vue.
             Elles restent donc a droite du titre, sans l'accent d'un bouton
             principal. La case dit sa PERIODE : « Rafraichir auto » ne permet
             pas de savoir si ce qu'on lit date de 5 s ou de 5 min. --}}
        <div class="rw-entete-page__actions">
            <label class="rw-filtre">
                <span class="rw-filtre__etiquette">{{ __('tasks.filter_label') }}</span>
                <select class="rw-saisie rw-saisie--compacte" id="task-filter" data-rw="filtre-statut">
                    <option value="">{{ __('tasks.filter_all') }}</option>
                    <option value="running">{{ __('tasks.st_running') }}</option>
                    <option value="success">{{ __('tasks.st_success') }}</option>
                    <option value="error">{{ __('tasks.st_error') }}</option>
                </select>
            </label>
            <label class="rw-case" title="{{ __('tasks.tip_autorefresh') }}">
                <input type="checkbox" id="task-autorefresh" data-rw="auto" checked>
                <span>{{ __('tasks.autorefresh') }}</span>
            </label>
        </div>
    </div>

    <div class="rw-grille rw-grille--compacte" id="task-stats"></div>

    {{-- Les identifiants d'element sont ceux du legacy : le MEME test de
         caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('tasks.col_status') }}</th>
                    <th>{{ __('tasks.col_type') }}</th>
                    <th>{{ __('tasks.col_label') }}</th>
                    <th>{{ __('tasks.col_started') }}</th>
                    <th>{{ __('tasks.col_duration') }}</th>
                </tr>
            </thead>
            <tbody id="task-tbody">
                <tr><td colspan="5" class="rw-tableau__message">{{ __('tasks.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" id="task-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    @php($libelles = ['st_running' => __('tasks.st_running'), 'st_success' => __('tasks.st_success'), 'st_error' => __('tasks.st_error'), 'st_pending' => __('tasks.st_pending'), 'sum_running_now' => __('tasks.sum_running_now'), 'sum_success_24h' => __('tasks.sum_success_24h'), 'sum_error_24h' => __('tasks.sum_error_24h'), 'sum_total_24h' => __('tasks.sum_total_24h'), 'sum_running_aide' => __('tasks.sum_running_aide'), 'sum_success_aide' => __('tasks.sum_success_aide'), 'sum_error_aide' => __('tasks.sum_error_aide'), 'sum_total_aide' => __('tasks.sum_total_aide'), 'empty' => __('tasks.empty'), 'empty_aide' => __('tasks.empty_aide'), 'empty_filtre' => __('tasks.empty_filtre'), 'empty_filtre_aide' => __('tasks.empty_filtre_aide'), 'err_load' => __('tasks.err_load'), 'err_filtre' => __('tasks.err_filtre'), 'err_stats' => __('tasks.err_stats'), 'derniere_maj' => __('tasks.derniere_maj')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="task-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/taches.js?v={{ @filemtime(public_path('js/taches.js')) ?: '0' }}"></script>
@endsection
