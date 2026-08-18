@extends('layouts.portail', ['titre' => __('maj.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('maj.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('maj.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton rw-bouton--discret" id="refresh-list-btn" type="button"
                    data-rw="rafraichir" title="{{ __('maj.tip_refresh') }}">{{ __('maj.btn_refresh') }}</button>
        </div>
    </div>

    {{-- Portage PARTIEL, dit a l'ecran. Un module qu'on porte par morceaux
         laisse forcement des capacites derriere lui : les faire disparaitre
         sans un mot ferait croire qu'elles n'existent plus. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('maj.partiel_titre') }}</strong>
        <p class="rw-tuile__texte">{{ __('maj.partiel_texte') }}</p>
        <p class="rw-tuile__lien">
            <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/update/"
               target="_blank" rel="noopener" data-rw="vers-legacy">{{ __('maj.partiel_lien') }} ↗</a>
        </p>
    </div>

    <div class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_environment') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="environment" data-rw="f-environnement">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['PROD', 'DEV', 'TEST', 'OTHER'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_criticality') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="criticality" data-rw="f-criticite">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['CRITIQUE', 'NON CRITIQUE'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_network') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="network-type" data-rw="f-reseau">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['INTERNE', 'EXTERNE'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        <button class="rw-bouton rw-bouton--discret" id="filter-btn" type="button"
                data-rw="filtrer">{{ __('maj.btn_filter') }}</button>
    </div>

    {{-- Les identifiants et les CLASSES de colonne sont ceux du legacy
         (`server-table-body`, `.linux-version`, `.maj-secu-date`...) : le MEME
         test de caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('maj.th_selection') }}</th>
                    <th>{{ __('maj.th_name') }}</th>
                    <th>{{ __('maj.th_linux') }}</th>
                    <th>{{ __('maj.th_last_check') }}</th>
                    <th>{{ __('maj.th_ip_port') }}</th>
                    <th>{{ __('maj.th_status') }}</th>
                    <th>{{ __('maj.th_secu_schedule') }}</th>
                    <th>{{ __('maj.th_last_exec') }}</th>
                    <th>{{ __('maj.th_last_reboot') }}</th>
                    <th>{{ __('maj.th_env') }}</th>
                    <th>{{ __('maj.th_criticality') }}</th>
                    <th>{{ __('maj.th_network') }}</th>
                    <th>{{ __('maj.th_actions') }}</th>
                </tr>
            </thead>
            <tbody id="server-table-body"></tbody>
        </table>
    </div>

    <p class="rw-annonce" id="maj-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    {{-- Le parc est rendu par le script a partir de ces donnees : le MEME code
         sert le premier rendu et les suivants, il ne peut donc pas exister deux
         versions du tableau qui divergent. --}}
    <script id="maj-parc" type="application/json">@json($machines)</script>
    @php($libelles = ['non_verifie' => __('maj.non_verifie'), 'inconnu' => __('maj.inconnu'), 'aucune' => __('maj.aucune'), 'en_cours' => __('maj.en_cours'), 'btn_version' => __('maj.btn_version'), 'tip_version' => __('maj.tip_version'), 'btn_statut' => __('maj.btn_statut'), 'tip_statut' => __('maj.tip_statut'), 'btn_reboot' => __('maj.btn_reboot'), 'tip_reboot' => __('maj.tip_reboot'), 'vide' => __('maj.vide'), 'vide_aide' => __('maj.vide_aide'), 'vide_filtre' => __('maj.vide_filtre'), 'vide_filtre_aide' => __('maj.vide_filtre_aide'), 'maj_ok' => __('maj.maj_ok'), 'filtre_ok' => __('maj.filtre_ok'), 'err_load' => __('maj.err_load'), 'err_releve' => __('maj.err_releve'), 'releve_ok' => __('maj.releve_ok')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="maj-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/mises-a-jour.js?v={{ @filemtime(public_path('js/mises-a-jour.js')) ?: '0' }}"></script>
@endsection
