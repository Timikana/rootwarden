@extends('layouts.portail', ['titre' => __('drift.title')])

@section('corps')
    {{-- Titre a gauche, action principale a DROITE. Le legacy la place aussi
         a droite ; ce qui change ici, c'est qu'elle porte son effet dans son
         infobulle — « scanner tout le parc » sur un parc de production merite
         qu'on sache avant de cliquer que rien n'est joint. --}}
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('drift.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('drift.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton" id="scan-all-btn" type="button"
                    data-rw="scan-tout" title="{{ __('drift.tip_scan_all') }}">{{ __('drift.btn_scan_all') }}</button>
        </div>
    </div>

    {{-- Resume : quatre tuiles. `rw-grille` les etale sur toute la largeur. --}}
    <div class="rw-grille rw-grille--compacte" id="drift-summary"></div>

    {{-- Les identifiants d'element sont ceux du legacy : le MEME test de
         caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('drift.col_server') }}</th>
                    <th>{{ __('drift.col_sudo') }}</th>
                    <th>{{ __('drift.col_sshd') }}</th>
                    <th>{{ __('drift.col_fail2ban') }}</th>
                    <th>{{ __('drift.col_checked') }}</th>
                    <th>{{ __('drift.col_action') }}</th>
                </tr>
            </thead>
            <tbody id="drift-tbody">
                <tr><td colspan="6" class="rw-tableau__message">{{ __('drift.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    {{-- Region d'annonce : elle remplace les bulles fugaces du legacy, qui
         disparaissent avant d'etre lues et qu'aucun lecteur d'ecran n'annonce. --}}
    <p class="rw-annonce" id="drift-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    @php($libelles = ['status_ok' => __('drift.status_ok'), 'status_drift' => __('drift.status_drift'), 'status_unknown' => __('drift.status_unknown'), 'status_absent' => __('drift.status_absent'), 'sum_servers' => __('drift.sum_servers'), 'sum_clean' => __('drift.sum_clean'), 'sum_drifted' => __('drift.sum_drifted'), 'sum_findings' => __('drift.sum_findings'), 'sum_servers_aide' => __('drift.sum_servers_aide'), 'sum_clean_aide' => __('drift.sum_clean_aide'), 'sum_drifted_aide' => __('drift.sum_drifted_aide'), 'sum_findings_aide' => __('drift.sum_findings_aide'), 'btn_rescan' => __('drift.btn_rescan'), 'tip_rescan' => __('drift.tip_rescan'), 'scanning' => __('drift.scanning'), 'scanned' => __('drift.scanned'), 'scan_done' => __('drift.scan_done'), 'empty' => __('drift.empty'), 'empty_aide' => __('drift.empty_aide'), 'never' => __('drift.never'), 'err_load' => __('drift.err_load'), 'err_scan' => __('drift.err_scan')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="drift-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/derive-config.js?v={{ @filemtime(public_path('js/derive-config.js')) ?: '0' }}"></script>
@endsection
