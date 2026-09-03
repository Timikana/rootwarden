@extends('layouts.portail', ['titre' => __('appr.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('appr.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('appr.desc') }}</p>

    {{-- Les classes et identifiants sont ceux du legacy : le MEME test vise
         les deux cibles, il ne peut pas connaitre deux jeux de selecteurs. --}}
    <div class="rw-onglets" role="tablist">
        @foreach (['pending', 'approved', 'rejected', 'all'] as $statut)
            <button class="appr-tab rw-onglet @if ($statut === 'pending') rw-onglet--actif @endif"
                    type="button" role="tab" data-status="{{ $statut }}"
                    data-rw="onglet-{{ $statut }}">{{ __('appr.tab_' . $statut) }}</button>
        @endforeach
    </div>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('appr.col_action') }}</th>
                    <th>{{ __('appr.col_target') }}</th>
                    <th>{{ __('appr.col_machine') }}</th>
                    <th>{{ __('appr.col_requester') }}</th>
                    <th>{{ __('appr.col_status') }}</th>
                    <th>{{ __('appr.col_decision') }}</th>
                </tr>
            </thead>
            <tbody id="appr-tbody">
                <tr><td colspan="6" class="rw-tableau__message">{{ __('appr.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    @php($libelles = ['empty' => __('appr.empty'), 'empty_aide' => __('appr.empty_aide'), 'approve' => __('appr.approve'), 'reject' => __('appr.reject'), 'tip_approve' => __('appr.tip_approve'), 'tip_reject' => __('appr.tip_reject'), 'own_hint' => __('appr.own_hint'), 'by' => __('appr.by'), 'motif' => __('appr.motif'), 'motif_indice' => __('appr.motif_indice'), 'confirmer' => __('appr.confirmer'), 'annuler' => __('appr.annuler'), 'done' => __('appr.done'), 'err_load' => __('appr.err_load'), 'err_decide' => __('appr.err_decide')])
    {{-- @json sur UNE ligne : multiligne, il casse le PHP compile. --}}
    <script id="appr-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/approbations.js?v={{ @filemtime(public_path('js/approbations.js')) ?: '0' }}"></script>
@endsection
