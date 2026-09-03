@extends('layouts.portail', ['titre' => __('backup.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('backup.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('backup.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton" id="create-btn" type="button"
                    data-rw="creer" title="{{ __('backup.tip_create') }}">{{ __('backup.btn_create') }}</button>
        </div>
    </div>

    {{-- Guidage. Le legacy porte le meme encart, mais y annonce que le controle
         « recharge la sauvegarde dans une base temporaire ». Le code ne le fait
         pas : il lit le fichier et compte les tables, sans executer une seule
         instruction. Le libelle dit ici ce que le controle fait vraiment — et
         surtout ce qu'il ne prouve pas. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('backup.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('backup.guide_creer') }}</li>
            <li>{{ __('backup.guide_controler') }}</li>
            <li>{{ __('backup.guide_restaurer') }}</li>
        </ul>
    </div>

    @if ($estSuperadmin)
        <p class="rw-erreur rw-prose" data-rw="avertissement-restauration">{{ __('backup.restore_warning') }}</p>
    @endif

    {{-- Les identifiants d'element sont ceux du legacy : le MEME test de
         caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('backup.col_file') }}</th>
                    <th>{{ __('backup.col_size') }}</th>
                    <th>{{ __('backup.col_date') }}</th>
                    <th>{{ __('backup.col_action') }}</th>
                </tr>
            </thead>
            <tbody id="backup-tbody">
                <tr><td colspan="4" class="rw-tableau__message">{{ __('backup.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" id="backup-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    @php($libelles = ['verify' => __('backup.verify'), 'tip_verify' => __('backup.tip_verify'), 'restore' => __('backup.restore'), 'tip_restore' => __('backup.tip_restore'), 'restore_titre' => __('backup.restore_titre'), 'restore_aide' => __('backup.restore_aide'), 'restore_nom' => __('backup.restore_nom'), 'restore_confirmer' => __('backup.restore_confirmer'), 'restore_annuler' => __('backup.restore_annuler'), 'creating' => __('backup.creating'), 'created' => __('backup.created'), 'verifying' => __('backup.verifying'), 'verify_ok' => __('backup.verify_ok'), 'verify_fail' => __('backup.verify_fail'), 'sha_ok' => __('backup.sha_ok'), 'sha_ko' => __('backup.sha_ko'), 'sha_absente' => __('backup.sha_absente'), 'tables' => __('backup.tables'), 'instructions' => __('backup.instructions'), 'restoring' => __('backup.restoring'), 'restore_ok' => __('backup.restore_ok'), 'empty' => __('backup.empty'), 'empty_aide' => __('backup.empty_aide'), 'err_load' => __('backup.err_load'), 'err_create' => __('backup.err_create'), 'err_restore' => __('backup.err_restore')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="backup-libelles" type="application/json">@json($libelles)</script>
    <script id="backup-superadmin" type="application/json">@json($estSuperadmin)</script>

    <script src="/js/sauvegardes.js?v={{ @filemtime(public_path('js/sauvegardes.js')) ?: '0' }}"></script>
@endsection
