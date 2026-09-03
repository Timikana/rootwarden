@extends('layouts.portail', ['titre' => __('cmdlog.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('cmdlog.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('cmdlog.desc') }}</p>

    {{-- Les identifiants d'element sont ceux du legacy : le MEME test de
         caracterisation vise les deux cibles, il ne peut pas connaitre deux
         jeux de selecteurs. --}}
    <div class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('cmdlog.col_machine') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="f-machine" data-rw="filtre-machine">
                <option value="">{{ __('cmdlog.all_machines') }}</option>
                @foreach ($machines as $machine)
                    <option value="{{ $machine->id }}">{{ $machine->name }}</option>
                @endforeach
            </select>
        </label>

        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('cmdlog.col_context') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="f-context" data-rw="filtre-contexte">
                <option value="">{{ __('cmdlog.all_contexts') }}</option>
            </select>
        </label>

        <button class="rw-bouton rw-bouton--discret" id="refresh-btn" type="button"
                data-rw="rafraichir" title="{{ __('cmdlog.tip_refresh') }}">{{ __('cmdlog.refresh') }}</button>
    </div>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('cmdlog.col_when') }}</th>
                    <th>{{ __('cmdlog.col_machine') }}</th>
                    <th>{{ __('cmdlog.col_user') }}</th>
                    <th>{{ __('cmdlog.col_context') }}</th>
                    <th>{{ __('cmdlog.col_command') }}</th>
                    <th>{{ __('cmdlog.col_result') }}</th>
                </tr>
            </thead>
            <tbody id="cmdlog-tbody">
                <tr><td colspan="6" class="rw-tableau__message">{{ __('cmdlog.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    {{-- Les libelles que le script doit rendre sont poses ICI, en donnees :
         un script ne lit pas les fichiers de langue, et une chaine ecrite en
         dur dans le JS echappe a la parite FR/EN. --}}
    @php($libelles = ['empty' => __('cmdlog.empty'), 'empty_aide' => __('cmdlog.empty_aide'), 'failed' => __('cmdlog.failed'), 'system' => __('cmdlog.system'), 'en_cours' => __('cmdlog.en_cours'), 'err_load' => __('cmdlog.err_load')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="cmdlog-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/journal-commandes.js?v={{ @filemtime(public_path('js/journal-commandes.js')) ?: '0' }}"></script>
@endsection
