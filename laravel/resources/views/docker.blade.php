@extends('layouts.portail', ['titre' => __('docker.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('docker.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('docker.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <select class="rw-saisie" data-rw="docker-machine" id="scan-machine"
                    aria-label="{{ __('docker.machine_libelle') }}">
                @foreach ($machines as $m)
                    <option value="{{ $m->id }}">{{ $m->name }}</option>
                @endforeach
            </select>
            <button class="rw-bouton" type="button" data-rw="docker-scan-un"
                    title="{{ __('docker.tip_scan_one') }}">{{ __('docker.btn_scan_one') }}</button>
            <button class="rw-bouton rw-bouton--discret" type="button" data-rw="docker-scan-tout"
                    title="{{ __('docker.tip_scan_all') }}">{{ __('docker.btn_scan_all') }}</button>
        </div>
    </div>

    {{-- LE GUIDAGE DIT CE QUE LE GESTE FAIT VRAIMENT.
         Le legacy presente « scanner » comme une simple lecture. Ce n'en est pas
         une : le backend ouvre une session SSH, lance un `git fetch` dans chaque
         depot de projet compose, et interroge le registre distant. Et « tout
         scanner » vise TOUTES les machines, production comprise. Nommer la
         production sur le geste qui coute. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('docker.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('docker.guide_lecture') }}</li>
            <li>{{ __('docker.guide_scan') }}</li>
            <li>{{ __('docker.guide_scan_tout') }}</li>
        </ul>
    </div>

    <div class="rw-grille rw-grille--compacte" data-rw="docker-synthese" id="docker-summary"></div>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('docker.col_machine') }}</th>
                    <th>{{ __('docker.col_container') }}</th>
                    <th>{{ __('docker.col_image') }}</th>
                    <th>{{ __('docker.col_state') }}</th>
                    <th title="{{ __('docker.tip_col_image_update') }}">{{ __('docker.col_image_update') }}</th>
                    <th title="{{ __('docker.tip_col_git') }}">{{ __('docker.col_git') }}</th>
                    <th>{{ __('docker.col_checked') }}</th>
                </tr>
            </thead>
            <tbody data-rw="docker-corps" id="docker-tbody">
                <tr><td colspan="7" class="rw-vide">{{ __('docker.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" data-rw="docker-message" role="status" aria-live="polite"></p>

    {{-- Les libelles affiches par le script sont poses EN DONNEES : une chaine
         ecrite en dur dans du JS echappe a la parite FR/EN. `@json` sur UNE
         ligne — multiligne, il casse le PHP compile. --}}
    <script type="application/json" id="docker-libelles">@json(__('docker'))</script>
    <script src="{{ asset('js/docker.js') }}?v={{ filemtime(public_path('js/docker.js')) }}"></script>
@endsection
