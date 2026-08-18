@extends('layouts.portail', ['titre' => __('tickets.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('tickets.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('tickets.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton" id="new-ticket-btn" type="button"
                    data-rw="nouveau" title="{{ __('tickets.tip_new') }}">{{ __('tickets.btn_new') }}</button>
        </div>
    </div>

    {{-- Guidage. Le legacy annonce que le dedoublonnage evite « plusieurs
         tickets pour la meme alerte » ; la cle reelle est (source, reference,
         machine), ce qui pour un ticket manuel revient a la machine seule. Le
         dire ici evite de croire creer un ticket qu'on ne cree pas. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('tickets.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('tickets.guide_local') }}</li>
            <li>{{ __('tickets.guide_dedup') }}</li>
            <li>{{ __('tickets.guide_cve') }}</li>
        </ul>
    </div>

    <p id="tickets-status" data-rw="fournisseur"></p>

    {{-- Formulaire de creation manuelle. `hidden` plutot qu'une classe : l'etat
         se lit alors sur la geometrie, ce qu'un test mesure sans connaitre nos
         conventions de nommage. --}}
    <form class="rw-carte rw-carte--pleine" id="ticket-form" data-rw="formulaire" hidden onsubmit="return false;">
        <div class="rw-grille rw-grille--compacte">
            <label class="rw-champ">
                <span class="rw-champ__etiquette">{{ __('tickets.f_summary') }}</span>
                <input type="text" id="t-summary" maxlength="255" class="rw-saisie"
                       data-rw="resume" autocomplete="off">
                <span class="rw-aide">{{ __('tickets.f_summary_aide') }}</span>
            </label>

            <label class="rw-champ">
                <span class="rw-champ__etiquette">{{ __('tickets.f_machine') }}</span>
                <select id="t-machine" class="rw-saisie" data-rw="machine">
                    <option value="">{{ __('tickets.no_machine') }}</option>
                    @foreach ($machines as $machine)
                        <option value="{{ $machine->id }}">{{ $machine->name }}</option>
                    @endforeach
                </select>
                <span class="rw-aide">{{ __('tickets.f_machine_aide') }}</span>
            </label>
        </div>

        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('tickets.f_desc') }}</span>
            <textarea id="t-desc" rows="3" class="rw-saisie" data-rw="description"></textarea>
            <span class="rw-aide">{{ __('tickets.f_desc_aide') }}</span>
        </label>

        {{-- Collision annoncee AVANT le clic, pas apres. --}}
        <p class="rw-annonce" id="t-collision" role="status" aria-live="polite" data-rw="collision"></p>

        <div class="rw-actions">
            <button class="rw-bouton rw-bouton--discret rw-actions__gauche" id="t-cancel" type="button"
                    data-rw="annuler">{{ __('tickets.btn_cancel') }}</button>
            <button class="rw-bouton" id="t-save" type="button" data-rw="creer"
                    title="{{ __('tickets.tip_create') }}" disabled>{{ __('tickets.btn_create') }}</button>
        </div>
    </form>

    {{-- Les identifiants d'element sont ceux du legacy : le MEME test de
         caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('tickets.col_when') }}</th>
                    <th>{{ __('tickets.col_source') }}</th>
                    <th>{{ __('tickets.col_summary') }}</th>
                    <th>{{ __('tickets.col_machine') }}</th>
                    <th>{{ __('tickets.col_provider') }}</th>
                    <th>{{ __('tickets.col_ref') }}</th>
                </tr>
            </thead>
            <tbody id="tickets-tbody">
                <tr><td colspan="6" class="rw-tableau__message">{{ __('tickets.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" id="tickets-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    @php($libelles = ['provider_on' => __('tickets.provider_on'), 'provider_off' => __('tickets.provider_off'), 'empty' => __('tickets.empty'), 'empty_aide' => __('tickets.empty_aide'), 'created' => __('tickets.created'), 'deduped' => __('tickets.deduped'), 'collision' => __('tickets.collision'), 'err_load' => __('tickets.err_load'), 'err_create' => __('tickets.err_create'), 'err_summary' => __('tickets.err_summary'), 'no_machine' => __('tickets.no_machine')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="tickets-libelles" type="application/json">@json($libelles)</script>

    <script src="/js/tickets.js?v={{ @filemtime(public_path('js/tickets.js')) ?: '0' }}"></script>
@endsection
