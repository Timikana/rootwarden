@extends('layouts.portail', ['titre' => __('maint.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('maint.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('maint.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            {{-- L'ÉTAT, D'UN COUP D'ŒIL. Le legacy ne l'affiche nulle part : il
                 faut lire le tableau et faire le calcul de tête, alors que c'est
                 ce qui décide si les actions mutantes passent. Rendu par le
                 SERVEUR, qui a compté.

                 TROIS états et non deux : une fenêtre limitée à une machine ne
                 restreint QUE cette machine (`WHERE ... scope = 'global' OR
                 machine_id = ?`). Annoncer « flotte restreinte » dans ce cas
                 ferait chercher une panne générale là où il n'y en a pas. --}}
            @php
                $classeEtat = ['flotte' => 'rw-pastille--attente',
                               'machines' => 'rw-pastille--attente',
                               'libre' => 'rw-pastille--ok'][$etat];
                $libelleEtat = $etat === 'flotte'
                    ? __('maint.etat_restreint')
                    : ($etat === 'machines'
                        ? trans_choice('maint.etat_machines', $machinesRestreintes, ['n' => $machinesRestreintes])
                        : __('maint.etat_libre'));
            @endphp
            <span class="rw-pastille {{ $classeEtat }}"
                  data-rw="maint-etat-flotte"
                  data-rw-etat="{{ $etat }}"
                  title="{{ trans('maint.etat_detail', ['n' => $activees, 'g' => $globales]) }}">
                {{ $libelleEtat }}
            </span>
            <button class="rw-bouton" type="button" data-rw="maint-nouvelle"
                    title="{{ __('maint.tip_new') }}">{{ __('maint.btn_new') }}</button>
        </div>
    </div>

    {{-- LA LOGIQUE S'INVERSE, ET ELLE EST CONTRE-INTUITIVE.
         Le legacy la mentionne d'une demi-phrase au milieu d'un paragraphe.
         Se tromper ici bloque la flotte à l'heure où l'on en a besoin. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('maint.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('maint.guide_aucune') }}</li>
            <li>{{ __('maint.guide_une') }}</li>
            <li>{{ __('maint.guide_role') }}</li>
            <li>{{ __('maint.guide_ailleurs') }}</li>
        </ul>
    </div>

    {{-- Le formulaire est CACHÉ par l'attribut `hidden`, jamais par une classe :
         une règle `display:` sur la classe rendrait `hidden` sans effet, ce que
         le projet a déjà payé. --}}
    <div class="rw-carte" data-rw="maint-formulaire" hidden>
        <div class="rw-barre-filtres">
            <div class="rw-champ">
                <label class="rw-etiquette" for="w-name">{{ __('maint.f_name') }}</label>
                <input class="rw-saisie" id="w-name" type="text" maxlength="100"
                       data-rw="maint-nom">
            </div>
            <div class="rw-champ">
                <label class="rw-etiquette" for="w-scope">{{ __('maint.f_scope') }}</label>
                {{-- LISTE FERMÉE : la colonne est un `enum('global','machine')`. --}}
                <select class="rw-saisie" id="w-scope" data-rw="maint-portee">
                    <option value="global">{{ __('maint.scope_global') }}</option>
                    <option value="machine">{{ __('maint.scope_machine') }}</option>
                </select>
            </div>
            <div class="rw-champ" data-rw="maint-machine-bloc" hidden>
                <label class="rw-etiquette" for="w-machine">{{ __('maint.f_machine') }}</label>
                <select class="rw-saisie" id="w-machine" data-rw="maint-machine">
                    @foreach ($machines as $m)
                        <option value="{{ $m->id }}">{{ $m->name }}</option>
                    @endforeach
                </select>
            </div>
            <div class="rw-champ">
                <label class="rw-etiquette" for="w-start">{{ __('maint.f_start') }}</label>
                <input class="rw-saisie" id="w-start" type="time" value="22:00"
                       data-rw="maint-debut">
            </div>
            <div class="rw-champ">
                <label class="rw-etiquette" for="w-end">{{ __('maint.f_end') }}</label>
                <input class="rw-saisie" id="w-end" type="time" value="06:00"
                       data-rw="maint-fin">
            </div>
        </div>

        <fieldset class="rw-barre-filtres">
            <legend class="rw-etiquette">{{ __('maint.f_days') }}</legend>
            @foreach (['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as $i => $jour)
                <label class="rw-case">
                    <input type="checkbox" value="{{ $i }}" data-rw="maint-jour"
                           @checked($i < 5)>
                    {{ __('maint.' . $jour) }}
                </label>
            @endforeach
        </fieldset>

        <label class="rw-case">
            <input type="checkbox" data-rw="maint-activee" checked>
            {{ __('maint.f_enabled') }}
        </label>

        <p class="rw-aide rw-prose">{{ __('maint.overnight_hint') }}</p>

        <div class="rw-actions">
            <button class="rw-bouton rw-bouton--discret rw-actions__gauche" type="button"
                    data-rw="maint-annuler">{{ __('maint.btn_cancel') }}</button>
            <button class="rw-bouton" type="button"
                    data-rw="maint-enregistrer">{{ __('maint.btn_save') }}</button>
        </div>
    </div>

    {{-- L'HORLOGE QUI DÉCIDE, nommée seulement si elle diffère de celle du
         navigateur. Le verdict « active maintenant » vient du serveur ; quand
         son horloge n'est pas la nôtre — mesuré : UTC contre CEST — lire
         « fermée » à 07:00 est incompréhensible sans cette ligne. Posée ici
         plutôt qu'en permanence : une information toujours présente cesse
         d'être lue. Remplie par le script, `hidden` par défaut. --}}
    <p class="rw-aide rw-prose" data-rw="maint-horloge" hidden></p>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('maint.col_name') }}</th>
                    <th>{{ __('maint.col_scope') }}</th>
                    <th>{{ __('maint.col_days') }}</th>
                    <th>{{ __('maint.col_hours') }}</th>
                    <th>{{ __('maint.col_status') }}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody data-rw="maint-corps">
                <tr><td colspan="6" class="rw-vide">{{ __('maint.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" data-rw="maint-message" role="status" aria-live="polite"></p>

    <script type="application/json" id="maint-libelles">@json(__('maint'))</script>
    <script src="{{ asset('js/maintenance.js') }}?v={{ filemtime(public_path('js/maintenance.js')) }}"></script>
@endsection
