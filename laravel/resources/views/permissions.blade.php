@extends('layouts.portail', ['titre' => __('perms.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('perms.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('perms.desc') }}</p>

    {{-- UNE SEULE LISTE, ET ELLE VIENT DU SCHEMA. Le legacy en porte trois — 18
         colonnes, 14 posables a la creation, 16 basculables — et les ecarts se
         croisent : une permission s'accorde sans se reprendre, une autre
         n'existe ni a la creation ni a la bascule (PARITE E-118). --}}
    <div class="rw-encart" data-rw="perms-source">
        <p class="rw-prose">{{ __('perms.source', ['nombre' => count($permissions)]) }}</p>
    </div>

    <p class="rw-annonce" data-rw="perms-annonce" role="status" aria-live="polite"></p>

    {{-- Le panneau de re-authentification, le MEME que D4. C'est lui qui rend la
         garde franchissable : le legacy l'exige et n'offre aucun moyen d'y
         repondre (E-119). --}}
    <div class="rw-panneau-decision" data-rw="perms-panneau-stepup" hidden>
        <p class="rw-panneau-decision__texte">{{ __('perms.step_up_titre') }}</p>
        <p class="rw-aide">{{ __('perms.step_up_aide') }}</p>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('perms.step_up_code') }}</span>
            <input type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code"
                   class="rw-saisie rw-saisie--code" data-rw="perms-stepup-code">
        </label>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="perms-stepup-annuler">{{ __('perms.annuler') }}</button>
            <button type="button" class="rw-bouton"
                    data-rw="perms-stepup-valider">{{ __('perms.step_up_valider') }}</button>
        </div>
    </div>

    @foreach ($comptes as $c)
        <section class="rw-carte rw-carte--pleine">
            <details data-rw="perms-carte-{{ $c['id'] }}">
                <summary class="rw-sous-titre-fort">
                    {{ $c['name'] }}
                    <span class="rw-badge rw-badge--neutre">{{ __('perms.role_' . $c['role_id']) }}</span>
                    <span class="rw-tableau__discret">{{ __('perms.compte_resume', [
                        'droits' => count(array_filter($droits[$c['id']])),
                        'machines' => count($acces[$c['id']]),
                    ]) }}</span>
                </summary>

                <p class="rw-sous-titre-fort">{{ __('perms.droits') }}</p>
                <div class="rw-grille rw-grille--compacte">
                    @foreach ($permissions as $perm)
                        <label class="rw-liste-selection__etiquette">
                            <input type="checkbox"
                                   data-rw="perm-{{ $perm }}-{{ $c['id'] }}"
                                   data-user-id="{{ $c['id'] }}"
                                   data-permission="{{ $perm }}"
                                   @checked($droits[$c['id']][$perm])>
                            <span class="rw-liste-selection__nom">
                                {{ __('perms.p_' . $perm) === 'perms.p_' . $perm ? $perm : __('perms.p_' . $perm) }}
                            </span>
                        </label>
                    @endforeach
                </div>

                <p class="rw-sous-titre-fort">{{ __('perms.acces') }}</p>
                <div class="rw-grille rw-grille--compacte">
                    @foreach ($machines as $m)
                        <label class="rw-liste-selection__etiquette">
                            <input type="checkbox"
                                   data-rw="acces-{{ $m->id }}-{{ $c['id'] }}"
                                   data-user-id="{{ $c['id'] }}"
                                   data-machine-id="{{ $m->id }}"
                                   @checked(in_array((int) $m->id, $acces[$c['id']], true))>
                            <span class="rw-liste-selection__nom">{{ $m->name }}</span>
                        </label>
                    @endforeach
                </div>
            </details>
        </section>
    @endforeach

    @php($libelles = ['err_reseau' => __('perms.err_reseau')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="perms-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/permissions.js?v={{ @filemtime(public_path('js/permissions.js')) ?: '0' }}"></script>
@endsection
