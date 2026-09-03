@extends('layouts.portail', ['titre' => __('notif.reglages_titre')])

@section('corps')
    <h1 class="rw-titre">{{ __('notif.reglages_titre') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('notif.reglages_desc') }}</p>

    {{-- UNE REGLE APPLIQUEE AILLEURS SE REND VISIBLE. Cinq types sont emis par
         `notify()` / `notify_admins()`, qui n'ouvrent JAMAIS
         `notification_preferences` (`backend/notify.py:26-66`) : aucun reglage
         de cette page ne les gouverne. Le legacy ne le dit nulle part, et sa
         page laisse croire le contraire. Voir PARITE E-111. --}}
    <div class="rw-encart" data-rw="notif-reserve">
        <p><strong>{{ __('notif.reserve_titre') }}</strong></p>
        <p class="rw-prose">{{ __('notif.reserve_texte') }}</p>
        <p class="rw-prose">
            @foreach ($inconditionnels as $type)
                <span class="rw-badge rw-badge--neutre">{{ __('notif.type_' . $type) }}</span>
            @endforeach
        </p>
    </div>

    <p class="rw-annonce" data-rw="notif-reglages-annonce" role="status" aria-live="polite"></p>

    @foreach ($comptes as $compte)
        <section class="rw-carte rw-carte--pleine">
            <div class="rw-section__entete">
                <strong>{{ $compte['name'] }}</strong>
                <span class="rw-tableau__discret">{{ __('notif.role_' . $compte['role_id']) }}</span>
            </div>
            <div class="rw-grille rw-grille--compacte">
                @foreach ($reglables as $type)
                    <label class="rw-liste-selection__etiquette">
                        <input type="checkbox"
                               data-user-id="{{ $compte['id'] }}"
                               data-event-type="{{ $type }}"
                               @checked($prefs[$compte['id']][$type] ?? false)>
                        <span class="rw-liste-selection__nom">{{ __('notif.type_' . $type) }}</span>
                        <span class="rw-liste-selection__detail">{{ __('notif.type_' . $type . '_desc') }}</span>
                    </label>
                @endforeach
            </div>
        </section>
    @endforeach

    @php($libelles = ['err_reseau' => __('notif.err_reseau'), 'pref_activee' => __('notif.pref_activee'), 'pref_desactivee' => __('notif.pref_desactivee')])
    <script id="notif-reglages-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/notifications-reglages.js?v={{ @filemtime(public_path('js/notifications-reglages.js')) ?: '0' }}"></script>
@endsection
