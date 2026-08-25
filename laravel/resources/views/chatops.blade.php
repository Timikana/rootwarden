@extends('layouts.portail', ['titre' => __('chatops.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('chatops.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('chatops.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <span class="rw-pastille" data-rw="chatops-etat">{{ __('chatops.loading') }}</span>
        </div>
    </div>

    {{-- CE QU'IL FAUT CONFIGURER, ET OÙ. Le legacy affiche la même URL, mais
         sans dire qu'elle a changé. Après la bascule, l'adresse du webhook n'est
         plus `/chatops/webhook.php` : il faut la reporter dans Slack. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('chatops.setup_title') }}</strong>
        <p>{{ __('chatops.setup_url') }}</p>
        <p class="rw-journal" data-rw="chatops-webhook">{{ $urlWebhook }}</p>
        <ul class="rw-liste-guide">
            <li>{{ __('chatops.setup_slack') }}</li>
            <li>{{ __('chatops.setup_token') }}</li>
            <li>{{ __('chatops.setup_commands') }} : <code>status</code>, <code>approvals</code>,
                <code>approve &lt;id&gt;</code>, <code>reject &lt;id&gt;</code>, <code>help</code></li>
            <li><strong>{{ __('chatops.setup_changement') }}</strong></li>
        </ul>
    </div>

    <section class="rw-section">
        <div class="rw-section__entete">
            <h2 class="rw-sous-titre-fort">{{ __('chatops.mappings_title') }}</h2>
        </div>

    <div class="rw-barre-filtres">
        <div class="rw-champ">
            <label class="rw-etiquette" for="m-platform">{{ __('chatops.f_platform') }}</label>
            {{-- LISTE FERMÉE. Une plateforme est un identifiant que le backend
                 range puis relit : la laisser saisir librement ouvrirait une
                 valeur que rien n'attend. --}}
            <select class="rw-saisie" id="m-platform" data-rw="chatops-plateforme">
                <option value="slack">Slack</option>
                <option value="teams">Teams</option>
                <option value="generic">Generic</option>
            </select>
        </div>
        <div class="rw-champ">
            <label class="rw-etiquette" for="m-chatid">{{ __('chatops.f_chat_id') }}</label>
            <input class="rw-saisie" id="m-chatid" type="text" placeholder="U012ABCDEF"
                   data-rw="chatops-chatid">
        </div>
        <div class="rw-champ">
            <label class="rw-etiquette" for="m-user">{{ __('chatops.f_user') }}</label>
            <select class="rw-saisie" id="m-user" data-rw="chatops-utilisateur">
                @foreach ($comptes as $c)
                    <option value="{{ $c->id }}">{{ $c->name }}</option>
                @endforeach
            </select>
        </div>
        <div class="rw-champ">
            <label class="rw-etiquette" for="m-label">{{ __('chatops.f_label') }}</label>
            <input class="rw-saisie" id="m-label" type="text" data-rw="chatops-etiquette">
        </div>
        <button class="rw-bouton" type="button" data-rw="chatops-ajouter"
                title="{{ __('chatops.tip_add') }}">{{ __('chatops.btn_add') }}</button>
    </div>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('chatops.col_platform') }}</th>
                    <th>{{ __('chatops.col_chat_id') }}</th>
                    <th>{{ __('chatops.col_user') }}</th>
                    <th>{{ __('chatops.col_label') }}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody data-rw="chatops-corps">
                <tr><td colspan="5" class="rw-vide">{{ __('chatops.loading') }}</td></tr>
            </tbody>
        </table>
    </div>

    <p class="rw-annonce" data-rw="chatops-message" role="status" aria-live="polite"></p>
    </section>

    <script type="application/json" id="chatops-libelles">@json(__('chatops'))</script>
    <script src="{{ asset('js/chatops.js') }}?v={{ filemtime(public_path('js/chatops.js')) }}"></script>
@endsection
