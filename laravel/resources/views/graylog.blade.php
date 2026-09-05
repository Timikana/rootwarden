@extends('layouts.portail', ['titre' => __('graylog.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('graylog.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('graylog.desc') }}</p>
        </div>
    </div>

    {{-- L'ENCART QUE LE LEGACY N'A PAS.

         Trois boutons de l'onglet Machines ouvrent une session SSH réelle et
         exécutent en root : installation d'un paquet, écriture de fichiers,
         redémarrage d'un service. Le legacy ne le dit nulle part, et il ne
         demande même pas confirmation pour « Tester ».

         Le dire AVANT le clic, pas dans la boîte de confirmation : quelqu'un qui
         découvre la page doit savoir ce qu'elle peut faire avant d'y toucher. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('graylog.guide_titre') }}</strong>
        <ul class="rw-liste-guide">
            <li>{{ __('graylog.guide_deploy') }}</li>
            <li>{{ __('graylog.guide_test') }}</li>
            <li>{{ __('graylog.guide_retirer') }}</li>
            <li>{{ __('graylog.guide_prod') }}</li>
        </ul>
    </div>

    {{-- Les onglets viennent du contrôleur, en données : leur ordre et leur
         nombre se lisent d'un coup, et le test les parcourt sans connaître la
         page. Les panneaux se cachent par l'attribut `hidden`, jamais par une
         classe — une règle `display:` sur la classe rendrait `hidden` sans
         effet, ce que le projet a déjà payé. --}}
    <div class="rw-onglets" role="tablist">
        @foreach ($onglets as $onglet)
            <button type="button" role="tab"
                    class="rw-onglet @if ($loop->first) rw-onglet--actif @endif"
                    data-rw="graylog-onglet-{{ $onglet }}"
                    data-onglet="{{ $onglet }}"
                    aria-selected="{{ $loop->first ? 'true' : 'false' }}"
                    aria-controls="graylog-panneau-{{ $onglet }}">{{ __('graylog.onglet_' . $onglet) }}</button>
        @endforeach
    </div>

    {{-- ══ Configuration ══════════════════════════════════════════════════ --}}
    <div id="graylog-panneau-config" data-rw="graylog-panneau-config" role="tabpanel">
        <div class="rw-carte">
            <h2 class="rw-sous-titre-fort">{{ __('graylog.config_titre') }}</h2>
            <p class="rw-aide rw-prose">{{ __('graylog.config_aide') }}</p>

            <div class="rw-grille rw-grille--compacte">
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-hote">{{ __('graylog.hote') }}</label>
                    <input class="rw-saisie" id="gl-hote" type="text" maxlength="255"
                           data-rw="graylog-hote">
                    <p class="rw-aide">{{ __('graylog.hote_aide') }}</p>
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-port">{{ __('graylog.port') }}</label>
                    <input class="rw-saisie" id="gl-port" type="number" min="1" max="65535"
                           data-rw="graylog-port">
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-protocole">{{ __('graylog.protocole') }}</label>
                    {{-- LISTE FERMÉE : un protocole est un identifiant que le
                         backend range puis relit pour composer la conf rsyslog.
                         Une saisie libre y ouvrirait une valeur que rien
                         n'attend. --}}
                    <select class="rw-saisie" id="gl-protocole" data-rw="graylog-protocole">
                        <option value="udp">UDP</option>
                        <option value="tcp">TCP</option>
                        <option value="tls">TLS</option>
                    </select>
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-tls-ca">{{ __('graylog.tls_ca') }}</label>
                    <input class="rw-saisie" id="gl-tls-ca" type="text" maxlength="255"
                           data-rw="graylog-tls-ca">
                    <p class="rw-aide">{{ __('graylog.tls_ca_aide') }}</p>
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-rl-burst">{{ __('graylog.rl_burst') }}</label>
                    <input class="rw-saisie" id="gl-rl-burst" type="number" min="0"
                           data-rw="graylog-rl-burst">
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-rl-interval">{{ __('graylog.rl_interval') }}</label>
                    <input class="rw-saisie" id="gl-rl-interval" type="number" min="0"
                           data-rw="graylog-rl-interval">
                    <p class="rw-aide">{{ __('graylog.rl_aide') }}</p>
                </div>
            </div>

            <div class="rw-actions">
                <button class="rw-bouton" type="button"
                        data-rw="graylog-config-enregistrer">{{ __('graylog.enregistrer') }}</button>
            </div>
            <p class="rw-annonce" data-rw="graylog-config-etat" role="status" aria-live="polite"></p>
        </div>
    </div>

    {{-- ══ Machines ═══════════════════════════════════════════════════════ --}}
    <div id="graylog-panneau-deploy" data-rw="graylog-panneau-deploy" role="tabpanel" hidden>
        <div class="rw-entete-page">
            <h2 class="rw-sous-titre-fort">{{ __('graylog.machines_titre') }}</h2>
            <div class="rw-entete-page__actions">
                <button class="rw-bouton rw-bouton--discret" type="button"
                        data-rw="graylog-rafraichir">{{ __('graylog.rafraichir') }}</button>
            </div>
        </div>
        <div class="rw-tableau-cadre" data-rw="graylog-serveurs">
            <p class="rw-vide">{{ __('graylog.chargement') }}</p>
        </div>
        <p class="rw-annonce" data-rw="graylog-machines-etat" role="status" aria-live="polite"></p>
    </div>

    {{-- ══ Gabarits ═══════════════════════════════════════════════════════ --}}
    <div id="graylog-panneau-templates" data-rw="graylog-panneau-templates" role="tabpanel" hidden>
        <div class="rw-grille">
            <div class="rw-carte">
                <div class="rw-entete-page">
                    <h2 class="rw-sous-titre-fort">{{ __('graylog.gabarits_titre') }}</h2>
                    <div class="rw-entete-page__actions">
                        <button class="rw-bouton rw-bouton--discret rw-bouton--minuscule" type="button"
                                data-rw="graylog-gabarit-nouveau">{{ __('graylog.gabarit_nouveau') }}</button>
                    </div>
                </div>
                <div data-rw="graylog-gabarits">
                    <p class="rw-vide">{{ __('graylog.chargement') }}</p>
                </div>
            </div>

            <div class="rw-carte rw-carte--large">
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-tpl-nom">{{ __('graylog.gabarit_nom') }}</label>
                    <input class="rw-saisie" id="gl-tpl-nom" type="text" maxlength="64"
                           data-rw="graylog-gabarit-nom">
                </div>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-tpl-desc">{{ __('graylog.gabarit_desc') }}</label>
                    <input class="rw-saisie" id="gl-tpl-desc" type="text" maxlength="255"
                           data-rw="graylog-gabarit-desc">
                </div>
                <label class="rw-case">
                    <input type="checkbox" data-rw="graylog-gabarit-active">
                    {{ __('graylog.gabarit_actif') }}
                </label>
                <div class="rw-champ">
                    <label class="rw-champ__etiquette" for="gl-tpl-contenu">{{ __('graylog.gabarit_contenu') }}</label>
                    <textarea class="rw-saisie rw-saisie--edition" id="gl-tpl-contenu" rows="18"
                              spellcheck="false" data-rw="graylog-gabarit-contenu"></textarea>
                </div>
                <div class="rw-actions">
                    <button class="rw-bouton rw-bouton--danger rw-actions__gauche" type="button"
                            data-rw="graylog-gabarit-supprimer">{{ __('graylog.gabarit_supprimer') }}</button>
                    <button class="rw-bouton" type="button"
                            data-rw="graylog-gabarit-enregistrer">{{ __('graylog.enregistrer') }}</button>
                </div>
                {{-- La confirmation s'ouvre ICI, sous les boutons, jamais dans une
                     boîte native : elle recouvrirait précisément ce sur quoi on
                     décide, ne se style pas, et bloque Puppeteer. --}}
                <div class="rw-panneau-decision" data-rw="graylog-gabarit-panneau" hidden></div>
                <p class="rw-annonce" data-rw="graylog-gabarit-etat" role="status" aria-live="polite"></p>
            </div>
        </div>
    </div>

    {{-- ══ Historique ═════════════════════════════════════════════════════ --}}
    <div id="graylog-panneau-history" data-rw="graylog-panneau-history" role="tabpanel" hidden>
        <div class="rw-carte">
            <h2 class="rw-sous-titre-fort">{{ __('graylog.historique_titre') }}</h2>
            {{-- RENDU CÔTÉ SERVEUR, comme le legacy — il n'existe aucune route
                 `/graylog/history` dans le backend. Voir le contrôleur. --}}
            <div class="rw-tableau-cadre" data-rw="graylog-historique">
                @if ($historique->isEmpty())
                    <p class="rw-vide">{{ __('graylog.historique_vide') }}</p>
                @else
                    <table class="rw-tableau">
                        <thead>
                            <tr>
                                <th>{{ __('graylog.col_dernier') }}</th>
                                <th>{{ __('graylog.col_nom') }}</th>
                                <th>{{ __('graylog.col_actions') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($historique as $ligne)
                                <tr>
                                    <td>{{ $ligne->created_at }}</td>
                                    <td>{{ $ligne->user_name ?? '—' }}</td>
                                    <td class="rw-tableau__discret">{{ $ligne->action }}</td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                @endif
            </div>
        </div>
    </div>

    {{-- Les libellés partent EN DONNÉES : une chaîne écrite en dur dans le
         script échapperait à la parité FR/EN. `@json` sur UNE ligne — multiligne
         casse le PHP compilé. --}}
    <script type="application/json" id="graylog-libelles">@json(__('graylog'))</script>
    <script src="{{ asset('js/graylog.js') }}?v={{ filemtime(public_path('js/graylog.js')) }}"></script>
@endsection
