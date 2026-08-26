@extends('layouts.portail', ['titre' => __('serveurs.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('serveurs.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('serveurs.desc') }}</p>

    @include('composants.onglets-adm', ['courant' => 'serveurs'])

    <p class="rw-annonce @if (session('succes')) rw-annonce--ok @endif @if (session('erreur')) rw-annonce--echec @endif"
       data-rw="serveurs-annonce" role="status" aria-live="polite">
        @if (session('succes')){{ session('succes') }}@endif
        @if (session('erreur')){{ session('erreur') }}@endif
    </p>

    {{-- UNE CAPACITE NON PORTEE N'EST PAS UN SILENCE. Etiquettes, notes, cycle
         de vie et test de connexion passent par `server_actions.php` — sous-lot
         D6b. La page le DIT, plutot que de laisser croire qu'ils ont disparu. --}}
    <div class="rw-encart" data-rw="serveurs-non-porte">
        <p><strong>{{ __('serveurs.reste_titre') }}</strong></p>
        <p class="rw-prose">{{ __('serveurs.reste_texte') }}</p>
        <p>
            <a class="rw-bouton rw-bouton--discret" data-rw="serveurs-lien-legacy"
               href="{{ rtrim(config('app.url_legacy'), '/') }}/adm/admin_page.php"
               target="_blank" rel="noopener">{{ __('serveurs.reste_lien') }} ↗</a>
        </p>
    </div>

    {{-- ═══ Ajout ═══════════════════════════════════════════════════════════ --}}
    <section class="rw-carte rw-carte--pleine">
        <details data-rw="serveurs-ajout-bloc">
            <summary class="rw-sous-titre-fort">{{ __('serveurs.ajouter_titre') }}</summary>

            <form method="POST" action="{{ route('serveurs.ajouter') }}" data-rw="serveurs-ajout-form">
                @csrf
                <div class="rw-grille">
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_nom') }} *</span>
                        <input type="text" name="name" required maxlength="255" placeholder="srv-web-01"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-nom">
                        <span class="rw-aide">{{ __('serveurs.aide_nom') }}</span>
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_ip') }} *</span>
                        <input type="text" name="ip" required placeholder="192.168.1.10"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-ip">
                        <span class="rw-aide">{{ __('serveurs.aide_ip') }}</span>
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_port') }} *</span>
                        <input type="number" name="port" required min="1" max="65535" value="22"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-port">
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_utilisateur') }} *</span>
                        <input type="text" name="user" required maxlength="255" placeholder="admin"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-utilisateur">
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_mdp') }} *</span>
                        <input type="password" name="password" required autocomplete="new-password"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-mdp">
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_mdp_root') }} *</span>
                        <input type="password" name="root_password" required autocomplete="new-password"
                               class="rw-saisie rw-saisie--compacte" data-rw="serveur-mdp-root">
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_environnement') }}</span>
                        <select name="environment" class="rw-saisie rw-saisie--compacte" data-rw="serveur-environnement">
                            @foreach ($environnements as $env)
                                <option value="{{ $env }}" @if ($env === 'DEV') selected @endif>
                                    {{ $env === 'OTHER' ? __('serveurs.env_autre') : $env }}
                                </option>
                            @endforeach
                        </select>
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_criticite') }}</span>
                        <select name="criticality" class="rw-saisie rw-saisie--compacte" data-rw="serveur-criticite">
                            @foreach ($criticites as $crit)
                                <option value="{{ $crit }}" @if ($crit === 'NON CRITIQUE') selected @endif>
                                    {{ $crit === 'CRITIQUE' ? __('serveurs.crit_critique') : __('serveurs.crit_non_critique') }}
                                </option>
                            @endforeach
                        </select>
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('serveurs.champ_reseau') }}</span>
                        <select name="network_type" class="rw-saisie rw-saisie--compacte" data-rw="serveur-reseau">
                            @foreach ($reseaux as $res)
                                <option value="{{ $res }}">
                                    {{ $res === 'INTERNE' ? __('serveurs.res_interne') : __('serveurs.res_externe') }}
                                </option>
                            @endforeach
                        </select>
                    </label>
                </div>
                <div class="rw-actions">
                    <span class="rw-actions__gauche rw-aide">{{ __('serveurs.champs_requis') }}</span>
                    <button type="submit" class="rw-bouton" data-rw="serveur-ajouter">{{ __('serveurs.btn_ajouter') }}</button>
                </div>
            </form>
        </details>
    </section>

    {{-- ═══ Le parc ═════════════════════════════════════════════════════════ --}}
    <section class="rw-carte rw-carte--pleine">
        <div class="rw-barre-filtres">
            <label class="rw-champ">
                <span class="rw-etiquette">{{ __('serveurs.filtre_label') }}</span>
                <input type="search" class="rw-saisie rw-saisie--large" data-rw="serveurs-filtre"
                       placeholder="{{ __('serveurs.filtre_placeholder') }}">
            </label>
            <p class="rw-aide" data-rw="serveurs-compte" role="status" aria-live="polite">
                {{ __('serveurs.compte', ['n' => count($machines)]) }}
            </p>
        </div>

        @forelse ($machines as $m)
            @php
                $enLigne = strtolower((string) ($m['online_status'] ?? ''));
                $cycle = (string) ($m['lifecycle_status'] ?? 'active');
                // LE FILTRE PORTE SUR LES TROIS CHAMPS QUE LA RECHERCHE MORTE
                // DU LEGACY VISAIT (nom, adresse, compte SSH), et non sur le
                // seul nom comme son filtre vivant. Les trois sont affiches
                // dans l'en-tete de la carte : filtrer sur ce qu'on ne voit pas
                // ferait disparaitre des lignes sans raison lisible.
                $cible = mb_strtolower($m['name'].' '.$m['ip'].' '.$m['user']);
            @endphp
            <details class="rw-carte rw-carte--pleine" data-rw="serveur-carte" data-cible="{{ $cible }}">
                <summary class="rw-etiquette">
                    <strong data-rw="serveur-carte-nom">{{ $m['name'] }}</strong>
                    <span class="rw-pastille @if ($enLigne === 'online') rw-pastille--ok @elseif ($enLigne === 'offline') rw-pastille--echec @endif"
                          data-rw="serveur-carte-etat">
                        @if ($enLigne === 'online'){{ __('serveurs.en_ligne') }}
                        @elseif ($enLigne === 'offline'){{ __('serveurs.hors_ligne') }}
                        @else{{ __('serveurs.statut_inconnu') }}@endif
                    </span>
                    <code class="rw-code">{{ $m['ip'] }}:{{ $m['port'] }}</code>
                    <span class="rw-badge rw-badge--neutre">{{ $m['user'] }}</span>
                    <span class="rw-badge rw-badge--neutre">{{ $m['environment'] ?? 'OTHER' }}</span>
                    <span class="rw-badge rw-badge--neutre">{{ ($m['criticality'] ?? '') === 'CRITIQUE' ? __('serveurs.crit_critique') : __('serveurs.crit_non_critique') }}</span>
                    <span class="rw-badge @if ($m['platform_key_deployed'] ?? false) rw-badge--ok @else rw-badge--attention @endif">
                        {{ ($m['platform_key_deployed'] ?? false) ? __('serveurs.auth_cle') : __('serveurs.auth_mdp') }}
                    </span>
                </summary>

                @if ($cycle !== 'active')
                    <p class="rw-annonce rw-annonce--attention">
                        {{ $cycle === 'retiring' ? __('serveurs.cycle_retrait') : __('serveurs.cycle_archive') }}
                        @if ($m['retire_date'] ?? null)
                            — {{ __('serveurs.cycle_date', ['date' => $m['retire_date']]) }}
                        @endif
                    </p>
                @endif

                <form method="POST" action="{{ route('serveurs.modifier', ['id' => $m['id']]) }}"
                      data-rw="serveur-form" data-id="{{ $m['id'] }}">
                    @csrf
                    <div class="rw-grille">
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_nom') }}</span>
                            <input type="text" name="name" value="{{ $m['name'] }}" maxlength="255"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-nom">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_ip') }}</span>
                            <input type="text" name="ip" value="{{ $m['ip'] }}"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-ip">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_port') }}</span>
                            <input type="number" name="port" value="{{ (int) $m['port'] }}" min="1" max="65535"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-port">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_utilisateur') }}</span>
                            <input type="text" name="user" value="{{ $m['user'] }}" maxlength="255"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-utilisateur">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_mdp') }}</span>
                            <input type="password" name="password" autocomplete="new-password"
                                   placeholder="{{ __('serveurs.inchange') }}"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-mdp">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_mdp_root') }}</span>
                            <input type="password" name="root_password" autocomplete="new-password"
                                   placeholder="{{ __('serveurs.inchange') }}"
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-mdp-root">
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_environnement') }}</span>
                            <select name="environment" class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-environnement">
                                @foreach ($environnements as $env)
                                    <option value="{{ $env }}" @if (($m['environment'] ?? '') === $env) selected @endif>
                                        {{ $env === 'OTHER' ? __('serveurs.env_autre') : $env }}
                                    </option>
                                @endforeach
                            </select>
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_criticite') }}</span>
                            <select name="criticality" class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-criticite">
                                @foreach ($criticites as $crit)
                                    <option value="{{ $crit }}" @if (($m['criticality'] ?? '') === $crit) selected @endif>
                                        {{ $crit === 'CRITIQUE' ? __('serveurs.crit_critique') : __('serveurs.crit_non_critique') }}
                                    </option>
                                @endforeach
                            </select>
                        </label>
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.champ_reseau') }}</span>
                            <select name="network_type" class="rw-saisie rw-saisie--compacte" data-rw="serveur-edit-reseau">
                                @foreach ($reseaux as $res)
                                    <option value="{{ $res }}" @if (($m['network_type'] ?? '') === $res) selected @endif>
                                        {{ $res === 'INTERNE' ? __('serveurs.res_interne') : __('serveurs.res_externe') }}
                                    </option>
                                @endforeach
                            </select>
                        </label>
                    </div>

                    <p class="rw-etiquette">{{ __('serveurs.options_deploiement') }}</p>
                    <label class="rw-champ rw-champ--case">
                        <input type="checkbox" name="cleanup_users" value="1"
                               @if ($m['cleanup_users'] ?? 1) checked @endif
                               data-rw="serveur-edit-nettoyage">
                        <span>
                            <span class="rw-etiquette">{{ __('serveurs.opt_nettoyage') }}</span>
                            <span class="rw-aide">{{ __('serveurs.opt_nettoyage_aide') }}</span>
                        </span>
                    </label>

                    <div class="rw-actions">
                        <button type="button" class="rw-bouton rw-bouton--danger rw-actions__gauche"
                                data-rw="serveur-supprimer" data-id="{{ $m['id'] }}" data-nom="{{ $m['name'] }}">
                            {{ __('serveurs.btn_supprimer') }}
                        </button>
                        <button type="submit" class="rw-bouton" data-rw="serveur-enregistrer">{{ __('serveurs.btn_enregistrer') }}</button>
                    </div>
                </form>

                {{-- ═══ Cycle de vie et test de connexion — sous-lot D6d ══════
                     LES BOUTONS DE CYCLE SONT DES FORMULAIRES, et l'état
                     COURANT n'est jamais proposé — bonne propriété reprise du
                     legacy, et mesurée : c'est elle qui rend « reposer la
                     valeur en place » inatteignable au clic.

                     Le test de connexion, lui, passe par la passerelle : sa
                     sonde TCP appartient au backend. Il n'est JAMAIS déclenché
                     au chargement — `health_check.php` a montré ce que coûte
                     une page qui joint le parc en s'ouvrant. --}}
                <section class="rw-bloc-secondaire" data-rw="serveur-exploitation">
                    <p class="rw-etiquette">{{ __('serveurs.exploitation_titre') }}</p>
                    <div class="rw-actions">
                        {{-- PAS `.rw-jetons` ICI : sa `margin: 6px 0 10px` écrase le
                             `margin-right: auto` de `.rw-actions__gauche`, et le bloc
                             ne se pousse plus à gauche. Vu à l'image. Les formulaires
                             sont déjà `display: inline`, ils s'alignent d'eux-mêmes. --}}
                        <div class="rw-actions__gauche">
                            @foreach ($serveurs->cyclesProposables($cycle) as $etat)
                                <form method="POST" action="{{ route('serveurs.cycle', ['id' => $m['id']]) }}"
                                      class="rw-jetons__forme">
                                    @csrf
                                    <input type="hidden" name="etat" value="{{ $etat }}">
                                    {{-- AUCUN DE CES TROIS GESTES N'EST DESTRUCTEUR : ils
                                         sont tous réversibles par leur voisin. Le rouge
                                         danger reste donc réservé à « Retirer du parc »,
                                         qui, lui, ne se défait pas. Deux rouges côte à
                                         côte pour deux niveaux de conséquence différents
                                         ne signalent plus rien. --}}
                                    <button type="submit" class="rw-bouton rw-bouton--discret"
                                            data-rw="serveur-cycle" data-etat="{{ $etat }}">
                                        {{ __('serveurs.cycle_' . $etat) }}
                                    </button>
                                </form>
                            @endforeach
                        </div>
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="serveur-tester" data-id="{{ $m['id'] }}">
                            {{ __('serveurs.btn_tester') }}
                        </button>
                    </div>
                    <p class="rw-aide" data-rw="serveur-test-resultat" data-id="{{ $m['id'] }}"
                       role="status" aria-live="polite"></p>
                </section>

                {{-- ═══ Étiquettes ═══════════════════════════════════════════
                     QUATRE FORMULAIRES, PAS UN `fetch`. Les quatre gestes du
                     legacy meurent sur un jeton CSRF que son enrobage de
                     `window.fetch` n'injecte pas pour cette famille d'URL
                     (E-125) : chaque clic reçoit « Token CSRF invalide ». Un
                     formulaire n'a pas de plomberie à oublier, et le legacy
                     rechargeait la page de toute façon.

                     Les formulaires sont FRÈRES de celui d'édition, jamais
                     imbriqués : un `<form>` dans un `<form>` est ignoré par
                     l'analyseur, et le geste partirait vers la mauvaise route. --}}
                <section class="rw-bloc-secondaire" data-rw="serveur-etiquettes">
                    <p class="rw-etiquette">{{ __('serveurs.etiquettes_titre') }}</p>
                    <div class="rw-jetons">
                        @forelse ($etiquettes[$m['id']] ?? [] as $tag)
                            <span class="rw-badge rw-badge--neutre">
                                {{ $tag }}
                                <form method="POST" action="{{ route('serveurs.etiquette.retirer', ['id' => $m['id']]) }}"
                                      class="rw-jetons__forme">
                                    @csrf
                                    <input type="hidden" name="etiquette" value="{{ $tag }}">
                                    <button type="submit" class="rw-jetons__retrait"
                                            data-rw="serveur-etiquette-retirer" data-tag="{{ $tag }}"
                                            title="{{ __('serveurs.etiquette_retirer', ['tag' => $tag]) }}"
                                            aria-label="{{ __('serveurs.etiquette_retirer', ['tag' => $tag]) }}">&times;</button>
                                </form>
                            </span>
                        @empty
                            <span class="rw-aide">{{ __('serveurs.etiquettes_vide') }}</span>
                        @endforelse
                    </div>
                    <form method="POST" action="{{ route('serveurs.etiquette.poser', ['id' => $m['id']]) }}"
                          class="rw-barre-filtres">
                        @csrf
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.etiquette_champ') }}</span>
                            <input type="text" name="etiquette" maxlength="50" required
                                   class="rw-saisie rw-saisie--compacte" data-rw="serveur-etiquette-saisie"
                                   placeholder="{{ __('serveurs.etiquette_placeholder') }}">
                            {{-- LA RÈGLE EST ANNONCÉE, pas appliquée en silence.
                                 Le legacy ampute la saisie sans rien dire. --}}
                            <span class="rw-aide">{{ __('serveurs.etiquette_aide') }}</span>
                        </label>
                        <button type="submit" class="rw-bouton rw-bouton--discret"
                                data-rw="serveur-etiquette-ajouter">{{ __('serveurs.etiquette_ajouter') }}</button>
                    </form>
                </section>

                {{-- ═══ Notes ════════════════════════════════════════════════ --}}
                <section class="rw-bloc-secondaire" data-rw="serveur-notes">
                    <p class="rw-etiquette">{{ __('serveurs.notes_titre') }}</p>
                    @forelse ($notes[$m['id']] ?? [] as $n)
                        <div class="rw-ligne-note">
                            <span class="rw-tableau__discret">{{ \Illuminate\Support\Carbon::parse($n['created_at'])->format('d/m H:i') }}</span>
                            <strong>{{ $n['author'] }}</strong>
                            <span>{{ $n['content'] }}</span>
                            <form method="POST"
                                  action="{{ route('serveurs.note.supprimer', ['id' => $m['id'], 'note' => $n['id']]) }}"
                                  class="rw-ligne-note__forme">
                                @csrf
                                <button type="submit" class="rw-jetons__retrait" data-rw="serveur-note-supprimer"
                                        title="{{ __('serveurs.note_supprimer') }}"
                                        aria-label="{{ __('serveurs.note_supprimer') }}">&times;</button>
                            </form>
                        </div>
                    @empty
                        <p class="rw-aide">{{ __('serveurs.notes_vide') }}</p>
                    @endforelse
                    @if (count($notes[$m['id']] ?? []) >= $borneNotes)
                        {{-- LA BORNE S'ANNONCE. Le legacy coupe a cinq sans le
                             dire : on croit voir toutes les notes. --}}
                        <p class="rw-aide">{{ __('serveurs.notes_borne', ['n' => $borneNotes]) }}</p>
                    @endif
                    <form method="POST" action="{{ route('serveurs.note.poser', ['id' => $m['id']]) }}"
                          class="rw-barre-filtres">
                        @csrf
                        <label class="rw-champ">
                            <span class="rw-etiquette">{{ __('serveurs.note_champ') }}</span>
                            <input type="text" name="note" maxlength="500" required
                                   class="rw-saisie rw-saisie--large" data-rw="serveur-note-saisie"
                                   placeholder="{{ __('serveurs.note_placeholder') }}">
                        </label>
                        <button type="submit" class="rw-bouton rw-bouton--discret"
                                data-rw="serveur-note-ajouter">{{ __('serveurs.note_ajouter') }}</button>
                    </form>
                </section>
            </details>
        @empty
            <div class="rw-vide" data-rw="serveurs-vide">
                <p><strong>{{ __('serveurs.vide') }}</strong></p>
                <p class="rw-prose">{{ __('serveurs.vide_aide') }}</p>
            </div>
        @endforelse
    </section>

    {{-- ═══ Retrait du parc ═════════════════════════════════════════════════
         Le legacy pose un `confirm()` natif, qui ne dit rien de ce que le geste
         engage. Ce panneau NOMME la consequence — et surtout ce qu'elle n'est
         PAS : la machine elle-meme n'est pas touchee. --}}
    <div class="rw-panneau-decision" data-rw="serveur-suppr-panneau" hidden
         data-action="{{ route('serveurs.supprimer', ['id' => '__ID__']) }}">
        <p class="rw-panneau-decision__texte" data-rw="serveur-suppr-titre"></p>
        <p class="rw-prose">{{ __('serveurs.suppr_texte') }}</p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret" data-rw="serveur-suppr-annuler">{{ __('serveurs.suppr_annuler') }}</button>
            <form method="POST" action="" data-rw="serveur-suppr-form">
                @csrf
                <button type="submit" class="rw-bouton rw-bouton--danger" data-rw="serveur-suppr-confirmer">{{ __('serveurs.suppr_confirmer') }}</button>
            </form>
        </div>
    </div>
    {{-- LES LIBELLES PASSENT PAR DU JSON, JAMAIS PAR UNE INTERPOLATION DANS DU
         JAVASCRIPT. E-114 a coute une page entiere : un nom portant une
         apostrophe cassait le script, et la page ne rendait plus rien. `@json`
         echappe ce qu'il faut, et il tient sur UNE ligne — multiligne, il casse
         le PHP compile. --}}
    <script id="serveurs-libelles" type="application/json">@json($libelles)</script>

    {{-- Le gabarit ne porte AUCUNE pile `@stack` : un `@push` n'y rendrait
         rien, sans erreur ni journal. Le script se charge donc dans la section,
         comme sur les cinq autres pages du module. L'empreinte de date force le
         rechargement apres modification. --}}
    <script src="/js/serveurs.js?v={{ @filemtime(public_path('js/serveurs.js')) ?: '0' }}"></script>
@endsection
