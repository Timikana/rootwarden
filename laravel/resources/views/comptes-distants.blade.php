@extends('layouts.portail', ['titre' => __('distants.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('distants.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('distants.desc') }}</p>

    <p class="rw-annonce @if (session('succes')) rw-annonce--ok @endif @if (session('erreur')) rw-annonce--echec @endif"
       data-rw="distants-annonce" role="status" aria-live="polite">
        @if (session('succes')){{ session('succes') }}@endif
        @if (session('erreur')){{ session('erreur') }}@endif
    </p>

    {{-- ═══ Choix de la machine ══════════════════════════════════════════════
         UN VRAI FORMULAIRE, pas un `onchange="location.href=…"`. Le legacy
         navigue au changement de valeur : au clavier, parcourir la liste
         déclenche une navigation à chaque flèche. Ici on choisit, puis on
         valide. --}}
    <section class="rw-carte rw-carte--pleine">
        <form method="GET" action="{{ route('comptes-distants') }}" class="rw-barre-filtres"
              data-rw="distants-choix-form">
            <label class="rw-champ">
                <span class="rw-etiquette">{{ __('distants.champ_machine') }}</span>
                <select name="machine" class="rw-saisie rw-saisie--compacte" data-rw="distants-machine">
                    @foreach ($parc as $m)
                        <option value="{{ $m->id }}" @if ((int) $m->id === $machine) selected @endif>{{ $m->name }}</option>
                    @endforeach
                </select>
            </label>
            <button type="submit" class="rw-bouton rw-bouton--discret" data-rw="distants-choisir">
                {{ __('distants.btn_choisir') }}
            </button>
        </form>

        @if ($machine > 0)
            <div class="rw-actions">
                <p class="rw-actions__gauche rw-aide rw-prose">{{ __('distants.scan_aide') }}</p>
                {{-- LE SCAN EST UN GESTE, JAMAIS UN EFFET DE BORD DU CHARGEMENT.
                     Il ouvre une session SSH ; `health_check.php` a montré ce que
                     coûte une page qui joint le parc en s'ouvrant. --}}
                <button type="button" class="rw-bouton" data-rw="distants-scanner"
                        data-machine="{{ $machine }}">{{ __('distants.btn_scanner') }}</button>
            </div>
            <p class="rw-aide" data-rw="distants-scan-etat" role="status" aria-live="polite"></p>
            {{--
                ── E-199 : LES COMPTES QUE LE SCAN A TROUVES ILLISIBLES ────────

                Le drapeau `nom_valide` est calcule PAR LA ROUTE de scan, il
                n'est pas une colonne de `server_user_inventory`. Cet encart ne
                peut donc etre renseigne qu'APRES un scan, jamais au chargement
                de la page — et il naît `hidden` plutot que de rendre une boite
                vide qui inviterait au clic.

                La regle n'est PAS recopiee ici : le portage ne compile pas de
                Python, et une regle recopiee finit par diverger de celle qui
                DECIDE. Ce qui manque pour un affichage durable est dit au Lead.
            --}}
            <div class="rw-encart" data-rw="distants-illisibles" hidden></div>
        @endif
    </section>

    @if ($machine > 0)
        {{-- ═══ Ce qui attend un examen ══════════════════════════════════════
             UN COMPTEUR À ZÉRO S'ÉNONCE. « Aucun compte n'attend d'examen » dit
             quelque chose ; un « 0 » ne dit rien. --}}
        @if ($enAttente > 0)
            <div class="rw-encart" data-rw="distants-en-attente">
                <p><strong>{{ __('distants.en_attente_titre', ['n' => $enAttente]) }}</strong></p>
                <p class="rw-prose">{{ __('distants.en_attente_aide') }}</p>
                <div class="rw-actions">
                    @foreach (['excluded', 'unmanaged'] as $cible)
                        <form method="POST" action="{{ route('comptes-distants.classer-en-attente', ['machine' => $machine]) }}"
                              class="rw-jetons__forme">
                            @csrf
                            <input type="hidden" name="statut" value="{{ $cible }}">
                            <button type="submit" class="rw-bouton rw-bouton--discret"
                                    data-rw="distants-classer-masse" data-statut="{{ $cible }}">
                                {{ __('distants.btn_classer_masse', ['n' => $enAttente, 'statut' => __('distants.statut_' . $cible)]) }}
                            </button>
                        </form>
                    @endforeach
                </div>
            </div>
        @else
            <p class="rw-aide" data-rw="distants-rien-en-attente">{{ __('distants.rien_en_attente') }}</p>
        @endif

        {{-- ═══ L'inventaire ═════════════════════════════════════════════════ --}}
        <section class="rw-carte rw-carte--pleine">
            <p class="rw-etiquette">{{ __('distants.liste_titre', ['n' => count($comptes), 'machine' => $nomMachine]) }}</p>

            <div class="rw-tableau-cadre">
                <table class="rw-tableau" data-rw="distants-liste">
                    <thead>
                        <tr>
                            <th>{{ __('distants.col_compte') }}</th>
                            <th class="rw-colonne-secondaire">{{ __('distants.col_uid') }}</th>
                            <th class="rw-colonne-secondaire">{{ __('distants.col_shell') }}</th>
                            <th>{{ __('distants.col_cles') }}</th>
                            <th>{{ __('distants.col_statut') }}</th>
                            <th>{{ __('distants.col_action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($comptes as $c)
                            <tr data-rw="distant-ligne" data-username="{{ $c['username'] }}">
                                <td>
                                    <strong>{{ $c['username'] }}</strong>
                                    @if ($c['has_platform_key'])
                                        <span class="rw-badge rw-badge--ok">{{ __('distants.cle_plateforme') }}</span>
                                    @endif
                                </td>
                                <td class="rw-colonne-secondaire">{{ $c['uid'] ?? '—' }}</td>
                                <td class="rw-colonne-secondaire"><code class="rw-code">{{ $c['shell'] ?? '—' }}</code></td>
                                <td>
                                    @if ((int) $c['keys_count'] > 0)
                                        <a class="rw-lien" data-rw="distant-voir-cles"
                                           href="{{ route('comptes-distants.cles', ['machine' => $machine, 'username' => $c['username']]) }}">
                                            {{ __('distants.n_cles', ['n' => $c['keys_count']]) }}
                                        </a>
                                    @else
                                        <span class="rw-aide">{{ __('distants.aucune_cle') }}</span>
                                    @endif
                                </td>
                                <td>
                                    <span class="rw-pastille @if ($c['status'] === $statutInitial) rw-pastille--attente @elseif ($c['status'] === 'managed') rw-pastille--ok @endif"
                                          data-rw="distant-statut">{{ __('distants.statut_' . $c['status']) }}</span>
                                </td>
                                <td>
                                    {{-- LE CLASSEMENT EST SANS RETOUR, et la page le
                                         dit. `pending_review` se pose au scan et
                                         n'est PAS dans la liste fermée du backend :
                                         une fois classé, un compte ne revient jamais
                                         « en attente d'examen ». --}}
                                    <form method="POST" action="{{ route('comptes-distants.classer', ['machine' => $machine]) }}"
                                          class="rw-barre-filtres">
                                        @csrf
                                        <input type="hidden" name="username" value="{{ $c['username'] }}">
                                        <label class="rw-champ">
                                            <span class="rw-etiquette rw-visuellement-cache">{{ __('distants.col_statut') }}</span>
                                            <select name="statut" class="rw-saisie rw-saisie--compacte"
                                                    data-rw="distant-choix-statut">
                                                @foreach ($statuts as $s)
                                                    <option value="{{ $s }}" @if ($c['status'] === $s) selected @endif>
                                                        {{ __('distants.statut_' . $s) }}
                                                    </option>
                                                @endforeach
                                            </select>
                                        </label>
                                        <button type="submit" class="rw-bouton rw-bouton--minuscule"
                                                data-rw="distant-classer">{{ __('distants.btn_classer') }}</button>
                                    </form>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="6">
                                    <div class="rw-vide" data-rw="distants-vide">
                                        <p><strong>{{ __('distants.vide') }}</strong></p>
                                        <p class="rw-prose">{{ __('distants.vide_aide') }}</p>
                                    </div>
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </section>

        {{-- ═══ Les gestes qui MODIFIENT la machine ══════════════════════════
             Ils ne sont PAS dans le tableau, et c'est délibéré. Le legacy pose
             « effacer les clés », « autoriser dans sshd » et « supprimer le
             compte » en trois boutons minuscules au bout de chaque ligne — trois
             gestes distants, dont un irréversible, à la portée d'un clic mal
             visé. Ici ils demandent de désigner le compte, puis de confirmer
             dans un panneau qui NOMME la conséquence. --}}
        <section class="rw-carte rw-carte--pleine" data-rw="distants-gestes">
            <p class="rw-etiquette">{{ __('distants.gestes_titre') }}</p>
            <p class="rw-aide rw-prose">{{ __('distants.gestes_aide') }}</p>

            <div class="rw-barre-filtres">
                <label class="rw-champ">
                    <span class="rw-etiquette">{{ __('distants.geste_compte') }}</span>
                    <select class="rw-saisie rw-saisie--compacte" data-rw="distants-geste-compte">
                        <option value="">{{ __('distants.geste_choisir') }}</option>
                        @foreach ($comptes as $c)
                            <option value="{{ $c['username'] }}">{{ $c['username'] }}</option>
                        @endforeach
                    </select>
                </label>
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="distant-retirer-cles">{{ __('distants.btn_retirer_cles') }}</button>
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="distant-sshd">{{ __('distants.btn_sshd') }}</button>
                <button type="button" class="rw-bouton rw-bouton--danger"
                        data-rw="distant-supprimer">{{ __('distants.btn_supprimer') }}</button>
            </div>

            <div class="rw-panneau-decision" data-rw="distant-panneau" hidden
                 data-machine="{{ $machine }}" data-nom-machine="{{ $nomMachine }}">
                <p class="rw-panneau-decision__texte" data-rw="distant-panneau-titre"></p>
                <p class="rw-prose" data-rw="distant-panneau-texte"></p>
                <div class="rw-panneau-decision__actions">
                    <button type="button" class="rw-bouton rw-bouton--discret"
                            data-rw="distant-annuler">{{ __('distants.annuler') }}</button>
                    <button type="button" class="rw-bouton rw-bouton--danger"
                            data-rw="distant-confirmer">{{ __('distants.confirmer') }}</button>
                </div>
            </div>
            <p class="rw-aide" data-rw="distant-geste-etat" role="status" aria-live="polite"></p>
        </section>
    @endif

    <script id="distants-libelles" type="application/json">@json($libelles ?? [])</script>
    <script src="/js/comptes-distants.js?v={{ @filemtime(public_path('js/comptes-distants.js')) ?: '0' }}"></script>
@endsection
