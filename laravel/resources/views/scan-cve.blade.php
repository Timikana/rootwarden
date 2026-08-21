@extends('layouts.portail', ['titre' => __('cve.titre')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('cve.titre') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('cve.description') }}</p>
        </div>
    </div>

    @if ($machines === [])
        {{-- Un etat vide doit dire ce qui manque ET pourquoi : « aucun serveur »
             sans la raison laisse croire a une panne. --}}
        <div class="rw-vide">
            <p class="rw-vide__titre">{{ __('cve.aucun_serveur') }}</p>
            <p class="rw-vide__texte rw-prose">{{ __('cve.aucun_serveur_aide') }}</p>
        </div>
    @else
        {{-- RESUME BORNE AUX MACHINES CI-DESSOUS (E-47). Le legacy agrege le
             dernier scan de TOUTE la base, archivees comprises, et l'affiche des
             que le compte voit deux machines : un lecteur y lisait les compteurs
             de la flotte entiere. Chaque legende dit donc sur QUOI porte le
             nombre — une legende qui ne le dit pas laisse deviner. --}}
        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('cve.section_resume') }}</h2>
            </div>
            <div class="rw-grille rw-grille--compacte">
                <div class="rw-tuile">
                    <span class="rw-tuile__titre">{{ __('cve.serveurs_scannes') }}</span>
                    <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $resume['serveurs_scannes'] }} / {{ count($machines) }}</span>
                    <p class="rw-tuile__texte">{{ __('cve.tuile_scannes_aide') }}</p>
                </div>
                <div class="rw-tuile">
                    <span class="rw-tuile__titre">{{ __('cve.total_cve') }}</span>
                    <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $resume['total'] }}</span>
                    <p class="rw-tuile__texte">{{ __('cve.tuile_total_aide') }}</p>
                </div>
                <div class="rw-tuile">
                    <span class="rw-tuile__titre">{{ __('cve.critiques') }}</span>
                    <span class="rw-tuile__valeur {{ $resume['critiques'] > 0 ? 'rw-tuile__valeur--alerte' : 'rw-tuile__valeur--ok' }}"
                          data-rw="tuile-valeur">{{ $resume['critiques'] }}</span>
                    <p class="rw-tuile__texte">{{ __('cve.tuile_critiques_aide') }}</p>
                </div>
                <div class="rw-tuile">
                    <span class="rw-tuile__titre">{{ __('cve.hautes') }}</span>
                    <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $resume['hautes'] }}</span>
                    <p class="rw-tuile__texte">{{ __('cve.tuile_hautes_aide') }}</p>
                </div>
                <div class="rw-tuile">
                    <span class="rw-tuile__titre">{{ __('cve.moyennes') }}</span>
                    <span class="rw-tuile__valeur" data-rw="tuile-valeur">{{ $resume['moyennes'] }}</span>
                    <p class="rw-tuile__texte">{{ __('cve.tuile_moyennes_aide') }}</p>
                </div>
            </div>
        </section>

        @if ($peutPlanifier)
            {{-- PLANIFICATION — sous-lot S4. Rendu SEULEMENT au-dela du role 2,
                 comme le bloc du legacy. La difference : ici le script ne
                 s'initialise pas non plus, alors que le legacy branche son
                 chargeur pour tous les roles et emet donc un appel refuse a
                 chaque affichage de page. --}}
            <section class="rw-section" id="planification">
                <div class="rw-section__entete">
                    <h2 class="rw-sous-titre-fort">{{ __('planif.titre') }}</h2>
                    <span class="rw-aide" id="schedule-count"></span>
                </div>
                <p class="rw-aide rw-prose">{{ __('planif.description') }}</p>

                <div class="rw-carte rw-carte--pleine">
                    <div class="rw-barre-filtres">
                        <label class="rw-etiquette-champ">
                            <span class="rw-champ__etiquette">{{ __('planif.champ_nom') }}</span>
                            <input type="text" id="sched-name" class="rw-saisie rw-saisie--compacte"
                                   maxlength="100" data-rw="planif-nom">
                        </label>
                        <label class="rw-etiquette-champ">
                            <span class="rw-champ__etiquette">{{ __('planif.champ_cron') }}</span>
                            <input type="text" id="sched-cron" class="rw-saisie rw-saisie--compacte"
                                   value="0 3 * * *" data-rw="planif-cron">
                        </label>
                        <label class="rw-etiquette-champ">
                            <span class="rw-champ__etiquette">{{ __('planif.champ_seuil') }}</span>
                            <select id="sched-cvss" class="rw-saisie rw-saisie--compacte">
                                <option value="0">0</option>
                                <option value="4">4</option>
                                <option value="7" selected>7</option>
                                <option value="9">9</option>
                            </select>
                        </label>
                        <label class="rw-etiquette-champ">
                            <span class="rw-champ__etiquette">{{ __('planif.champ_source') }}</span>
                            <select id="sched-source" class="rw-saisie rw-saisie--compacte"
                                    title="{{ __('planif.source_aide') }}">
                                <option value="fast">{{ __('planif.source_fast') }}</option>
                                <option value="hybrid" selected>{{ __('planif.source_hybrid') }}</option>
                                <option value="precise">{{ __('planif.source_precise') }}</option>
                            </select>
                        </label>
                        <label class="rw-etiquette-champ">
                            <span class="rw-champ__etiquette">{{ __('planif.champ_cible') }}</span>
                            <select id="sched-target" class="rw-saisie rw-saisie--compacte">
                                <option value="all">{{ __('planif.cible_all') }}</option>
                                @foreach ($tags as $tag)
                                    <option value="tag:{{ $tag }}">{{ __('planif.cible_tag') }} — {{ $tag }}</option>
                                @endforeach
                                <option value="multi">{{ __('planif.cible_machines') }}</option>
                            </select>
                        </label>
                    </div>

                    {{-- Selection multiple : masquee tant que la cible ne la
                         demande pas. Une liste vide serait refusee par le
                         service — et pour cause, cote scheduler une cible
                         `machines` illisible retombe sur TOUT le parc. --}}
                    <div id="sched-multi-list" class="rw-barre-filtres" hidden>
                        @foreach ($machines as $m)
                            <label class="rw-case">
                                <input type="checkbox" class="sched-multi-cb"
                                       value="{{ (int) $m->id }}" data-nom="{{ $m->name }}">
                                <span>{{ $m->name }}</span>
                            </label>
                        @endforeach
                        <span class="rw-aide" id="sched-multi-count"></span>
                        <button type="button" class="rw-bouton rw-bouton--minuscule"
                                data-rw="planif-tout-cocher">{{ __('planif.tout_cocher') }}</button>
                        <button type="button" class="rw-bouton rw-bouton--minuscule"
                                data-rw="planif-tout-decocher">{{ __('planif.tout_decocher') }}</button>
                    </div>

                    {{-- L'apercu remplace la PHRASE du legacy, fabriquee en Python
                         et donc intraduisible (E-53) : les cinq dates reelles,
                         mises en forme dans la langue de la session. --}}
                    <p class="rw-aide" id="cron-preview" aria-live="polite"></p>

                    <div class="rw-actions">
                        <div class="rw-actions__gauche">
                            <button type="button" class="rw-bouton rw-bouton--discret"
                                    data-rw="planif-presets">{{ __('planif.presets') }}</button>
                        </div>
                        <button type="button" class="rw-bouton"
                                data-rw="planif-ajouter">{{ __('planif.ajouter') }}</button>
                    </div>
                </div>

                {{-- Modeles de recurrence : un panneau EN LIGNE, pas une boite
                     native — elle recouvre la ligne sur laquelle on decide, ne se
                     style pas, et bloque Puppeteer. --}}
                <div class="rw-panneau-decision" id="cron-presets-modal" hidden>
                    <p class="rw-panneau-decision__texte">{{ __('planif.presets_titre') }}</p>
                    <div class="rw-barre-filtres">
                        <button type="button" class="rw-onglet" data-cron="0 * * * *">{{ __('planif.preset_horaire') }}</button>
                        <button type="button" class="rw-onglet" data-cron="0 */6 * * *">{{ __('planif.preset_6h') }}</button>
                        <button type="button" class="rw-onglet" data-cron="0 3 * * *">{{ __('planif.preset_quotidien') }}</button>
                        <button type="button" class="rw-onglet" data-cron="0 3 * * 1">{{ __('planif.preset_hebdo') }}</button>
                    </div>
                    <div class="rw-panneau-decision__actions">
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="planif-presets-fermer">{{ __('planif.confirmer_non') }}</button>
                    </div>
                </div>

                <div class="rw-tableau-cadre">
                    <table class="rw-tableau">
                        <thead>
                            <tr>
                                <th>{{ __('planif.col_nom') }}</th>
                                <th>{{ __('planif.col_recurrence') }}</th>
                                <th class="rw-colonne-secondaire">{{ __('planif.col_cible') }}</th>
                                <th>{{ __('planif.col_prochaine') }}</th>
                                <th class="rw-colonne-secondaire">{{ __('planif.col_derniere') }}</th>
                                <th class="rw-colonne-secondaire">{{ __('planif.col_auteur') }}</th>
                                <th>{{ __('planif.col_etat') }}</th>
                                {{-- « Actions », et non « Suivi » : cette colonne
                                     porte les boutons, pas l'etat de remediation
                                     de S5. Un en-tete doit nommer ce que la
                                     colonne CONTIENT. --}}
                                <th>{{ __('planif.col_actions') }}</th>
                            </tr>
                        </thead>
                        <tbody id="schedules-list"></tbody>
                    </table>
                </div>
            </section>
        @endif

        <section class="rw-section">
            <div class="rw-section__entete">
                <h2 class="rw-sous-titre-fort">{{ __('cve.section_serveurs') }}</h2>
            </div>

            @foreach ($machines as $m)
                @php($id = (int) $m->id)
                @php($scan = $derniers[$id] ?? null)
                @php($f = $facettes[$id] ?? ['severites' => [], 'annees' => [], 'total' => 0])
                <article class="rw-carte rw-carte--pleine" id="server-card-{{ $id }}">
                    <div class="rw-section__entete">
                        <div>
                            <h3 class="rw-sous-titre-fort">{{ $m->name }}</h3>
                            <p class="rw-aide">
                                <span class="rw-colonne-secondaire">{{ $m->ip }}</span>
                                @if ($m->environment)<span class="rw-pastille rw-pastille--neutre">{{ $m->environment }}</span>@endif
                                @if ($m->criticality)<span class="rw-pastille rw-pastille--neutre">{{ $m->criticality }}</span>@endif
                            </p>
                        </div>
                        <div class="rw-entete-page__actions">
                            {{-- Les compteurs et la date vivent dans des elements
                                 NOMMES : la suite de caracterisation les vise par
                                 ces identifiants, sur les deux portails. --}}
                            <span id="badges-{{ $id }}">
                                @if ($scan)
                                    @if ((int) $scan->critical_count > 0)
                                        <span class="rw-badge rw-badge--alerte">{{ (int) $scan->critical_count }} CRITICAL</span>
                                    @endif
                                    @if ((int) $scan->high_count > 0)
                                        <span class="rw-badge rw-badge--attention">{{ (int) $scan->high_count }} HIGH</span>
                                    @endif
                                    @if ((int) $scan->medium_count > 0)
                                        <span class="rw-badge">{{ (int) $scan->medium_count }} MEDIUM</span>
                                    @endif
                                @endif
                            </span>
                            @if ($scan)
                                <a class="rw-bouton rw-bouton--discret" data-rw="export-csv-{{ $id }}"
                                   href="{{ route('export-cve', ['machine_id' => $id]) }}">{{ __('cve.export_csv') }}</a>
                                <button type="button" class="rw-bouton rw-bouton--discret"
                                        data-rw="comparer-{{ $id }}" data-machine="{{ $id }}"
                                        title="{{ __('cve.comparer_aide') }}">{{ __('cve.comparer') }}</button>
                            @endif
                        </div>
                    </div>

                    @if (! $scan)
                        <div class="rw-vide rw-vide--compact">
                            <p class="rw-vide__titre">{{ __('cve.jamais_scanne') }}</p>
                            <p class="rw-vide__texte rw-prose">{{ __('cve.jamais_scanne_aide') }}</p>
                        </div>
                        {{-- Les deux conteneurs existent MEME sans scan : la suite
                             verifie qu'ils sont vides, ce qui ne veut rien dire
                             s'ils sont absents. --}}
                        <div id="results-{{ $id }}" hidden></div>
                        <div id="results-detail-{{ $id }}" hidden></div>
                    @else
                        <p class="rw-aide" id="last-scan-{{ $id }}">
                            {{ __('cve.dernier_scan') }} : {{ $scan->scan_date }}
                            — {{ (int) $scan->packages_scanned }} {{ __('cve.paquets_scannes') }}
                            — {{ __('cve.seuil_du_scan') }} {{ $scan->min_cvss }}
                        </p>

                        {{-- LE BLOC EST REPLIE AU PREMIER RENDU, comme sur le
                             legacy : 1458 lignes deployees d'office noieraient la
                             page. Le resume reste cliquable et le dit. --}}
                        <button type="button" class="rw-repliable" id="results-{{ $id }}"
                                data-rw="deplier-{{ $id }}" data-cible="results-detail-{{ $id }}"
                                aria-expanded="false" aria-controls="results-detail-{{ $id }}">
                            <span id="cve-chevron-{{ $id }}" class="rw-repliable__chevron" aria-hidden="true">›</span>
                            <span>{{ __('cve.nb_cve', ['nombre' => $f['total']]) }}</span>
                            <span class="rw-repliable__aide">{{ __('cve.voir_details') }}</span>
                        </button>

                        <div id="results-detail-{{ $id }}" hidden>
                            @if ($f['total'] === 0)
                                <p class="rw-aide">{{ __('cve.aucune_cve') }}</p>
                            @else
                                <div class="rw-barre-filtres" data-machine="{{ $id }}">
                                    <span class="rw-filtre__etiquette">{{ __('cve.filtre_severite') }}</span>
                                    <button type="button" class="rw-onglet rw-onglet--actif" data-sev="ALL">
                                        {{ __('cve.filtre_tout') }} ({{ $f['total'] }})</button>
                                    @foreach ($f['severites'] as $sev => $n)
                                        <button type="button" class="rw-onglet" data-sev="{{ $sev }}">{{ $sev }} ({{ $n }})</button>
                                    @endforeach
                                </div>
                                <div class="rw-barre-filtres" data-machine="{{ $id }}">
                                    <span class="rw-filtre__etiquette">{{ __('cve.filtre_annee') }}</span>
                                    <button type="button" class="rw-onglet rw-onglet--actif" data-an="ALL">
                                        {{ __('cve.filtre_toutes') }}</button>
                                    @foreach ($f['annees'] as $an => $n)
                                        <button type="button" class="rw-onglet" data-an="{{ $an }}">{{ $an }} ({{ $n }})</button>
                                    @endforeach
                                </div>
                                <div class="rw-recherche">
                                    <label>
                                        <span class="rw-visuellement-cache">{{ __('cve.recherche') }}</span>
                                        <input type="text" class="rw-saisie rw-saisie--compacte" data-machine="{{ $id }}"
                                               placeholder="{{ __('cve.recherche') }}">
                                    </label>
                                </div>

                                {{-- L'EN-TETE EST RENDU ICI, UNE FOIS, ET TRADUIT.
                                     Cote legacy il est fabrique par le script en
                                     six colonnes, alors que trois de ses quatre
                                     generateurs de lignes n'en produisent que
                                     cinq : le tableau se desaligne des qu'on le
                                     pagine ou qu'on le filtre (E-49). Ici le
                                     script ne remplit QUE le corps, par un seul
                                     generateur. --}}
                                <div class="rw-tableau-cadre">
                                    <table class="rw-tableau">
                                        <thead>
                                            <tr>
                                                <th class="rw-cve-id">{{ __('cve.col_cve') }}</th>
                                                <th>{{ __('cve.col_paquet') }}</th>
                                                <th class="rw-colonne-secondaire">{{ __('cve.col_version') }}</th>
                                                <th>{{ __('cve.col_severite') }}</th>
                                                <th class="rw-colonne-secondaire rw-cve-resume">{{ __('cve.col_resume') }}</th>
                                                <th>{{ __('cve.col_suivi') }}</th>
                                            </tr>
                                        </thead>
                                        <tbody id="findings-body-{{ $id }}"></tbody>
                                    </table>
                                </div>

                                {{-- Compteur et bouton PRESENTS MEME sous 50 CVE :
                                     le legacy ne les cree que s'il existe une page
                                     suivante, alors que la recherche et les
                                     filtres s'en servent toujours. Le bouton se
                                     cache quand il n'y a plus rien a charger, il
                                     ne disparait pas du DOM. --}}
                                <div class="rw-pagination">
                                    <span class="rw-aide" id="findings-count-{{ $id }}"></span>
                                    <button type="button" class="rw-bouton rw-bouton--discret"
                                            id="load-more-{{ $id }}" hidden>{{ __('cve.voir_plus') }}</button>
                                </div>
                            @endif
                        </div>

                        {{-- Le panneau de comparaison s'ouvre EN LIGNE, sous la
                             machine concernee : aucune boite native dans le
                             portage — elle recouvre la ligne sur laquelle on
                             decide, ne se style pas, et bloque Puppeteer. --}}
                        <div class="rw-panneau-decision" id="comparaison-{{ $id }}" hidden
                             data-rw="panneau-comparaison-{{ $id }}"></div>
                    @endif
                </article>
            @endforeach
        </section>
    @endif

    {{-- Les donnees partent EN DONNEES, pas en HTML fabrique : le script rend par
         `textContent`, et une valeur qui contient des caracteres de balisage reste
         du texte. Cote legacy tout passe par `innerHTML` (E-50).
         @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="cve-findings" type="application/json">@json($findings)</script>
    {{-- Le suivi STOCKE, et les libelles du sous-lot S5. `peut_ticket` voyage avec
         eux : le script en a besoin pour desactiver le bouton, pas pour decider —
         c'est le backend qui refuse. --}}
    <script id="cve-suivi" type="application/json">@json($suivi)</script>
    <script id="suivi-libelles" type="application/json">@json($libellesSuivi + ['peut_ticket' => $peutTicket])</script>
    <script id="cve-libelles" type="application/json">@json($libelles)</script>
    @if ($peutPlanifier)
        <script id="planif-libelles" type="application/json">@json($libellesPlanif)</script>
    @endif
    <script src="/js/scan-cve.js?v={{ @filemtime(public_path('js/scan-cve.js')) ?: '0' }}"></script>
    @if ($peutPlanifier)
        <script src="/js/planification-cve.js?v={{ @filemtime(public_path('js/planification-cve.js')) ?: '0' }}"></script>
    @endif
@endsection
