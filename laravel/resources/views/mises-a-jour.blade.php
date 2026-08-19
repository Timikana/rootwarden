@extends('layouts.portail', ['titre' => __('maj.title')])

@section('corps')
    <div class="rw-entete-page">
        <div>
            <h1 class="rw-titre">{{ __('maj.title') }}</h1>
            <p class="rw-sous-titre rw-prose">{{ __('maj.desc') }}</p>
        </div>
        <div class="rw-entete-page__actions">
            <button class="rw-bouton rw-bouton--discret" id="refresh-list-btn" type="button"
                    data-rw="rafraichir" title="{{ __('maj.tip_refresh') }}">{{ __('maj.btn_refresh') }}</button>
        </div>
    </div>

    {{-- Portage PARTIEL, dit a l'ecran. Un module qu'on porte par morceaux
         laisse forcement des capacites derriere lui : les faire disparaitre
         sans un mot ferait croire qu'elles n'existent plus. --}}
    <div class="rw-encart rw-prose">
        <strong>{{ __('maj.partiel_titre') }}</strong>
        <p class="rw-tuile__texte">{{ __('maj.partiel_texte') }}</p>
        <p class="rw-tuile__lien">
            <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/update/"
               target="_blank" rel="noopener" data-rw="vers-legacy">{{ __('maj.partiel_lien') }} ↗</a>
        </p>
    </div>

    <div class="rw-barre-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_environment') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="environment" data-rw="f-environnement">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['PROD', 'DEV', 'TEST', 'OTHER'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_criticality') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="criticality" data-rw="f-criticite">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['CRITIQUE', 'NON CRITIQUE'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_network') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="network-type" data-rw="f-reseau">
                <option value="">{{ __('maj.tous') }}</option>
                @foreach (['INTERNE', 'EXTERNE'] as $valeur)
                    <option value="{{ $valeur }}">{{ $valeur }}</option>
                @endforeach
            </select>
        </label>

        {{-- Etiquettes. Elles sont posees par le module `adm/`, non porte : cette
             page ne fait que les lire. Aucune etiquette au parc est un etat
             normal — le champ le DIT au lieu de proposer une liste vide. --}}
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('maj.f_tag') }}</span>
            <select class="rw-saisie rw-saisie--compacte" id="tag-filter" data-rw="f-etiquette"
                    @if (! count($etiquettes)) disabled @endif
                    title="{{ count($etiquettes) ? __('maj.tip_tag') : __('maj.tip_tag_vide') }}">
                <option value="">{{ count($etiquettes) ? __('maj.tous') : __('maj.tag_aucune') }}</option>
                @foreach ($etiquettes as $etiquette)
                    <option value="{{ $etiquette }}">{{ $etiquette }}</option>
                @endforeach
            </select>
        </label>

        <button class="rw-bouton rw-bouton--discret" id="filter-btn" type="button"
                data-rw="filtrer">{{ __('maj.btn_filter') }}</button>
    </div>


    {{-- Actions groupees — sous-lot U3. Une seule pour l'instant : le constat
         « paquets en attente ». La simulation du legacy n'est PAS portee, et
         l'encart de portage partiel ci-dessus renvoie vers elle. --}}
    <div class="rw-actions rw-actions--groupe">
        <p class="rw-actions__compteur" id="selection-count" data-rw="compteur-selection"
           data-nombre="0" role="status" aria-live="polite">{{ __('maj.selection_vide') }}</p>
        <button class="rw-bouton rw-bouton--discret" id="pending-packages-btn" type="button"
                data-rw="paquets-en-attente"
                title="{{ __('maj.tip_paquets') }}">{{ __('maj.btn_paquets') }}</button>
        <button class="rw-bouton rw-bouton--danger" id="reboot-btn" type="button"
                data-rw="redemarrer"
                title="{{ __('maj.tip_reboot_action') }}">{{ __('maj.btn_reboot_action') }}</button>
    </div>

    {{-- Redemarrage — sous-lot U5. La decision se prend EN LIGNE, sous l'action,
         et non dans deux `confirm()` natifs empiles : le legacy pose deux fois la
         MEME question, ce qui se clique deux fois par reflexe et n'empeche rien.

         Ici le bouton naît desactive et ne s'active que si le nombre de machines
         est recopie. Le panneau NOMME les machines, dit ce qui sera interrompu,
         et annonce AVANT le geste qu'un second administrateur devra valider. --}}
    <div class="rw-panneau-decision" id="reboot-panneau" data-rw="panneau-redemarrage" hidden>
        <div class="rw-panneau-decision__texte">
            <strong>{{ __('maj.reboot_titre') }}</strong>
            <p class="rw-aide" id="reboot-machines" data-rw="redemarrage-machines"></p>
            <p class="rw-aide">{{ __('maj.reboot_consequences') }}</p>
            <p class="rw-aide" id="reboot-approbation" data-rw="redemarrage-approbation">
                {{ __('maj.reboot_quatre_yeux') }}
            </p>
        </div>

        <label class="rw-etiquette-champ">
            {{ __('maj.reboot_delai') }}
            <select class="rw-saisie rw-saisie--compacte" id="reboot-delai" data-rw="redemarrage-delai">
                <option value="0">{{ __('maj.reboot_delai_0') }}</option>
                <option value="5">{{ __('maj.reboot_delai_5') }}</option>
                <option value="15">{{ __('maj.reboot_delai_15') }}</option>
                <option value="60">{{ __('maj.reboot_delai_60') }}</option>
            </select>
        </label>

        {{-- Recopier le nombre : un geste delibere, la ou deux « OK » d'affilee
             ne sont qu'un reflexe. --}}
        <label class="rw-etiquette-champ">
            <span id="reboot-consigne" data-rw="redemarrage-consigne"></span>
            <input type="text" class="rw-saisie rw-saisie--compacte" id="reboot-nombre"
                   data-rw="redemarrage-nombre" autocomplete="off" inputmode="numeric">
        </label>

        <div class="rw-panneau-decision__actions">
            <button class="rw-bouton rw-bouton--discret" id="reboot-annuler" type="button"
                    data-rw="redemarrage-annuler">{{ __('maj.btn_cancel') }}</button>
            <button class="rw-bouton rw-bouton--danger" id="reboot-confirmer" type="button"
                    data-rw="redemarrage-confirmer" disabled>{{ __('maj.btn_reboot_confirmer') }}</button>
        </div>
    </div>

    {{-- Planification — sous-lot U4. Un SEUL formulaire pour les deux natures
         (generale, securite) : les champs sont les memes, seule la route et la
         lecture de la recurrence changent. Le legacy a deux fenetres modales
         qui repetent le meme formulaire.

         `hidden` plutot qu'une classe : l'etat se lit sur la geometrie. --}}
    <form class="rw-carte rw-carte--pleine" id="schedule-form" data-rw="formulaire-planification"
          hidden onsubmit="return false;">
        <h2 class="rw-sous-titre-fort" id="sched-titre" data-rw="titre-planification"></h2>
        <p class="rw-sous-titre rw-prose" id="sched-machine" data-rw="machine-planification"></p>

        <div class="rw-grille rw-grille--compacte">
            <label class="rw-champ">
                <span class="rw-champ__etiquette">{{ __('maj.f_date') }}</span>
                <input type="date" id="sched-date" class="rw-saisie" data-rw="date">
            </label>

            <label class="rw-champ">
                <span class="rw-champ__etiquette">{{ __('maj.f_time') }}</span>
                <input type="time" id="sched-time" class="rw-saisie" data-rw="heure">
            </label>

            <label class="rw-champ">
                <span class="rw-champ__etiquette">{{ __('maj.f_repeat') }}</span>
                <select id="sched-repeat" class="rw-saisie" data-rw="recurrence">
                    <option value="none">{{ __('maj.repeat_none') }}</option>
                    <option value="daily">{{ __('maj.repeat_daily') }}</option>
                    <option value="weekly">{{ __('maj.repeat_weekly') }}</option>
                    <option value="monthly">{{ __('maj.repeat_monthly') }}</option>
                </select>
            </label>
        </div>

        {{-- CE QUE LE BACKEND VA REELLEMENT ECRIRE, avant le geste. Les quatre
             recurrences ne veulent pas dire ce que leur nom laisse croire :
             « ne pas repeter » revient chaque annee, et la planification
             generale place l'hebdomadaire le LUNDI et le mensuel le PREMIER du
             mois, quelle que soit la date choisie. --}}
        <p class="rw-apercu" id="sched-apercu" role="status" aria-live="polite"
           data-rw="apercu"></p>

        <div class="rw-actions">
            <button class="rw-bouton rw-bouton--discret rw-actions__gauche" id="sched-cancel"
                    type="button" data-rw="annuler-planification">{{ __('maj.btn_cancel') }}</button>
            <button class="rw-bouton" id="sched-save" type="button" data-rw="enregistrer-planification"
                    title="{{ __('maj.tip_save_sched') }}">{{ __('maj.btn_save_sched') }}</button>
        </div>
    </form>

    {{-- Les identifiants et les CLASSES de colonne sont ceux du legacy
         (`server-table-body`, `.linux-version`, `.maj-secu-date`...) : le MEME
         test de caracterisation vise les deux cibles. --}}
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('maj.th_selection') }}</th>
                    <th>{{ __('maj.th_name') }}</th>
                    <th>{{ __('maj.th_actions') }}</th>
                    <th>{{ __('maj.th_linux') }}</th>
                    <th>{{ __('maj.th_last_check') }}</th>
                    <th>{{ __('maj.th_ip_port') }}</th>
                    <th>{{ __('maj.th_status') }}</th>
                    <th>{{ __('maj.th_secu_schedule') }}</th>
                    <th>{{ __('maj.th_last_exec') }}</th>
                    <th>{{ __('maj.th_last_reboot') }}</th>
                    <th>{{ __('maj.th_env') }}</th>
                    <th>{{ __('maj.th_criticality') }}</th>
                    <th>{{ __('maj.th_network') }}</th>
                </tr>
            </thead>
            <tbody id="server-table-body"></tbody>
        </table>
    </div>

    <p class="rw-annonce" id="maj-annonce" role="status" aria-live="polite" data-rw="annonce"></p>

    {{-- Journal d'execution — sous-lot U2. Presentation pure : il est alimente
         par les autres sous-lots via `window.rwJournal`. Les identifiants et
         les classes sont ceux du legacy (`logs-container`, `logs`,
         `.server-log-window`, `.log-window`, `.log-line`) : le MEME test vise
         les deux cibles. --}}
    <section class="rw-journal" data-rw="journal">
        <div class="rw-entete-page">
            <div>
                <h2 class="rw-sous-titre-fort">{{ __('maj.journal_titre') }}</h2>
                <p class="rw-sous-titre rw-prose">{{ __('maj.journal_desc') }}</p>
            </div>
            <div class="rw-entete-page__actions">
                <button class="rw-bouton rw-bouton--discret" id="clear-logs-btn" type="button"
                        data-rw="vider-journal"
                        title="{{ __('maj.tip_vider') }}">{{ __('maj.btn_vider') }}</button>
            </div>
        </div>

        {{-- Zone GENERALE. Le legacy la rend aussi mais ne l'alimente jamais :
             `appendLog` y est defini deux fois et la seconde definition ecrase
             la premiere. Ici elle recoit vraiment les messages sans serveur. --}}
        <div class="rw-journal__general" id="logs" data-rw="journal-general"
             aria-label="{{ __('maj.journal_general') }}"></div>

        {{-- Un panneau par serveur, cree a la premiere ligne. --}}
        <div class="rw-journal__panneaux" id="logs-container" data-rw="journal-panneaux"></div>
    </section>

    {{-- Le parc est rendu par le script a partir de ces donnees : le MEME code
         sert le premier rendu et les suivants, il ne peut donc pas exister deux
         versions du tableau qui divergent. --}}
    <script id="maj-parc" type="application/json">@json($machines)</script>
    @php($libelles = ['non_verifie' => __('maj.non_verifie'), 'inconnu' => __('maj.inconnu'), 'aucune' => __('maj.aucune'), 'en_cours' => __('maj.en_cours'), 'btn_version' => __('maj.btn_version'), 'tip_version' => __('maj.tip_version'), 'btn_statut' => __('maj.btn_statut'), 'tip_statut' => __('maj.tip_statut'), 'btn_reboot' => __('maj.btn_reboot'), 'tip_reboot' => __('maj.tip_reboot'), 'vide' => __('maj.vide'), 'vide_aide' => __('maj.vide_aide'), 'vide_filtre' => __('maj.vide_filtre'), 'vide_filtre_aide' => __('maj.vide_filtre_aide'), 'maj_ok' => __('maj.maj_ok'), 'filtre_ok' => __('maj.filtre_ok'), 'err_load' => __('maj.err_load'), 'err_releve' => __('maj.err_releve'), 'releve_ok' => __('maj.releve_ok'), 'selection' => __('maj.selection'), 'selection_vide' => __('maj.selection_vide'), 'aucune_selection' => __('maj.aucune_selection'), 'paquets_en_cours' => __('maj.paquets_en_cours'), 'paquets_err' => __('maj.paquets_err'), 'paquets_aucun' => __('maj.paquets_aucun'), 'paquets_aucun_reserve' => __('maj.paquets_aucun_reserve'), 'paquets_nombre' => __('maj.paquets_nombre'), 'paquets_fin' => __('maj.paquets_fin'), 'paquets_fin_partielle' => __('maj.paquets_fin_partielle'), 'btn_planifier' => __('maj.btn_planifier'), 'tip_planifier' => __('maj.tip_planifier'), 'btn_planifier_secu' => __('maj.btn_planifier_secu'), 'tip_planifier_secu' => __('maj.tip_planifier_secu'), 'reboot_machines' => __('maj.reboot_machines'), 'reboot_consigne' => __('maj.reboot_consigne'), 'reboot_en_cours' => __('maj.reboot_en_cours'), 'reboot_demande' => __('maj.reboot_demande'), 'reboot_attente' => __('maj.reboot_attente'), 'reboot_envoye' => __('maj.reboot_envoye'), 'reboot_fenetre' => __('maj.reboot_fenetre'), 'reboot_err' => __('maj.reboot_err'), 'reboot_fin' => __('maj.reboot_fin'), 'reboot_fin_attente' => __('maj.reboot_fin_attente'), 'reboot_fin_partielle' => __('maj.reboot_fin_partielle')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="maj-libelles" type="application/json">@json($libelles)</script>

    @php($planif = ['titre_general' => __('maj.titre_general'), 'titre_secu' => __('maj.titre_secu'), 'desc_general' => __('maj.desc_general'), 'desc_secu' => __('maj.desc_secu'), 'apercu_incomplet' => __('maj.apercu_incomplet'), 'apercu_daily' => __('maj.apercu_daily'), 'apercu_weekly' => __('maj.apercu_weekly'), 'apercu_monthly' => __('maj.apercu_monthly'), 'apercu_none' => __('maj.apercu_none'), 'reserve_annuel' => __('maj.reserve_annuel'), 'reserve_lundi' => __('maj.reserve_lundi'), 'reserve_premier' => __('maj.reserve_premier'), 'sched_incomplet' => __('maj.sched_incomplet'), 'sched_en_cours' => __('maj.sched_en_cours'), 'sched_pose' => __('maj.sched_pose'), 'sched_ok' => __('maj.sched_ok'), 'sched_err' => __('maj.sched_err'), 'jours' => [__('maj.j_lundi'), __('maj.j_mardi'), __('maj.j_mercredi'), __('maj.j_jeudi'), __('maj.j_vendredi'), __('maj.j_samedi'), __('maj.j_dimanche')]])
    <script id="maj-planif-libelles" type="application/json">@json($planif)</script>

    @php($journal = ['suivre' => __('maj.suivre'), 'suivre_aide' => __('maj.suivre_aide'), 'vide' => __('maj.journal_vide')])
    <script id="journal-libelles" type="application/json">@json($journal)</script>

    {{-- Le journal AVANT la page : les autres sous-lots s'appuieront sur
         `window.rwJournal`, il doit exister quand ils s'initialisent. --}}
    <script src="/js/journal-execution.js?v={{ @filemtime(public_path('js/journal-execution.js')) ?: '0' }}"></script>
    <script src="/js/mises-a-jour.js?v={{ @filemtime(public_path('js/mises-a-jour.js')) ?: '0' }}"></script>
@endsection
