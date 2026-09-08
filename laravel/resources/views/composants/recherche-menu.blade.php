{{-- ══ LE PANNEAU DE RECHERCHE DE L'EN-TETE ═══════════════════════════════════

     Le legacy avait une recherche VIVANTE dans son menu ; le portage n'avait
     qu'une page. C'est la capacite qui manquait — pas un endpoint : la page
     `/recherche` appelle deja `GET /api/gateway/search`, et ce panneau appelle
     LE MEME chemin. Aucun second chemin pour un seul geste.

     ⚠ LA GARDE EST CELLE DE LA ROUTE, RELEVEE ET NON DEVINEE :
     `web.php:554  ->middleware(['role:2', 'perm:can_admin_portal'])`

     Sans cette condition, le champ s'afficherait pour un role 1 et chaque frappe
     rendrait une erreur de la passerelle. **Un controle qui ne peut qu'echouer
     n'est pas une capacite offerte, c'est une panne promise.** Et une permission
     vaut « cette permission OU superadmin », comme partout dans ce depot.
--}}
@php($rwRole = (int) session('role_id', 0))
@php($rwPerms = $rwRole >= 2 ? app(\App\Services\Droits::class)->permissions((int) session('utilisateur_id', 0)) : [])

@if ($rwRole >= 2 && ($rwRole >= 3 || ($rwPerms['can_admin_portal'] ?? false)))
    <details class="rw-recherche" data-rw="recherche-menu">
        <summary class="rw-lien" title="{{ __('search.tip_input') }}"
                 aria-label="{{ __('search.menu_ouvrir') }}" data-rw="recherche-menu-bascule">🔍</summary>

        <div class="rw-recherche__menu">
            {{-- Un `placeholder` n'est PAS un nom accessible : l'intitule existe,
                 il est seulement invisible. --}}
            <label class="rw-visuellement-cache" for="rw-recherche-champ">{{ __('search.label') }}</label>
            <input type="search" id="rw-recherche-champ"
                   class="rw-saisie rw-saisie--compacte rw-recherche__saisie"
                   placeholder="{{ __('search.placeholder') }}" autocomplete="off"
                   data-rw="recherche-menu-champ">

            <p class="rw-aide" role="status" aria-live="polite" data-rw="recherche-menu-etat"></p>
            <div data-rw="recherche-menu-resultats"></div>

            {{-- Le panneau plafonne a quelques lignes par categorie : la page
                 complete reste la sortie, et elle est ANNONCEE plutot que devinee. --}}
            <a class="rw-lien" href="{{ route('recherche') }}"
               data-rw="recherche-menu-tout">{{ __('search.menu_voir_tout') }}</a>
        </div>
    </details>

    {{-- Charges de donnees : la table de traduction des liens et les libelles.
         `@json` sur UNE ligne — multiligne casse le PHP compile. --}}
    <script id="rw-liens-legacy" type="application/json">@json(\App\Support\LiensLegacy::pourLeNavigateur())</script>
    <script id="rw-recherche-libelles" type="application/json">@json(__('search'))</script>
    <script src="/js/liens-legacy.js?v={{ @filemtime(public_path('js/liens-legacy.js')) ?: '0' }}"></script>
    <script src="/js/recherche-menu.js?v={{ @filemtime(public_path('js/recherche-menu.js')) ?: '0' }}"></script>
@endif
