@extends('layouts.portail', ['titre' => __('nav.wazuh')])

@section('corps')
    <h1 class="rw-titre">{{ __('wazuh.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('wazuh.subtitle') }}</p>

    <div class="rw-carte rw-carte--pleine" data-rw="wazuh-portee">
        <h2 class="rw-sous-titre-fort">{{ __('wazuh.portee_titre') }}</h2>
        <p class="rw-prose">{{ __('wazuh.portee_texte') }}</p>
    </div>

    {{--
        ══ CE QUE R1 NE PORTE PAS — NOMME, PAS COMPTE ═══════════════════════

        « Neuf gestes ne sont pas portes » serait invérifiable ET
        infalsifiable. Et un COMPTE ecrit a cote d'une enumeration se
        desynchronise des que l'un des gestes est porte : ici il n'y a pas de
        compte, l'enumeration est la seule source.

        ⚠ La reserve qui suit n'est pas une precaution de style. Trois de ces
        gestes n'ont pas l'effet que leur nom suggere, MEME sur l'ancien
        portail — releve par lecture du backend :

          - `group` ne transmet jamais le groupe : la seule commande distante
            est un redemarrage, et l'agent qui redemarre se re-inscrit aupres
            du manager, qui lui assigne ce qu'il veut ;
          - `options` et `rules` (POST) n'atteignent AUCUNE machine. La page
            relit ce qu'elle a ecrit, donc l'ecran CONFIRME, et la boucle se
            referme sans que rien ne soit applique.

        Renvoyer quelqu'un vers l'ancien portail sans le dire serait
        l'envoyer croire un ecran qui se trompe.
    --}}
    <div class="rw-carte rw-carte--pleine" data-rw="wazuh-non-porte">
        <h2 class="rw-sous-titre-fort">{{ __('wazuh.np_titre') }}</h2>
        <p class="rw-prose" data-rw="wazuh-np-liste">{{ __('wazuh.np_liste') }}</p>
        <p class="rw-aide rw-prose" data-rw="wazuh-np-reserve">{{ __('wazuh.np_reserve') }}</p>
        <p class="rw-tuile__lien">
            <a class="rw-lien" href="{{ $lienLegacy }}" target="_blank" rel="noopener"
               data-rw="wazuh-np-lien">{{ __('wazuh.np_ouvrir') }} ↗</a>
        </p>
    </div>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('wazuh.config_title') }}</h2>
    <p class="rw-prose">{{ __('wazuh.config_desc') }}</p>
    <div data-rw="wazuh-config">
        <p class="rw-vide__texte">{{ __('wazuh.loading') }}</p>
    </div>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('wazuh.deploy_title') }}</h2>
    <div data-rw="wazuh-agents">
        <p class="rw-vide__texte">{{ __('wazuh.loading') }}</p>
    </div>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('wazuh.tab_options') }}</h2>
    @if (! $lisible)
        <div class="rw-vide rw-vide--erreur" data-rw="wazuh-perimetre-illisible">
            <p class="rw-vide__texte">{{ __('wazuh.err_servers') }}</p>
        </div>
    @elseif (! count($serveurs))
        <div class="rw-vide" data-rw="wazuh-aucun-serveur">
            <p class="rw-vide__texte">{{ __('wazuh.no_servers') }}</p>
        </div>
    @else
        <div class="rw-champ rw-champ--espace">
            <label class="rw-champ__etiquette" for="wazuh-serveur">{{ __('wazuh.server') }}</label>
            <select id="wazuh-serveur" class="rw-saisie rw-saisie--compacte" data-rw="wazuh-serveur">
                <option value="">{{ __('wazuh.select_server') }}</option>
                @foreach ($serveurs as $s)
                    <option value="{{ $s->id }}">{{ $s->name }} — {{ $s->ip }}</option>
                @endforeach
            </select>
        </div>
        <div data-rw="wazuh-options">
            <p class="rw-vide__texte">{{ __('wazuh.choisir_serveur') }}</p>
        </div>
    @endif

    <h2 class="rw-section__entete rw-titre--espace">{{ __('wazuh.rules_list') }}</h2>
    <div data-rw="wazuh-regles">
        <p class="rw-vide__texte">{{ __('wazuh.loading') }}</p>
    </div>

    <script id="wazuh-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/wazuh.js?v={{ @filemtime(public_path('js/wazuh.js')) ?: '0' }}"></script>
@endsection
