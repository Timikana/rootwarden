@extends('layouts.portail', ['titre' => __('nav.wazuh')])

@section('corps')
    <h1 class="rw-titre">{{ __('wazuh.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('wazuh.subtitle') }}</p>

    <div class="rw-carte rw-carte--pleine" data-rw="wazuh-portee">
        <h2 class="rw-sous-titre-fort">{{ __('wazuh.portee_titre') }}</h2>
        <p class="rw-prose">{{ __('wazuh.portee_texte') }}</p>
    </div>

    {{--
        ══ CE QUE R2 NE PORTE PAS — NOMME, PAS COMPTE ═══════════════════════

        ⚠ CE BLOC EST PASSE DE NEUF GESTES A SIX, ET LE COMPTE N'EST PAS LE
        SUJET. R1 enumerait neuf absences ; trois d'entre elles sont portees
        ici. **Une phrase qui promet plus de manques qu'il n'y en a est aussi
        fausse qu'une qui en promet moins** — et elle envoie chercher sur
        l'ancien portail un geste qui vit desormais sur celui-ci.

        Les six qui restent ont toutes la MEME raison, et c'est la seule qui
        vaille : **elles ouvrent une session SSH sur la machine.** Aucune n'a
        de bouton ici, pas meme grise — un bouton inerte est une promesse.

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

    {{--
        ⚠ CE QU'ENREGISTRER VEUT DIRE — ET LES TROIS GESTES DE CETTE PAGE NE
        DISENT PAS LA MEME CHOSE.

        Mesure du 2026-09-05, « qui LIT ce que ce geste ECRIT » :

            wazuh_config           lu par install() et install_all()
                                   -> effet DIFFERE, reel
            wazuh_machine_options  2 occurrences dans TOUT le depot : son
                                   propre SELECT et son propre INSERT
            wazuh_rules            lu par list_rules et get_rule seulement

        Un « Enregistre. » identique sur les trois ferait croire trois fois la
        meme chose, et deux fois ce serait faux. La phrase d'effet est donc
        ATTACHEE A CHAQUE GESTE, jamais mutualisee.
    --}}
    <p class="rw-prose rw-aide" data-rw="wazuh-config-effet">{{ __('wazuh.enr_config_effet') }}</p>

    <div data-rw="wazuh-config">
        <p class="rw-vide__texte">{{ __('wazuh.loading') }}</p>
    </div>

    <form class="rw-grille" data-rw="wazuh-config-form" hidden>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-manager-ip">{{ __('wazuh.manager_ip') }}</label>
            <input id="wz-manager-ip" class="rw-saisie" type="text" maxlength="253"
                   data-rw="wazuh-manager-ip" autocomplete="off">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-manager-port">{{ __('wazuh.manager_port') }}</label>
            <input id="wz-manager-port" class="rw-saisie" type="number" min="1" max="65535"
                   data-rw="wazuh-manager-port">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-registration-port">{{ __('wazuh.registration_port') }}</label>
            <input id="wz-registration-port" class="rw-saisie" type="number" min="1" max="65535"
                   data-rw="wazuh-registration-port">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-default-group">{{ __('wazuh.default_group') }}</label>
            <input id="wz-default-group" class="rw-saisie" type="text" maxlength="100"
                   data-rw="wazuh-default-group" autocomplete="off">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-agent-version">{{ __('wazuh.agent_version') }}</label>
            <input id="wz-agent-version" class="rw-saisie" type="text" maxlength="20"
                   data-rw="wazuh-agent-version" autocomplete="off">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-api-url">{{ __('wazuh.api_url') }}</label>
            <input id="wz-api-url" class="rw-saisie" type="text" maxlength="253"
                   data-rw="wazuh-api-url" autocomplete="off">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-api-user">{{ __('wazuh.api_user') }}</label>
            <input id="wz-api-user" class="rw-saisie" type="text" maxlength="100"
                   data-rw="wazuh-api-user" autocomplete="off">
        </div>

        {{--
            ⚠ LES DEUX MOTS DE PASSE NE SONT JAMAIS PREREMPLIS, ET CE N'EST PAS
            UN OUBLI : `get_config` les BLANCHIT avant de repondre
            (`wazuh.py:222-223`) et ne rend que deux booleens. Le portage ne
            peut donc pas les afficher, et il ne doit pas essayer.

            Ce que l'ecran doit dire, en revanche, c'est ce qu'un champ VIDE
            fait — et le backend le decide a `:268-270` : il CONSERVE l'ancienne
            valeur. *« Vide » ne veut pas dire « efface » ici, et personne ne
            peut le deviner d'un champ vide.*
        --}}
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-reg-pwd">{{ __('wazuh.registration_password') }}</label>
            <input id="wz-reg-pwd" class="rw-saisie" type="password" autocomplete="new-password"
                   placeholder="{{ __('wazuh.unchanged') }}" data-rw="wazuh-reg-pwd">
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-api-pwd">{{ __('wazuh.api_password') }}</label>
            <input id="wz-api-pwd" class="rw-saisie" type="password" autocomplete="new-password"
                   placeholder="{{ __('wazuh.unchanged') }}" data-rw="wazuh-api-pwd">
        </div>

        {{--
            `.rw-champ--case` et non `.rw-champ__etiquette` : cette derniere est
            en `display: block`, donc la case tombait SUR SA PROPRE LIGNE,
            au-dessus de son texte. Vu a l'image. Le motif employe ici est celui
            de `acces-sftp` et `bashrc` — une etiquette qui englobe la case ET
            le texte, donc toute la ligne est cliquable.
        --}}
        <label class="rw-champ rw-champ--case">
            <input type="checkbox" class="rw-case" data-rw="wazuh-enable-ar">
            <span>{{ __('wazuh.enable_active_response_global') }}</span>
        </label>
    </form>
    <p class="rw-prose rw-aide" data-rw="wazuh-mdp-conserve" hidden>{{ __('wazuh.mdp_conserve') }}</p>
    <div class="rw-actions" data-rw="wazuh-config-actions" hidden>
        <button type="button" class="rw-bouton" data-rw="wazuh-config-enregistrer">{{ __('wazuh.save') }}</button>
    </div>
    <p class="rw-annonce" data-rw="wazuh-config-annonce" role="status" aria-live="polite"></p>

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
        <p class="rw-prose rw-aide" data-rw="wazuh-options-effet">{{ __('wazuh.enr_options_effet') }}</p>

        <div data-rw="wazuh-options">
            <p class="rw-vide__texte">{{ __('wazuh.choisir_serveur') }}</p>
        </div>

        <form class="rw-grille" data-rw="wazuh-options-form" hidden>
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="wz-opt-format">{{ __('wazuh.log_format') }}</label>
                {{--
                    LISTE FERMEE, RENDUE DEPUIS SA SOURCE. `$formatsLog` vient du
                    controleur, qui la tient de `WazuhController::FORMATS_LOG` —
                    releve de `_LOG_FORMATS` (`wazuh.py:60`). Une liste recopiee
                    a la main dans le gabarit finirait par ne plus dire la meme
                    chose que le serveur qui l'applique.
                --}}
                <select id="wz-opt-format" class="rw-saisie rw-saisie--compacte" data-rw="wazuh-opt-format">
                    @foreach ($formatsLog as $f)
                        <option value="{{ $f }}">{{ $f }}</option>
                    @endforeach
                </select>
            </div>
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="wz-opt-freq">{{ __('wazuh.syscheck_frequency') }}</label>
                <input id="wz-opt-freq" class="rw-saisie" type="number" min="60" max="604800"
                       data-rw="wazuh-opt-freq">
            </div>
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="wz-opt-fim">{{ __('wazuh.fim_paths') }}</label>
                <textarea id="wz-opt-fim" class="rw-saisie rw-saisie--edition" rows="6" spellcheck="false"
                          data-rw="wazuh-opt-fim"></textarea>
                <p class="rw-aide">{{ __('wazuh.fim_aide') }}</p>
            </div>
            <div class="rw-champ">
                <label class="rw-champ rw-champ--case">
                    <input type="checkbox" class="rw-case" data-rw="wazuh-opt-ar">
                    <span>{{ __('wazuh.active_response') }}</span>
                </label>
                <label class="rw-champ rw-champ--case">
                    <input type="checkbox" class="rw-case" data-rw="wazuh-opt-sca">
                    <span>{{ __('wazuh.sca') }}</span>
                </label>
                <label class="rw-champ rw-champ--case">
                    <input type="checkbox" class="rw-case" data-rw="wazuh-opt-rk">
                    <span>{{ __('wazuh.rootcheck') }}</span>
                </label>
            </div>
        </form>
        <div class="rw-actions" data-rw="wazuh-options-actions" hidden>
            <button type="button" class="rw-bouton" data-rw="wazuh-options-enregistrer">{{ __('wazuh.save') }}</button>
        </div>
        <p class="rw-annonce" data-rw="wazuh-options-annonce" role="status" aria-live="polite"></p>
    @endif

    <h2 class="rw-section__entete rw-titre--espace">{{ __('wazuh.rules_list') }}</h2>
    <p class="rw-prose rw-aide" data-rw="wazuh-regles-effet">{{ __('wazuh.enr_regles_effet') }}</p>

    <div data-rw="wazuh-regles">
        <p class="rw-vide__texte">{{ __('wazuh.loading') }}</p>
    </div>

    <h3 class="rw-sous-titre-fort rw-titre--espace">{{ __('wazuh.regle_editeur_titre') }}</h3>
    <form data-rw="wazuh-regle-form">
        <div class="rw-grille">
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="wz-regle-nom">{{ __('wazuh.rule_name') }}</label>
                <input id="wz-regle-nom" class="rw-saisie" type="text" maxlength="100"
                       autocomplete="off" data-rw="wazuh-regle-nom">
                {{--
                    ⚠ CE TEXTE DECRIT LA FORME ADMISE, IL NE LA CONTROLE PAS.
                    `_NAME_RE` vit dans le backend (`wazuh.py:57`) et c'est lui
                    qui tranche. **Une regle de securite ne se recopie pas** :
                    deux expressions pour une meme regle divergent, et celle du
                    navigateur ne garde rien contre une requete forgee. Le champ
                    porte une BORNE (`maxlength`), pas un predicat.
                --}}
                <p class="rw-aide">{{ __('wazuh.regle_aide_nom') }}</p>
            </div>
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="wz-regle-type">{{ __('wazuh.regle_type') }}</label>
                <select id="wz-regle-type" class="rw-saisie rw-saisie--compacte" data-rw="wazuh-regle-type">
                    @foreach ($typesRegle as $cle => $libelle)
                        <option value="{{ $cle }}">{{ $libelle }}</option>
                    @endforeach
                </select>
            </div>
        </div>
        <div class="rw-champ">
            <label class="rw-champ__etiquette" for="wz-regle-contenu">{{ __('wazuh.regle_contenu') }}</label>
            <textarea id="wz-regle-contenu" class="rw-saisie rw-saisie--edition" rows="18" spellcheck="false"
                      data-rw="wazuh-regle-contenu"></textarea>
            <p class="rw-aide">{{ __('wazuh.regle_taille') }} {{ __('wazuh.regle_aide_xml') }}</p>
        </div>
    </form>
    <div class="rw-actions">
        <div class="rw-actions__gauche">
            <button type="button" class="rw-bouton rw-bouton--discret" data-rw="wazuh-regle-nouvelle">{{ __('wazuh.regle_nouvelle') }}</button>
            {{--
                LE BOUTON DE SUPPRESSION N'AGIT PAS : il OUVRE le panneau. Le
                geste destructeur est derriere une decision qui NOMME la regle —
                `confirm()` est proscrit ici, et surtout il ne nomme rien.
            --}}
            <button type="button" class="rw-bouton rw-bouton--danger" data-rw="wazuh-regle-supprimer" disabled>{{ __('wazuh.delete') }}</button>
        </div>
        <button type="button" class="rw-bouton" data-rw="wazuh-regle-enregistrer">{{ __('wazuh.save') }}</button>
    </div>
    <p class="rw-annonce" data-rw="wazuh-regle-annonce" role="status" aria-live="polite"></p>

    <div class="rw-panneau-decision" data-rw="wazuh-suppr-panneau" hidden>
        <p class="rw-panneau-decision__texte" data-rw="wazuh-suppr-question"></p>
        <p class="rw-aide rw-prose">{{ __('wazuh.suppr_consequence') }}</p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret" data-rw="wazuh-suppr-annuler">{{ __('wazuh.suppr_annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger" data-rw="wazuh-suppr-confirmer">{{ __('wazuh.suppr_confirmer') }}</button>
        </div>
    </div>

    <script id="wazuh-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/wazuh.js?v={{ @filemtime(public_path('js/wazuh.js')) ?: '0' }}"></script>
@endsection
