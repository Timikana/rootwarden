@extends('layouts.portail', ['titre' => __('fail2ban.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('fail2ban.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('fail2ban.intro') }}</p>

@if ($total === 0)
    <div class="rw-vide" data-rw="f2b-vide">
        <p class="rw-vide__titre">{{ __('fail2ban.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('fail2ban.vide_texte') }}</p>
        <a class="rw-bouton rw-vide__action" href="{{ route('serveurs') }}">{{ __('fail2ban.vide_action') }}</a>
    </div>
@else

@if ($sensibles > 0)
    <div class="rw-avertissement" data-rw="f2b-avert">
        <strong>{{ __('fail2ban.avert_titre') }}</strong>
        <span class="rw-aide">
            {{ $sensibles === 1
                ? __('fail2ban.avert_un', ['total' => $total])
                : __('fail2ban.avert_plusieurs', ['nb' => $sensibles, 'total' => $total]) }}
        </span>
    </div>
@endif

<div class="rw-section">
    <label class="rw-champ">
        <span class="rw-champ__etiquette">{{ __('fail2ban.serveur') }}</span>
        <select class="rw-saisie" data-rw="f2b-serveur">
            <option value="">{{ __('fail2ban.choisir') }}</option>
            @foreach ($lignes as $l)
                <option value="{{ $l['machine']->id }}"
                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                        data-histo="{{ $l['histo'] }}"
                        data-nom="{{ $l['machine']->name }}">
                    {{ $l['machine']->name }} ({{ $l['machine']->ip }}){{ $l['sensible'] ? ' — ' . __('fail2ban.sensible') : '' }}
                </option>
            @endforeach
        </select>
    </label>

    {{--
        L'AVERTISSEMENT VIENT AVANT L'ACTION, ET C'EST LE POINT.

        Il etait rendu SOUS le bouton : on lisait « cette machine est en
        production » apres avoir decide de relever son etat. Vu a l'image du
        sous-lot F1, invisible a toute assertion — la propriete « le message
        existe » etait verte dans les deux dispositions.
    --}}
    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="f2b-etat-message">{{ __('fail2ban.choisir') }}</p>
    <div class="rw-actions">
        {{--
            LES DEUX LECTURES SONT DES ACTIONS SECONDAIRES, donc a gauche : le
            geste principal de cette page reste le releve. Elles restent cachees
            tant qu'aucun releve n'a dit que fail2ban est installe — proposer de
            lire un fichier dont on sait qu'il n'existe pas n'est pas une offre.
        --}}
        <div class="rw-actions__gauche">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="f2b-voir-config" hidden>{{ __('fail2ban.voir_config') }}</button>
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="f2b-voir-logs" hidden>{{ __('fail2ban.voir_logs') }}</button>
        </div>
        <button type="button" class="rw-bouton" data-rw="f2b-relever"
                disabled>{{ __('fail2ban.relever') }}</button>
    </div>
</div>

{{--
    ── LE PANNEAU DE DECISION, AU NIVEAU DE LA PAGE ────────────────────────

    Il vivait DANS le detail d'une jail. Or il sert aussi aux gestes de la liste
    blanche, qui s'exercent detail ferme : le panneau s'ouvrait alors dans un
    parent cache, donc **il ne s'affichait pas** — et un geste destructeur
    partait sans que rien ne l'ait annonce. Un element partage par plusieurs
    sections ne vit dans aucune d'elles.

    Le legacy ouvre un `confirm()` natif qui dit « Bannir cette IP ? » — il ne
    nomme NI l'adresse, NI la jail, NI la machine, alors que les trois lui sont
    passees (E-167). Un panneau en page peut dire ce que l'action ENGAGE ; une
    boite native tient en une ligne et s'accepte au reflexe.
--}}
<div class="rw-panneau-decision" data-rw="f2b-confirmation" hidden>
    <div class="rw-panneau-decision__texte">
        <p class="rw-sous-titre-fort" data-rw="f2b-confirmation-titre"></p>
        <p class="rw-aide" data-rw="f2b-confirmation-texte"></p>
    </div>
    {{--
        ── F6 : POUR UN GESTE DE PARC, LE PANNEAU DEMANDE UN AUTRE GESTE ───

        Deux « oui » d'affilee sont un reflexe, pas deux decisions. Pour les deux
        gestes qui partent vers PLUSIEURS machines a la fois, le bouton de
        confirmation nait DESACTIVE et ne s'active qu'a l'egalite exacte avec le
        NOMBRE de machines touchees — le nombre qu'on veut justement faire lire.

        Ce bloc reste MASQUE pour les gestes machine par machine (F4, F5) : leur
        confirmation part au premier clic, comme avant. Une exigence de recopie
        posee sur tous les gestes ferait de la recopie un reflexe a son tour.
    --}}
    <label class="rw-etiquette-champ" data-rw="f2b-recopie-bloc" hidden>
        <span>{{ __('fail2ban.recopie_etiquette') }}</span>
        <input type="text" class="rw-saisie rw-saisie--court" data-rw="f2b-recopie"
               inputmode="numeric" autocomplete="off" spellcheck="false">
        <span class="rw-aide">{{ __('fail2ban.recopie_aide') }}</span>
        <span class="rw-erreur" data-rw="f2b-recopie-message" hidden>{{ __('fail2ban.recopie_faux') }}</span>
    </label>
    <div class="rw-panneau-decision__actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="f2b-annuler">{{ __('fail2ban.conf_annuler') }}</button>
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="f2b-confirmer">{{ __('fail2ban.conf_confirmer') }}</button>
    </div>
</div>

{{--
    ── LE JOURNAL DES GESTES, AU NIVEAU DE LA PAGE LUI AUSSI ───────────────

    Il vivait DANS le detail d'une jail. Or les trois gestes de la liste blanche
    et l'activation d'une jail s'exercent detail FERME : leur verdict s'ecrivait
    donc dans une section `hidden` — invisible, alors que c'est la seule chose
    qui dit si le geste a abouti. Deuxieme fois que ce module paie « un element
    partage par plusieurs sections ne vit dans aucune d'elles » : F5 l'a corrige
    pour le PANNEAU et l'a laisse sur le JOURNAL.

    F6 rend le defaut incontournable : `install_all` ne vise AUCUNE jail, donc
    son resultat n'aurait jamais pu s'afficher.

    Vide, le cadre DIT qu'il est vide (`rw-journal--vide` rend `aria-label` en
    contenu) plutot que d'etre un rectangle muet.
--}}
<div class="rw-section" data-rw="f2b-journal-bloc">
    <h2 class="rw-section__entete">{{ __('fail2ban.geste_journal') }}</h2>
    <div class="rw-journal__general rw-journal--vide" data-rw="f2b-journal"
         aria-live="polite" aria-label="{{ __('fail2ban.geste_vide') }}"></div>
</div>

{{--
    ── LE DERNIER RELEVÉ CONNU, ET SA DATE ─────────────────────────────────

    Lu dans le cache `fail2ban_status`, pas sur la machine : ouvrir la page ne
    doit pas joindre trois machines en SSH. Mais **un état sans sa date se prend
    pour un état courant** — la date est donc rendue avec, et l'encart le dit.
--}}
<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('fail2ban.cache_titre') }}</h2>
    <p class="rw-aide">{{ __('fail2ban.cache_aide') }}</p>
    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('fail2ban.serveur') }}</th>
                    <th>{{ __('fail2ban.etat') }}</th>
                    <th>{{ __('fail2ban.bannies') }}</th>
                    <th>{{ __('fail2ban.cache_titre') }}</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($lignes as $l)
                    <tr @class(['rw-ligne-sensible' => $l['sensible']])
                        data-rw="f2b-cache-{{ $l['machine']->id }}">
                        <td>
                            <span class="rw-tableau__fort">{{ $l['machine']->name }}</span>
                            @if ($l['sensible'])
                                <span class="rw-badge rw-badge--alerte"
                                      title="{{ __('fail2ban.sensible_avert') }}">{{ __('fail2ban.sensible') }}</span>
                            @endif
                        </td>
                        <td>
                            @php
                                $c = $l['cache'];
                                $etat = $c === null ? null : (! $c['installe'] ? 'absent' : (! $c['actif'] ? 'arrete' : 'actif'));
                            @endphp
                            @if ($etat === null)
                                <span class="rw-tableau__discret">{{ __('fail2ban.cache_jamais') }}</span>
                            @else
                                <span class="rw-pastille rw-pastille--{{ $etat === 'actif' ? 'ok' : ($etat === 'absent' ? 'echec' : 'attente') }}">
                                    {{ __('fail2ban.etat_' . $etat) }}
                                </span>
                                @if ($etat !== 'actif')
                                    <div class="rw-aide">{{ __('fail2ban.etat_' . $etat . '_aide') }}</div>
                                @endif
                            @endif
                        </td>
                        <td>{{ $c === null ? '—' : $c['bannis'] }}</td>
                        <td class="rw-tableau__discret">
                            {{ $c === null ? __('fail2ban.cache_jamais') : __('fail2ban.cache_le', ['date' => $c['releve_le']]) }}
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>
</div>

<div class="rw-section" data-rw="f2b-statut" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.etat') }}</h2>
    <div data-rw="f2b-statut-contenu"></div>
</div>

<div class="rw-section" data-rw="f2b-jails-bloc" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.jails') }}</h2>
    <p class="rw-aide" data-rw="f2b-jails-compte"></p>
    <div class="rw-grille" data-rw="f2b-jails"></div>
</div>

{{--
    ── LE DETAIL D'UNE JAIL, ET LES DEUX GESTES QUI ECRIVENT ───────────────

    Le legacy aligne TROIS boutons destructeurs alimentes par le meme champ, et
    celui du milieu bannit sur TOUTES les machines de production. Les deux plus
    dangereux sont d'ailleurs les seuls a avoir perdu leur couleur d'alerte —
    `bg-red-800` et `bg-orange-600` sont purgees (E-166).

    Ici : deux gestes seulement, le ban de parc appartenant a F6 et n'etant pas
    rendu. Leurs couleurs viennent des JETONS du socle, pas d'une classe
    utilitaire — une couleur d'alerte ne doit pas dependre d'un purge.
--}}
<div class="rw-section" data-rw="f2b-jail-detail" hidden>
    <div class="rw-section__tete">
        <h2 class="rw-section__entete" data-rw="f2b-jail-nom"></h2>
        {{-- F7 : ce geste BAISSE UNE GARDE. Ton « avertissement » et non
             « danger » : rien n'est detruit, et « Activer la jail » le retablit —
             mais la machine cesse d'etre protegee. Deux rouges pour deux niveaux
             de consequence ne signalent plus rien, et cette vue reserve deja le
             rouge aux gestes de parc. --}}
        <button type="button" class="rw-bouton rw-bouton--avertissement rw-bouton--minuscule"
                data-rw="f2b-jail-desactiver">{{ __('fail2ban.jail_desactiver') }}</button>
        {{-- La reserve vit ICI, a cote du bouton, donc lue AVANT le clic — pas
             dans le panneau qui s'ouvre apres. `demande()` ne lit que `bloque`
             et `recopie` : lui passer une option de plus aurait transmis une
             cle que personne ne lit. --}}
        <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                data-rw="f2b-jail-fermer">{{ __('fail2ban.jail_fermer') }}</button>
    </div>
    <p class="rw-aide" data-rw="f2b-desact-jamais">{{ __('fail2ban.desact_jamais_exercee') }}</p>
    <dl class="rw-faits" data-rw="f2b-jail-config"></dl>

    <h3 class="rw-sous-titre-fort">{{ __('fail2ban.bannies_titre') }}</h3>
    <div data-rw="f2b-bannies-message"></div>
    <div class="rw-tableau-cadre" data-rw="f2b-bannies-cadre" hidden>
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('fail2ban.bannies_th_ip') }}</th>
                    <th>{{ __('fail2ban.bannies_th_action') }}</th>
                </tr>
            </thead>
            <tbody data-rw="f2b-bannies-corps"></tbody>
        </table>
    </div>

    <label class="rw-champ rw-champ--espace">
        <span class="rw-champ__etiquette">{{ __('fail2ban.ban_etiquette') }}</span>
        <input type="text" class="rw-saisie" data-rw="f2b-ban-ip"
               placeholder="{{ __('fail2ban.ban_placeholder') }}"
               autocomplete="off" spellcheck="false">
    </label>
    <p class="rw-aide">{{ __('fail2ban.ban_aide') }}</p>
    <div class="rw-actions">
        <div class="rw-actions__gauche">
            <button type="button" class="rw-bouton rw-bouton--avertissement"
                    data-rw="f2b-tout-debannir">{{ __('fail2ban.tout_debannir') }}</button>
        </div>
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="f2b-bannir">{{ __('fail2ban.bannir') }}</button>
    </div>

    {{--
        ── F6 : BANNIR SUR TOUT LE PARC ────────────────────────────────────

        Ce geste vit ICI, et non dans la section de parc, parce qu'il lit
        l'adresse et la jail de cet ecran-la. Mais il est SORTI de la rangee
        d'actions : le legacy aligne trois boutons alimentes par le meme champ,
        et celui du milieu bannit sur toutes les machines actives du parc — a
        deux centimetres de celui qui n'en bannit qu'une. Rien ne les distingue
        que leur libelle.

        Il dit sa portee AVANT le geste, chiffree et nommee. Elle vient de la
        meme donnee que la section de parc : les deux ne peuvent pas diverger.
    --}}
    <div class="rw-encart" data-rw="f2b-parc-ban">
        <p class="rw-sous-titre-fort">{{ __('fail2ban.parc_ban_titre') }}</p>
        <p class="rw-aide" data-rw="f2b-parc-ban-aide"></p>
        @if ($peutParc)
            <div class="rw-actions">
                <button type="button" class="rw-bouton rw-bouton--danger"
                        data-rw="f2b-bannir-parc">{{ __('fail2ban.parc_bannir') }}</button>
            </div>
        @else
            <p class="rw-prose">{{ __('fail2ban.parc_role') }}</p>
        @endif
    </div>
</div>

<div class="rw-section" data-rw="f2b-services-bloc" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.services_titre') }}</h2>
    <p class="rw-aide">{{ __('fail2ban.services_aide') }}</p>
    <div data-rw="f2b-services-message"></div>
    {{--
        UN SERVICE ABSENT SE DIT, IL NE SE DEVINE PAS A UNE OPACITE.

        Le legacy distingue installe et absent par `opacity-50` — une classe
        Tailwind. Elle n'est pas purgee aujourd'hui (mesure : 1 et 0.5), mais une
        distinction qui ne tient qu'a une classe utilitaire est a un purge pres
        de disparaitre, et elle ne dit rien a un lecteur d'ecran. Chaque ligne
        porte donc le MOT.
    --}}
    <div class="rw-liste-etats" data-rw="f2b-services"></div>
</div>

{{--
    ── UN FICHIER DISTANT, ET CE QUI ARRIVE QUAND IL N'EXISTE PAS ──────────

    Les deux commandes se terminent par `|| echo "[FICHIER ABSENT]"`. Le legacy
    pose ce retour dans le meme bloc vert sur noir qu'une vraie configuration :
    le marqueur du shell devient le contenu du fichier (E-161). Ici, l'absence
    est reconnue et ANNONCEE, dans la langue de l'interface.
--}}
<div class="rw-section" data-rw="f2b-config" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.config_titre') }}</h2>
    <p class="rw-aide" data-rw="f2b-config-source"></p>
    <div data-rw="f2b-config-message"></div>
    <pre class="rw-fichier" data-rw="f2b-config-contenu" hidden></pre>
</div>

<div class="rw-section" data-rw="f2b-logs" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.logs_titre') }}</h2>
    <p class="rw-aide" data-rw="f2b-logs-source"></p>
    <div data-rw="f2b-logs-message"></div>
    <pre class="rw-fichier" data-rw="f2b-logs-contenu" hidden></pre>
</div>

{{--
    ── LA LISTE BLANCHE ────────────────────────────────────────────────────

    Deux choses que le legacy ne dit pas :

    — quand `/etc/fail2ban/jail.local` n'a aucune ligne `ignoreip`, le backend en
      SUPPOSE une. Le legacy affiche donc une liste qui n'existe nulle part sur
      la machine (E-168). Le backend porte desormais un drapeau `lue`, et l'ecran
      le dit ;
    — `127.0.0.1/8` est un RESEAU, pas une adresse, et `_validate_ip` n'accepte
      que des adresses. Son « × » ne peut donc jamais aboutir — alors que c'est
      l'une des deux entrees affichees par defaut (E-169). Ici, une entree qui ne
      peut pas etre retiree ne porte pas de bouton : elle porte la RAISON.
--}}
<div class="rw-section" data-rw="f2b-blanche" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.blanche_titre') }}</h2>
    <p class="rw-aide">{{ __('fail2ban.blanche_aide') }}</p>
    <p class="rw-aide" data-rw="f2b-blanche-source"></p>
    <div data-rw="f2b-blanche-message"></div>
    <div class="rw-liste-etats" data-rw="f2b-blanche-liste"></div>

    <label class="rw-champ rw-champ--espace">
        <span class="rw-champ__etiquette">{{ __('fail2ban.blanche_etiquette') }}</span>
        <input type="text" class="rw-saisie" data-rw="f2b-blanche-ip"
               placeholder="{{ __('fail2ban.ban_placeholder') }}"
               autocomplete="off" spellcheck="false">
    </label>
    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--avertissement"
                data-rw="f2b-blanche-ajouter">{{ __('fail2ban.blanche_ajouter') }}</button>
    </div>
</div>

{{--
    ── LES REGLAGES D'UNE JAIL ─────────────────────────────────────────────

    La fenetre du legacy propose trois nombres et ne dit ni qu'elle va ECRIRE un
    fichier, ni que le service va REDEMARRER — donc que tous les bans en cours
    seront perdus (E-170). Ici l'avertissement est en tete, avant les champs.
--}}
<div class="rw-section" data-rw="f2b-jail-reglages" hidden>
    <h2 class="rw-section__entete" data-rw="f2b-reglages-titre"></h2>
    <p class="rw-avertissement">{{ __('fail2ban.jail_reglages_avert') }}</p>
    <div class="rw-grille-champs">
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('fail2ban.jail_maxretry') }}</span>
            <input type="number" class="rw-saisie" data-rw="f2b-maxretry" min="1" max="100" value="5">
            <span class="rw-aide">{{ __('fail2ban.jail_maxretry_aide') }}</span>
        </label>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('fail2ban.jail_bantime') }}</span>
            <input type="number" class="rw-saisie" data-rw="f2b-bantime" min="60" value="3600">
            <span class="rw-aide">{{ __('fail2ban.jail_bantime_aide') }}</span>
        </label>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('fail2ban.jail_findtime') }}</span>
            <input type="number" class="rw-saisie" data-rw="f2b-findtime" min="60" value="600">
            <span class="rw-aide">{{ __('fail2ban.jail_findtime_aide') }}</span>
        </label>
    </div>
    <div class="rw-actions">
        <div class="rw-actions__gauche">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="f2b-reglages-annuler">{{ __('fail2ban.conf_annuler') }}</button>
        </div>
        <button type="button" class="rw-bouton rw-bouton--avertissement"
                data-rw="f2b-jail-activer">{{ __('fail2ban.jail_activer') }}</button>
    </div>
</div>

{{--
    ── LA FRISE, ET L'HISTORIQUE ───────────────────────────────────────────

    Les deux sections sont VISIBLES des qu'une machine est choisie — elles ne
    dependent pas du releve de statut. Le legacy les charge a la fin du succes
    de `loadStatus` : une machine injoignable y masque donc son propre
    historique de bans, alors que celui-ci est EN BASE (E-156).

    Et elles s'affichent meme VIDES, en disant pourquoi : « aucun ban
    enregistre » et « la lecture a echoue » produisaient le meme ecran — rien
    du tout (E-153).
--}}
<div class="rw-section" data-rw="f2b-frise" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.frise_titre') }}</h2>
    <p class="rw-aide">{{ __('fail2ban.frise_aide') }}</p>
    <div class="rw-frise" data-rw="f2b-frise-cadre">
        {{--
            LA HAUTEUR DU CADRE VIENT DU CSS DU SOCLE, ET C'EST TOUT LE POINT.

            Le legacy ecrit `class="... h-32"` et donne a ses barres une hauteur
            en POURCENTAGE. `h-32` etant purgee du CSS compile, le cadre mesure
            0 px — et 100 % de zero fait zero : la carte s'affiche VIDE (E-159).
            Ici la hauteur est posee par `.rw-frise`, et les barres recoivent
            une hauteur en PIXELS calculee par le script.
        --}}
        <div class="rw-frise__barres" data-rw="f2b-frise-barres"></div>
        <div class="rw-frise__axe" data-rw="f2b-frise-axe"></div>
    </div>
    <p class="rw-frise__legende">
        <span class="rw-frise__cle rw-frise__cle--ban"></span>{{ __('fail2ban.frise_legende_ban') }}
        <span class="rw-frise__cle rw-frise__cle--unban"></span>{{ __('fail2ban.frise_legende_unban') }}
    </p>
    <div data-rw="f2b-frise-message"></div>
</div>

<div class="rw-section" data-rw="f2b-historique" hidden>
    <h2 class="rw-section__entete">{{ __('fail2ban.histo_titre') }}</h2>
    <p class="rw-aide">{{ __('fail2ban.histo_aide') }}</p>
    <p class="rw-aide" data-rw="f2b-historique-compte"></p>
    <div data-rw="f2b-historique-message"></div>
    <div class="rw-tableau-cadre" data-rw="f2b-historique-cadre" hidden>
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('fail2ban.histo_th_date') }}</th>
                    <th>{{ __('fail2ban.histo_th_jail') }}</th>
                    <th>{{ __('fail2ban.histo_th_ip') }}</th>
                    <th>{{ __('fail2ban.histo_th_action') }}</th>
                    <th>{{ __('fail2ban.histo_th_par') }}</th>
                </tr>
            </thead>
            <tbody data-rw="f2b-historique-corps"></tbody>
        </table>
    </div>
</div>

{{--
    ── F6 : LES DEUX GESTES SUR TOUT LE PARC, ET LEUR PORTEE ───────────────

    Cette section est en BAS de page, et c'est delibere : un geste irreversible
    qui part vers tout le parc ne doit pas se rencontrer en passant. Elle est en
    revanche TOUJOURS rendue — c'est la seule facon d'annoncer la portee, et
    l'annonce vaut par elle-meme, avant tout geste.

    Le legacy, lui, n'affiche son bouton d'installation de parc que si la machine
    CHOISIE n'a pas fail2ban (`main.js:77`) : la disponibilite d'un geste de parc
    y est decidee par un objet sur lequel il n'agit pas. C'est l'incoherence
    qu'E-162 a fait corriger ailleurs dans ce meme module. Ici l'offre suit SA
    portee : proposee quand elle n'est pas vide, et quand elle l'est, l'ecran le
    DIT au lieu de proposer. **Divergence declaree** — le geste devient plus
    atteignable que dans le legacy, en echange d'une portee enfin lisible et
    d'une confirmation qui exige de recopier le nombre de machines.
--}}
<div class="rw-section" data-rw="f2b-parc">
    <h2 class="rw-section__entete">{{ __('fail2ban.parc_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('fail2ban.parc_aide') }}</p>

    {{--
        Un seul rendu, en JS, alimente par la page puis par la relecture : il
        n'existe donc jamais deux versions de cette liste.

        IL NAIT `hidden`, ET LE SCRIPT LE DEVOILE APRES L'AVOIR PEINT.

        Rendu vide, `rw-encart` est une boite BORDEE : la session 7 l'a vue a
        l'image, aux trois largeurs et dans les deux langues, et elle ressemble a
        un champ de saisie — dans la section qui porte le geste le plus dangereux
        du module. Qu'elle ait ete surprise avant le peignage ou jamais peinte ne
        change rien a la regle : **un encart sans contenu ne se rend pas.** Si le
        script ne tourne pas, il n'y a pas de boite qui invite au clic ; s'il
        tourne, il dit soit la portee, soit qu'il n'a pas pu la lire.
    --}}
    <div class="rw-encart" data-rw="f2b-portee" hidden></div>
    <p class="rw-aide" role="status" aria-live="polite" data-rw="f2b-portee-message"></p>

    @if ($peutParc)
        <div class="rw-actions">
            <div class="rw-actions__gauche">
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="f2b-portee-relire">{{ __('fail2ban.portee_relire') }}</button>
            </div>
            {{-- Une INSTALLATION n'interrompt pas de service : teinte
                 d'avertissement, pas rouge. Le rouge de cette page est reserve
                 a ce qui coupe un acces — bannir. Et le poids de la decision
                 appartient au panneau, pas au bouton qui l'ouvre. --}}
            <button type="button" class="rw-bouton rw-bouton--avertissement"
                    data-rw="f2b-installer-parc">{{ __('fail2ban.parc_installer') }}</button>
        </div>
    @else
        {{--
            LE BACKEND EXIGE LE ROLE 2 SUR CES DEUX ROUTES, ET SUR ELLES SEULES.

            Un role 1 lit cette page et ces deux gestes ne peuvent que lui rendre
            403. Il recoit donc la RAISON, pas un bouton — meme regle qu'E-169.
            Branche NON exercee sur le banc : aucun compte de role 1 ne porte
            `can_manage_fail2ban`, donc aucun n'atteint cette page.
        --}}
        <div class="rw-encart" data-rw="f2b-parc-refuse">
            <p class="rw-sous-titre-fort">{{ __('fail2ban.parc_role_titre') }}</p>
            <p class="rw-prose">{{ __('fail2ban.parc_role') }}</p>
        </div>
    @endif
</div>

<div class="rw-encart" data-rw="f2b-non-porte">
    <p class="rw-sous-titre-fort">{{ __('fail2ban.non_porte_titre') }}</p>
    <p class="rw-prose">{{ __('fail2ban.non_porte_texte') }}</p>
    <a class="rw-bouton" data-rw="f2b-lien-legacy"
       href="{{ rtrim(config('app.url_legacy'), '/') }}/fail2ban/"
       target="_blank" rel="noopener">{{ __('fail2ban.non_porte_lien') }} ↗</a>
</div>
@endif

    <script id="f2b-textes" type="application/json">@json($textes)</script>
    {{-- Les noms de comptes, pour resoudre la colonne « Par » (E-157). --}}
    <script id="f2b-noms" type="application/json">@json($noms)</script>
    {{-- F6 : la portee des deux gestes de parc, lue en base par le controleur
         avec le SQL des routes. `@json` reste sur UNE ligne — multiligne, il
         casse le PHP compile par Blade. --}}
    <script id="f2b-portee-donnees" type="application/json">@json($portee)</script>
    <script src="/js/fail2ban.js?v={{ @filemtime(public_path('js/fail2ban.js')) ?: '0' }}"></script>
@endsection
