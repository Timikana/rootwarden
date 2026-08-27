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
        <button type="button" class="rw-bouton rw-bouton--discret rw-bouton--minuscule"
                data-rw="f2b-jail-fermer">{{ __('fail2ban.jail_fermer') }}</button>
    </div>
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
        ── LE PANNEAU DE DECISION ──────────────────────────────────────────

        Le legacy ouvre un `confirm()` natif qui dit « Bannir cette IP ? » — il
        ne nomme NI l'adresse, NI la jail, NI la machine, alors que les trois lui
        sont passees (E-167). On confirme donc un geste destructeur sans savoir
        sur quoi il porte, et F4 vient de montrer que la machine peut differer de
        celle qu'affiche le selecteur.

        Un panneau en page peut dire ce que l'action ENGAGE. Une boite native
        tient en une ligne et s'accepte au reflexe.
    --}}
    <div class="rw-panneau-decision" data-rw="f2b-confirmation" hidden>
        <div class="rw-panneau-decision__texte">
            <p class="rw-sous-titre-fort" data-rw="f2b-confirmation-titre"></p>
            <p class="rw-aide" data-rw="f2b-confirmation-texte"></p>
        </div>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="f2b-annuler">{{ __('fail2ban.conf_annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="f2b-confirmer">{{ __('fail2ban.conf_confirmer') }}</button>
        </div>
    </div>

    <h3 class="rw-sous-titre-fort rw-titre--espace">{{ __('fail2ban.geste_journal') }}</h3>
    <div class="rw-journal__general" data-rw="f2b-journal"
         aria-live="polite" aria-label="{{ __('fail2ban.geste_vide') }}"></div>
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
    <script src="/js/fail2ban.js?v={{ @filemtime(public_path('js/fail2ban.js')) ?: '0' }}"></script>
@endsection
