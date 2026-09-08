@extends('layouts.portail', ['titre' => __('pare-feu.titre')])

@section('corps')
<h1 class="rw-titre">{{ __('pare-feu.titre') }}</h1>
<p class="rw-sous-titre rw-prose">{{ __('pare-feu.intro') }}</p>

@if ($total === 0)
    {{--
        LA LISTE EST FILTREE PAR ACCES : un role 1 sans machine attribuee voit
        cet ecran, pas une liste vide sans explication. Le legacy rend un
        `<select>` ne portant que « Choisir un serveur » — indiscernable d'une
        page cassee.
    --}}
    <div class="rw-vide" data-rw="ipt-vide">
        <p class="rw-vide__titre">{{ __('pare-feu.machines_aucune_titre') }}</p>
        <p class="rw-vide__texte">{{ __('pare-feu.machines_aucune') }}</p>
    </div>
@else

@if ($sensibles > 0)
    <div class="rw-avertissement" data-rw="ipt-avert">
        <strong>{{ __('pare-feu.avert_titre') }}</strong>
        <span class="rw-aide">
            {{ $sensibles === 1
                ? __('pare-feu.avert_un', ['total' => $total])
                : __('pare-feu.avert_plusieurs', ['nb' => $sensibles, 'total' => $total]) }}
        </span>
    </div>
@endif

<div class="rw-section">
    <label class="rw-champ">
        <span class="rw-champ__etiquette">{{ __('pare-feu.serveur') }}</span>
        <select class="rw-saisie" data-rw="ipt-serveur">
            <option value="">{{ __('pare-feu.choisir') }}</option>
            @foreach ($lignes as $l)
                <option value="{{ $l['machine']->id }}"
                        data-sensible="{{ $l['sensible'] ? '1' : '0' }}"
                        data-nom="{{ $l['machine']->name }}">
                    {{ $l['machine']->name }} ({{ $l['machine']->ip }}){{ $l['sensible'] ? ' — ' . __('pare-feu.sensible') : '' }}
                </option>
            @endforeach
        </select>
    </label>

    {{--
        L'AVERTISSEMENT VIENT AVANT L'ACTION, et sur ce module il porte DEUX
        faits : la machine est sensible, et son port SSH est celui-ci. Le second
        n'a l'air de rien tant qu'on ne modifie pas les regles — c'est justement
        pourquoi il est annonce des la consultation, avant que I4 et I5 n'aient
        a le redecouvrir.

        Rendu SOUS le bouton, on lirait « cette machine est en production » apres
        avoir decide d'agir dessus. Defaut mesure a l'image en F1, invisible a
        toute assertion : « le message existe » etait vrai dans les deux
        dispositions.
    --}}
    <p class="rw-aide" role="status" aria-live="polite"
       data-rw="ipt-etat-message">{{ __('pare-feu.choisir') }}</p>

    <div class="rw-actions">
        <button type="button" class="rw-bouton" data-rw="ipt-relever" disabled>
            {{ __('pare-feu.relever') }}
        </button>
    </div>

    {{--
        LE CONTENEUR D'ANNONCE — C'EST LA MOITIE DU SOUS-LOT.

        `showNotification` du legacy vise `#notifications`, qui n'existe sur
        AUCUNE page de ce module : mesure, zero occurrence dans
        `legacy/iptables/index.php` pour treize points d'appel dans son JS. Les
        treize levent une `TypeError`, **y compris ceux places dans un `catch`**.

        Consequence mesuree par l'inventaire : appliquer un jeu de regles
        REUSSIT sur la machine et l'ecran ne dit rien. Ni succes, ni erreur.
        Tous les sous-lots suivants heritent de cette zone : c'est pourquoi elle
        est posee des I1, avant tout geste qui ecrit.

        `rw-annonce` est une region PERSISTANTE (`role="status"`), pas une bulle
        fugace : une annonce disparue ne dit plus si ce qu'on relit date d'avant
        ou d'apres.
    --}}
    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-annonce"></p>
</div>

{{--
    LES QUATRE BLOCS DU RELEVE.

    En `rw-grille` (`auto-fit`, minimum 280 px) et NON en `.rw-carte` : celle-ci
    est plafonnee a 420 px et le rapport resterait etroit sur une page de 1400.
    C'est le corollaire deja paye sur le rapport de preflight des cles SSH.
--}}
<div class="rw-grille" data-rw="ipt-blocs" hidden></div>

{{--
    ══ I2 : LA COPIE EN BASE ════════════════════════════════════════════════

    Ces deux gestes ne joignent AUCUNE machine : ils lisent et ecrivent la base
    du portail, comme les handlers PDO locaux du legacy. Ils vivent donc dans
    une section a part, apres le releve, et leur intitule dit ce qu'ils NE font
    pas — « enregistre » ne doit pas se lire « approuve ».
--}}
<div class="rw-section" data-rw="ipt-copie" hidden>
    <p class="rw-sous-titre-fort">{{ __('pare-feu.copie_titre') }}</p>
    <p class="rw-aide rw-prose">{{ __('pare-feu.copie_intro') }}</p>

    <div class="rw-actions">
        {{--
            LA LECTURE EST L'ACTION SECONDAIRE, a gauche. L'enregistrement naît
            DESACTIVE : sans releve prealable il n'y a rien a enregistrer, et la
            regle se lit AVANT le geste plutot que dans un refus apres le clic.
        --}}
        <div class="rw-actions__gauche">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="ipt-copie-charger">{{ __('pare-feu.copie_charger') }}</button>
        </div>
        {{-- AU-DESSUS du bouton : l'information doit etre lue avant le clic,
             pas apres. Ce geste ecrit des regles de pare-feu sur une machine
             reelle et n'a jamais ete exerce depuis cette interface. --}}
        <button type="button" class="rw-bouton" data-rw="ipt-copie-enregistrer" disabled>
            {{ __('pare-feu.copie_enregistrer') }}
        </button>
    </div>

    <p class="rw-aide rw-prose" data-rw="ipt-copie-jamais-exercee">{{ __('pare-feu.copie_jamais_exercee') }}</p>
    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-copie-annonce"></p>
    <div class="rw-grille" data-rw="ipt-copie-blocs" hidden></div>
</div>

{{--
    ══ I4 : LA VALIDATION A BLANC ═══════════════════════════════════════════

    Elle porte sur LA COPIE EN BASE, et c'est la chaine coherente : I2
    enregistre, I4 valide ce qui est enregistre, I5 appliquera la meme chose.
    Le legacy validait le contenu d'une zone d'edition ; le portage n'en offre
    pas, donc il valide l'objet qui existe.

    CE GESTE JOINT LA MACHINE. C'est le seul de I1 a I4 dans ce cas : il ouvre
    une session SSH et ecrit dans `/tmp`. Il ne modifie aucune table — mais
    « ne modifie rien » n'est pas « ne fait rien », et l'ecran le dit AVANT.
--}}
<div class="rw-section" data-rw="ipt-valid" hidden>
    <p class="rw-sous-titre-fort">{{ __('pare-feu.valid_titre') }}</p>
    <p class="rw-aide rw-prose">{{ __('pare-feu.valid_intro') }}</p>

    {{-- Les deux faits AVANT le geste : ce qu'il touche, et ce qu'il ne couvre pas. --}}
    <p class="rw-aide">{{ __('pare-feu.valid_avant') }}</p>
    <p class="rw-aide">{{ __('pare-feu.valid_limite') }}</p>

    <div class="rw-actions">
        <button type="button" class="rw-bouton" data-rw="ipt-valid-lancer" disabled>
            {{ __('pare-feu.valid_bouton') }}
        </button>
    </div>

    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-valid-annonce"></p>
    <div data-rw="ipt-valid-etat"></div>
</div>

{{--
    ══ I3 : L'HISTORIQUE DES VERSIONS ARCHIVEES ═════════════════════════════

    Il se charge au CHOIX de la machine, PAS apres un releve reussi. Le legacy
    appelle `loadHistory()` DANS la branche de succes de son releve
    (`js/main.js:79`) : une machine injoignable masque donc son propre
    historique — qui est en BASE et ne demande aucune machine. C'est E-156,
    refermee sur `fail2ban` par F2, et reproduite ici a l'identique.

    Un TABLEAU et non une liste de decision : ce sont des lignes de donnees
    qu'on compare colonne par colonne. Le defilement appartient au CADRE.
--}}
<div class="rw-section" data-rw="ipt-histo" hidden>
    <p class="rw-sous-titre-fort">{{ __('pare-feu.histo_titre') }}</p>
    <p class="rw-aide rw-prose">{{ __('pare-feu.histo_intro') }}</p>

    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-histo-annonce"></p>

    <div class="rw-tableau-cadre" data-rw="ipt-histo-cadre" hidden>
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('pare-feu.histo_col_date') }}</th>
                    <th>{{ __('pare-feu.histo_col_auteur') }}</th>
                    <th>{{ __('pare-feu.histo_col_motif') }}</th>
                    {{-- I6 : la colonne d'ACTION. Elle ne cede jamais la place —
                         c'est l'appoint qui s'efface, jamais la colonne
                         actionnable (regle de largeur du chantier). --}}
                    <th>{{ __('pare-feu.rb_titre') }}</th>
                </tr>
            </thead>
            <tbody data-rw="ipt-histo-corps"></tbody>
        </table>
    </div>

    <div data-rw="ipt-histo-etat"></div>
</div>

{{-- ══ I6 — LE RETOUR ARRIERE ═══════════════════════════════════════════════

     ⚠ PLUS DANGEREUX QUE L'APPLICATION, ET NON MOINS.

       APPLIQUER       l'operateur ECRIT les regles : il les a sous les yeux
       RETOUR ARRIERE  l'operateur choisit une DATE : il ne peut pas se relire

     C'est le seul des deux gestes ou l'humain ne voit pas son objet — d'ou
     l'apercu ci-dessous, qui n'est pas un confort : *un geste dont on ne voit pas
     l'objet ne se consent pas, il s'accepte.*

     Et `iptables_history` ne porte AUCUN port : une version etait valide LE JOUR
     DE SON ARCHIVAGE. Q2 se calcule donc sur le port ACTUEL de la machine.
--}}
<div class="rw-section" data-rw="ipt-rb" hidden>
    <h2 class="rw-sous-titre">{{ __('pare-feu.rb_titre') }}</h2>
    <p class="rw-aide" data-rw="ipt-rb-archive"></p>

    <p class="rw-sous-titre-fort">{{ __('pare-feu.rb_apercu') }}</p>
    <pre class="rw-fichier" data-rw="ipt-rb-apercu"></pre>

    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-rb-ssh"></p>

    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="ipt-rb-bouton" disabled>{{ __('pare-feu.rb_conf_ok') }}</button>
    </div>

    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-rb-annonce"></p>
    <div data-rw="ipt-rb-etat"></div>
</div>

<div class="rw-section" data-rw="ipt-rb-conf" hidden>
    <p class="rw-sous-titre-fort" data-rw="ipt-rb-conf-titre"></p>
    <p class="rw-prose" data-rw="ipt-rb-conf-texte"></p>
    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="ipt-rb-conf-non">{{ __('pare-feu.rb_conf_non') }}</button>
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="ipt-rb-conf-ok" disabled>{{ __('pare-feu.rb_conf_ok') }}</button>
    </div>
</div>

{{-- ══ I5 — APPLIQUER UN JEU DE REGLES ═══════════════════════════════════════

     ⚠ CE QUE CET ECRAN CREE, ET CE QU'IL NE CREE PAS.

     `RoutesBackend:114` porte `/iptables-` et la comparaison est PAR PREFIXE :
     `/iptables-apply` passe donc DEJA la passerelle, aujourd'hui, sans cet ecran.
     **I5 ne cree pas l'atteignabilite — il cree l'ECRAN.** Un geste qui n'etait
     atteignable que par requete forgee devient un bouton. C'est precisement pour
     cela que Q1 a Q4 ne sont pas negociables : ils ne protegent pas d'un geste
     nouveau, ils encadrent un geste qui existait sans garde-fou visible.

     Q1  le port SSH vient de la MACHINE (`ipt-ports`, lu en base), jamais de `22`
     Q2  un jeu qui fermerait SSH est REFUSE avant tout envoi — et le doute aussi
     Q3  tout retour produit un message visible, succes comme echec comme doute
     Q4  avant consentement, AUCUNE requete n'est emise
--}}
<div class="rw-section" data-rw="ipt-appl" hidden>
    <h2 class="rw-sous-titre">{{ __('pare-feu.appl_titre') }}</h2>
    <p class="rw-prose rw-aide" data-rw="ipt-appl-intro">{{ __('pare-feu.appl_intro') }}</p>

    <div class="rw-champ">
        <label class="rw-etiquette" for="ipt-appl-gabarit">{{ __('pare-feu.appl_gabarit') }}</label>
        <select class="rw-saisie" id="ipt-appl-gabarit" data-rw="ipt-appl-gabarit"></select>
        <p class="rw-aide rw-prose" data-rw="ipt-appl-gabarit-aide">{{ __('pare-feu.appl_gabarit_aide') }}</p>
    </div>

    {{-- L'APERCU N'EST PAS UN CONFORT : c'est ce qui rend le geste verifiable
         avant d'etre consenti. On applique ce qu'on a lu. --}}
    <p class="rw-sous-titre-fort">{{ __('pare-feu.appl_apercu') }}</p>
    <pre class="rw-fichier" data-rw="ipt-appl-apercu"></pre>

    {{-- Le verdict Q2, AVANT le bouton. Un jeu qui ferme SSH doit se lire avant
         qu'on ait envie de cliquer, pas apres. --}}
    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-appl-ssh"></p>

    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="ipt-appl-bouton" disabled>{{ __('pare-feu.appl_bouton') }}</button>
    </div>

    <p class="rw-annonce" role="status" aria-live="polite" data-rw="ipt-appl-annonce"></p>
    <div data-rw="ipt-appl-etat"></div>
</div>

{{-- LE PANNEAU DE CONSENTEMENT. Hors du bloc ci-dessus pour qu'il ne depende pas
     de son `hidden`. Le bouton de confirmation nait DESACTIVE et ne s'active que
     lorsque le panneau s'ouvre : un panneau ferme ne doit rien pouvoir declencher. --}}
<div class="rw-section" data-rw="ipt-appl-conf" hidden>
    <p class="rw-sous-titre-fort" data-rw="ipt-appl-conf-titre"></p>
    <p class="rw-prose" data-rw="ipt-appl-conf-texte"></p>
    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="ipt-appl-conf-non">{{ __('pare-feu.appl_conf_non') }}</button>
        <button type="button" class="rw-bouton rw-bouton--danger"
                data-rw="ipt-appl-conf-ok" disabled>{{ __('pare-feu.appl_conf_ok') }}</button>
    </div>
</div>

{{-- ⚠ L'ENCART « NON PORTE » A ETE RETIRE, ET C'ETAIT LE DERNIER FIL.

     Il portait deux enonces devenus FAUX, et un lien `/iptables/` en dur :

       'suite_titre'  « Cette page ne modifie rien »   -> elle applique et restaure
       'suite'        « seul le retour arriere reste » -> I6 l'a porte

     Les cinq gestes du pare-feu sont ici : relever, copier, valider, appliquer,
     revenir. Un encart qui envoie vers un portail qu'on demonte, pour un geste
     qui est sous les yeux de qui le lit, est pire qu'inutile.

     ⚠ ET C'ETAIT LE SEUL LIEN VIVANT DU PORTAGE VERS LE LEGACY. Les six autres
     sites sont des branches `@else` jamais prises : `Navigation` ne porte plus
     AUCUNE entree `legacy` (0 occurrence contre 33 `route`), et le predicat
     `porteDuLegacy` rend `false` pour les trois roles — avec un temoin qui
     montre qu'il SAIT rendre `true` sur un menu forge sans route.

     Les trois cles `suite*` sont retirees des deux catalogues dans le meme
     geste : une cle que personne ne cite est un orphelin, et un orphelin se lit
     comme une capacite qui existe encore ailleurs. --}}
@endif

    {{-- `@json` reste sur UNE ligne : multiligne, il casse le PHP compile. --}}
    <script id="ipt-textes" type="application/json">@json($textes)</script>
    {{-- Le port SSH par machine, lu en BASE. Les gabarits du legacy supposent
         22 ; cette table existe pour que le portage n'ait jamais a le supposer. --}}
    <script id="ipt-ports" type="application/json">@json($portsSsh)</script>
    {{-- ⚠ LES TROIS MODULES DE I5 SE CHARGENT AVANT `pare-feu.js`, qui les
         consomme par `window.rw*`. Chacun porte UNE propriete, et le code de la
         page les APPELLE plutot que de les reimplementer :

           Q1  rwGabaritPareFeu(nom, port)             le port vient de la machine
           Q2  rwLaisseLeSshOuvert(regles, port)       true / false / null
           Q3  rwRetourPareFeu(corps, statut, erreur)  huit cas, dont QUATRE
                                                       portent `sur: false`

         `pare-feu.js` teste leur presence avant usage : modules absents, il ne
         compose AUCUN jeu et le DIT — plutot que de retomber sur un gabarit qui
         supposerait le port 22, ce que Q1 existe precisement pour empecher. --}}
    <script src="/js/pare-feu-gabarits.js?v={{ @filemtime(public_path('js/pare-feu-gabarits.js')) ?: '0' }}"></script>
    <script src="/js/pare-feu-ssh-ouvert.js?v={{ @filemtime(public_path('js/pare-feu-ssh-ouvert.js')) ?: '0' }}"></script>
    <script src="/js/pare-feu-retour-visible.js?v={{ @filemtime(public_path('js/pare-feu-retour-visible.js')) ?: '0' }}"></script>
    <script src="/js/pare-feu.js?v={{ @filemtime(public_path('js/pare-feu.js')) ?: '0' }}"></script>
@endsection
