@extends('layouts.portail', ['titre' => __('nav.profile')])

@section('corps')
    <h1 class="rw-titre">{{ __('nav.profile') }}</h1>
    <p class="rw-sous-titre">{{ session('utilisateur_nom') }} · {{ $libelleRole }}</p>

    @if ($changementRequis)
        <p class="rw-erreur rw-prose">{{ __('auth.changement_requis') }}</p>
    @endif

    {{-- ══ SOUS-LOT A2 : LE CHANGEMENT DE MOT DE PASSE ═══════════════════════
         L'un des DEUX blocages de la v2.0. ⚠ CE CHIFFRE ETAIT PERIME. Remesure le
           2026-09-03 : 12 comptes actifs, 8 porteurs du drapeau — mais CINQ
           d'entre eux sont des comptes `e2e_test_*` crees par les suites. TROIS
           comptes reels sont concernes, dont `superadmin`. « Six sur dix »
           portent
         `force_password_change = 1`, dont `superadmin` : la page ANNONCAIT
         l'exigence par le bandeau ci-dessus et renvoyait vers l'ancien portail,
         qui n'existera plus apres la bascule.

         LA POLITIQUE S'ANNONCE AVANT D'ETRE APPLIQUEE. Decouvrir une regle en
         s'y cognant est le contraire d'un guidage — et les valeurs viennent du
         SERVEUR, donc de la meme source que le controle. --}}
    <section class="rw-note" data-rw="profil-mot-de-passe">
        <h2 class="rw-sous-titre">{{ __('profil.mdp_titre') }}</h2>

{{-- ⚠ DEUX ANCRES, PARCE QUE DEUX ETATS OPPOSES ────────────────────────

                 La confirmation et l'erreur partageaient `profil-mdp-message`.
                 Les deux `@if` etant exclusifs, un seul `<p>` existe a la fois —
                 donc l'etat EST mesurable, mais l'ancre ne le DISCRIMINE pas :
                 une assertion sur « le geste a reussi » serait **verte sur un
                 echec**.

                 Ancres separees plutot qu'assertion sur la classe : *une suite
                 qui doit lire une classe de PRESENTATION pour connaitre un etat
                 METIER depend d'une decision de style*, et ce depot a paye trois
                 fois une classe renommee ou purgee. Le jour ou `rw-erreur`
                 change de nom, l'assertion passerait au vert sur un echec sans
                 que rien ne bouge dans la page. --}}
                    @if (session('mdp_message'))
            <p class="rw-confirmation" data-rw="profil-mdp-succes">{{ session('mdp_message') }}</p>
        @endif
        @if (session('mdp_erreur'))
            <p class="rw-erreur" data-rw="profil-mdp-erreur">{{ session('mdp_erreur') }}</p>
        @endif

        {{-- L'ENONCE DE LA POLITIQUE EST UN ENCART, PAS UNE AIDE EN PETITS
             CARACTERES. Vu a l'image : en `rw-aide`, le paragraphe TOUCHAIT la
             premiere etiquette, sans respiration. Et le niveau d'alerte compte :
             l'erreur est en `rw-erreur`, l'enonce des regles doit rester neutre —
             deux niveaux, pas un. `rw-encart` porte sa marge et sa bordure
             discrete. --}}
        <p class="rw-encart rw-prose">{{ __('profil.mdp_politique', [
            'longueur' => $longueurMinimale, 'historique' => $tailleHistorique,
        ]) }}</p>

        {{-- Les champs sont REVIDES a chaque retour : `withInput()` republierait
             un mot de passe dans la reponse. --}}
        <form method="POST" action="{{ route('profil.mot-de-passe') }}" autocomplete="off"
              data-rw="profil-mdp-form">
            @csrf
            <label class="rw-etiquette-champ" for="current_password">
                {{ __('profil.mdp_actuel') }}
                <input class="rw-saisie" type="password" id="current_password"
                       name="current_password" autocomplete="current-password" required>
            </label>
            <label class="rw-etiquette-champ" for="new_password">
                {{ __('profil.mdp_nouveau') }}
                <input class="rw-saisie" type="password" id="new_password"
                       name="new_password" autocomplete="new-password"
                       minlength="{{ $longueurMinimale }}" required>
            </label>
            <label class="rw-etiquette-champ" for="confirm_password">
                {{ __('profil.mdp_confirmation') }}
                <input class="rw-saisie" type="password" id="confirm_password"
                       name="confirm_password" autocomplete="new-password"
                       minlength="{{ $longueurMinimale }}" required>
            </label>

            {{-- ACTION PRINCIPALE A DROITE, convention du pied de formulaire. --}}
            <div class="rw-actions">
                <p class="rw-actions__gauche rw-aide">{{ __('profil.mdp_effet_sessions') }}</p>
                <button type="submit" class="rw-bouton rw-bouton--primaire"
                        data-rw="profil-mdp-enregistrer">{{ __('profil.mdp_enregistrer') }}</button>
            </div>
        </form>
    </section>

    <div class="rw-grille">
        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.compte_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.compte_texte', ['nom' => session('utilisateur_nom'), 'role' => $libelleRole]) }}</p>
        </div>

        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.second_facteur_titre') }}</span>
            <span class="rw-tuile__valeur">{{ __('profil.second_facteur_valeur') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.second_facteur_texte') }}</p>
        </div>

        {{--
            ══ E-203 — LES SESSIONS OUVERTES ════════════════════════════════

            La page de profil du legacy publie l'identifiant de session COMPLET
            de chaque session ouverte. Le portage n'affiche qu'une EMPREINTE :
            un identifiant de session est un identifiant d'acces, et le mettre
            dans un champ cache pour pouvoir revoquer aurait annule la
            precaution — le HTML l'aurait publie tout autant.

            La fermeture vise donc l'empreinte, et le serveur la resout parmi
            les sessions DE CE COMPTE.
        --}}
        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.sessions_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.sessions_aide') }}</p>

            @if (! $sessionsLisibles)
                {{-- UNE LISTE QUI N'A PAS REPONDU N'EST PAS « AUCUNE SESSION ».
                     Sur un ecran de securite, rendre le vide affirmerait un
                     fait qu'on n'a pas mesure. --}}
                <p class="rw-tuile__texte" data-rw="profil-sessions-illisible">{{ __('profil.sessions_err') }}</p>
            @elseif (! count($sessions))
                <p class="rw-tuile__texte" data-rw="profil-sessions-vide">{{ __('profil.sessions_vide') }}</p>
            @else
                @if ($sessionsTotal > count($sessions))
                    {{-- La borne est ANNONCEE. Montrer vingt lignes sur deux
                         mille cinq cents sans le dire serait exactement le
                         compteur qui ment qu'on corrige partout ailleurs. --}}
                    <p class="rw-tuile__texte" data-rw="profil-sessions-bornee">{{ __('profil.sessions_bornee', ['n' => count($sessions), 'total' => $sessionsTotal]) }}</p>
                @endif
                <p class="rw-tuile__texte" data-rw="profil-sessions-vestiges">{{ __('profil.sessions_vestiges') }}</p>
                <div class="rw-liste-etats" data-rw="profil-sessions">
                    @foreach ($sessions as $s)
                        <div class="rw-liste-etats__ligne" data-rw="profil-session">
                            <span class="rw-liste-etats__nom">
                                {{ __('profil.sessions_empreinte', ['valeur' => $s['empreinte']]) }}
                                @if ($s['courante'])
                                    <span class="rw-badge rw-badge--ok" data-rw="profil-session-courante">{{ __('profil.sessions_actuelle') }}</span>
                                @endif
                            </span>
                            <span>
                                {{ $s['ip'] }} ·
                                {{ __('profil.sessions_vue', ['date' => substr($s['vue'], 0, 16)]) }}
                                @if (! $s['courante'])
                                    <form method="POST" action="{{ route('profil.sessions.fermer') }}" class="rw-actions__gauche">
                                        @csrf
                                        <input type="hidden" name="empreinte" value="{{ $s['empreinte'] }}">
                                        <button type="submit" class="rw-bouton rw-bouton--minuscule rw-bouton--danger"
                                                data-rw="profil-session-fermer">{{ __('profil.sessions_revoquer') }}</button>
                                    </form>
                                @endif
                            </span>
                        </div>
                    @endforeach
                </div>
            @endif
        </div>

        {{-- LA TUILE « Pas encore ici » A ETE RETIREE le 2026-09-05.
             Son texte disait : « Les connexions memorisees ne sont pas encore
             listees ici : l'ancien portail les affiche. » MESURE : `legacy/profile.php`
             ne les liste JAMAIS — ses deux seules occurrences de `remember_tokens`
             sont un `DELETE` (:209), pose apres un changement de mot de passe.
             Le libelle inventait un manque ET renvoyait vers un portail qui ne le
             comblait pas. Les trois gestes qui manquaient vraiment — changer son
             adresse, poser sa cle SSH, demander l'effacement — sont portes depuis
             la v1.51.1. Il ne reste rien a aller chercher ailleurs. --}}
    </div>

    {{-- L'EXPORT EST UN GET, DONC UN LIEN. C'est une LECTURE : elle ne modifie
         rien, elle n'a pas a passer par un formulaire POST, et un lien reste
         copiable et ouvrable dans un onglet. Le telechargement vient de
         `Content-Disposition: attachment`, pas d'un attribut `download` — que
         le navigateur pourrait ignorer et que le serveur, lui, impose.

         `a.rw-bouton` ne garde pas son soulignement de lien : un element se lit
         comme un bouton OU comme un lien, pas comme les deux. --}}
    {{--
        LES TROIS GESTES DE LIBRE-SERVICE. Leur cote administratif etait deja
        porte : c'est l'ACTEUR qui manquait. Chaque region porte son `data-rw`
        pour etre assertable, et aucune classe n'est neuve — toutes existent
        deja dans `rw.css`, verifie avant le premier rendu.
    --}}
    <section class="rw-note" data-rw="profil-courriel">
        <h2 class="rw-sous-titre">{{ __('profil.courriel_titre') }}</h2>
        <p class="rw-prose rw-aide" data-rw="profil-courriel-aide">{{ __('profil.courriel_aide') }}</p>
        @if (session('courriel_message'))
            <p class="rw-confirmation" data-rw="profil-courriel-succes">{{ session('courriel_message') }}</p>
        @endif
        @if (session('courriel_erreur'))
            <p class="rw-erreur" data-rw="profil-courriel-erreur">{{ session('courriel_erreur') }}</p>
        @endif
        <form method="POST" action="{{ route('profil.courriel') }}" data-rw="profil-courriel-form">
            @csrf
            <label class="rw-champ">
                <span>{{ __('profil.courriel_label') }}</span>
                <input type="email" name="courriel" maxlength="255" required
                       value="{{ $compte['email'] ?? '' }}"
                       data-rw="profil-courriel-champ">
            </label>
            <div class="rw-actions">
                <button type="submit" class="rw-bouton"
                        data-rw="profil-courriel-enregistrer">{{ __('profil.courriel_enregistrer') }}</button>
            </div>
        </form>
    </section>

    <section class="rw-note" data-rw="profil-cle-ssh">
        <h2 class="rw-sous-titre">{{ __('profil.cle_titre') }}</h2>
        <p class="rw-prose rw-aide" data-rw="profil-cle-aide">{{ __('profil.cle_aide') }}</p>
        <p class="rw-prose rw-aide" data-rw="profil-cle-vide-aide">{{ __('profil.cle_vide_aide') }}</p>
        @if (session('cle_message'))
            <p class="rw-confirmation" data-rw="profil-cle-succes">{{ session('cle_message') }}</p>
        @endif
        @if (session('cle_erreur'))
            <p class="rw-erreur" data-rw="profil-cle-erreur">{{ session('cle_erreur') }}</p>
        @endif
        <form method="POST" action="{{ route('profil.cle-ssh') }}" data-rw="profil-cle-form">
            @csrf
            <label class="rw-champ">
                <span>{{ __('profil.cle_label') }}</span>
                <textarea name="cle_ssh" rows="3" data-rw="profil-cle-champ">{{ $compte['ssh_key'] ?? '' }}</textarea>
            </label>
            <div class="rw-actions">
                <button type="submit" class="rw-bouton"
                        data-rw="profil-cle-enregistrer">{{ __('profil.cle_enregistrer') }}</button>
            </div>
        </form>
    </section>

    <section class="rw-section" data-rw="profil-rgpd">
        <h2 class="rw-sous-titre">{{ __('profil.rgpd_titre') }}</h2>
        <p class="rw-prose rw-aide">{{ __('profil.rgpd_aide') }}</p>
        <p class="rw-prose rw-aide" data-rw="rgpd-contenu">{{ __('profil.rgpd_contenu') }}</p>
        <p class="rw-prose rw-aide" data-rw="rgpd-protege">{{ __('profil.rgpd_protege') }}</p>
        <p class="rw-prose rw-aide" data-rw="rgpd-borne">{{ __('profil.rgpd_borne') }}</p>
        <p class="rw-prose rw-aide" data-rw="rgpd-trace">{{ __('profil.rgpd_trace') }}</p>

        {{--
            ⚠ IRREVERSIBLE. Place APRES le bloc RGPD parce qu'il en est la
            consequence : le meme droit qui donne l'export donne l'effacement.
            Le geste execute est l'ANONYMISATION — `user_logs` est une chaine de
            hachage, retirer une ligne casserait la verification de toutes les
            suivantes, et le code le dit deja (`supprimableSansPerte:504-507`).
        --}}
        <div class="rw-note" data-rw="profil-effacement">
            <h2 class="rw-sous-titre">{{ __('profil.eff_titre') }}</h2>
            <p class="rw-prose rw-aide" data-rw="profil-eff-aide">{{ __('profil.eff_aide') }}</p>
            <p class="rw-prose rw-aide" data-rw="profil-eff-prevenu">{{ __('profil.eff_prevenu') }}</p>
            @if (session('effacement_erreur'))
                <p class="rw-erreur" data-rw="profil-eff-erreur">{{ session('effacement_erreur') }}</p>
            @endif
            <form method="POST" action="{{ route('profil.effacement') }}" data-rw="profil-eff-form">
                @csrf
                {{--
                    ⚠ `<div class="rw-champ">` + `<label class="rw-etiquette">`, ET
                    PAS `<label class="rw-champ">` — vu a l'image.

                    `.rw-champ` ne pose que `margin-bottom` (`rw.css:146`), et un
                    `<label>` est INLINE par defaut : les deux champs de ce
                    formulaire se rendaient **sur une seule ligne**, collés, le
                    second ayant l'air d'un ajout. `.rw-etiquette`, elle, est en
                    `display: block` — c'est le motif employe partout ailleurs
                    dans le portage, et celui-ci ne le suivait pas.

                    *Le champ du nom est corrige avec celui du code : en laisser
                    un des deux inline garderait le defaut a moitie, pour une
                    paire qui se lit ensemble.*
                --}}
                <div class="rw-champ">
                    <label class="rw-etiquette" for="eff-confirmation">
                        {{ __('profil.eff_confirmation_label', ['nom' => $compte['name'] ?? '']) }}
                    </label>
                    <input class="rw-saisie" id="eff-confirmation" type="text" name="confirmation"
                           autocomplete="off" required data-rw="profil-eff-champ">
                </div>
                {{--
                    ⚠ LE SECOND FACTEUR EST DANS LE MEME FORMULAIRE, pas dans une
                    modale. Les trois autres gestes gardés du portage rendent
                    `step_up_required` en JSON a une modale branchee sur `fetch` ;
                    celui-ci est un `<form method="POST">`. **Un second ecran
                    ajouterait un etat a perdre entre deux soumissions**, pour un
                    geste qui doit en avoir le moins possible.

                    Et les DEUX controles ne protegent pas de la meme chose : le
                    nom retape protege du geste ACCIDENTEL — il est affiche juste
                    au-dessus — et le code protege d'une session VOLEE. `eff_code_aide`
                    le dit a l'ecran, parce que rien ne les distingue a l'oeil.
                --}}
                <div class="rw-champ">
                    <label class="rw-etiquette" for="eff-code">{{ __('profil.eff_code_label') }}</label>
                    {{-- `inputmode` et `pattern` sont des gardes du NAVIGATEUR :
                         ils evitent une frappe malheureuse, ils ne controlent
                         rien. `StepUp::verifie()` tranche, et lui seul.

                         ⚠ ET `required` EST GARDE ALORS QUE LE SERVEUR PEUT
                         S'EN PASSER — releve par la QA, et la raison est mesuree.

                         Le controleur court-circuite `verifie()` quand une marque
                         fraiche existe : ce code-la n'est alors pas lu. Mais
                         **cette marque ne survit presque jamais a une requete** —
                         `verifie()` est le seul a la poser, et le geste aboutit
                         dans la foulee (le compte est anonymise, la session
                         detruite). Elle ne subsiste que si `anonymise()` echoue
                         APRES un step-up reussi.

                         `required` sert donc le seul chemin qui se produise
                         reellement, et son cout dans l'autre est de retaper un
                         code apres un echec d'ecriture. *L'incoherence est reelle
                         et elle est ecrite : sans cette note, un lecteur conclurait
                         que le code est TOUJOURS exige, ce qui est faux cote
                         serveur.* --}}
                    <input class="rw-saisie" id="eff-code" type="text" name="code_2fa"
                           autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}"
                           maxlength="6" required data-rw="profil-eff-code">
                </div>
                <p class="rw-aide rw-prose" data-rw="profil-eff-code-aide">{{ __('profil.eff_code_aide') }}</p>

                <div class="rw-actions">
                    <button type="submit" class="rw-bouton rw-bouton--danger"
                            data-rw="profil-eff-bouton">{{ __('profil.eff_bouton') }}</button>
                </div>
            </form>
        </div>
        <div class="rw-actions">
            <a class="rw-bouton" data-rw="rgpd-telecharger"
               href="{{ route('profil.donnees-personnelles') }}">{{ __('profil.rgpd_bouton') }}</a>
        </div>
    </section>

@endsection
