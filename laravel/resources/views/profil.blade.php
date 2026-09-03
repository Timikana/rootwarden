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

        {{-- Ce qui reste non porte sur cette page, et QUOI exactement : le
             changement de mot de passe, lui, l'est desormais (A2). Un intitule
             qui reste vague apres un portage partiel laisse croire que rien n'a
             bouge. --}}
        <div class="rw-tuile">
            <span class="rw-tuile__titre">{{ __('profil.non_porte_titre') }}</span>
            <p class="rw-tuile__texte">{{ __('profil.non_porte_texte') }}</p>
            <p class="rw-tuile__lien">
                <a class="rw-lien" href="{{ rtrim(config('app.url_legacy'), '/') }}/profile.php"
                   target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
            </p>
        </div>
    </div>
@endsection
