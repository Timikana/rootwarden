@extends('layouts.portail', ['titre' => __('nav.ssh_audit')])

@section('corps')
    <h1 class="rw-titre">{{ __('ssh_audit.titre') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('ssh_audit.desc') }}</p>

    <div class="rw-carte rw-carte--pleine" data-rw="audit-ssh-portee">
        <h2 class="rw-sous-titre-fort">{{ __('ssh_audit.portee_titre') }}</h2>
        <p class="rw-prose">{{ __('ssh_audit.portee_texte') }}</p>
    </div>

    {{--
        ═══ LE SELECTEUR, BORNE COMME LE LEGACY ═════════════════════════════

        `legacy/ssh-audit/index.php:22-33` porte sa propre correction d'IDOR :
        avant elle, le selecteur listait TOUT le parc — noms ET adresses IP —
        quel que soit le role. La borne est reprise, mais ecrite au seul
        endroit qui la porte deja (`Machines::requeteBornee`).
    --}}
    @if (! $lisible)
        {{-- UNE BASE MUETTE N'EST PAS UN PERIMETRE VIDE. « Aucun serveur ne
             vous est attribue » se lirait comme un fait sur les droits. --}}
        <div class="rw-vide rw-vide--erreur" data-rw="audit-ssh-perimetre-illisible">
            <p class="rw-vide__texte">{{ __('ssh_audit.historique_err') }}</p>
        </div>
    @elseif (! count($serveurs))
        <div class="rw-vide" data-rw="audit-ssh-aucun-serveur">
            <p class="rw-vide__texte">{{ __('ssh_audit.serveur_aucun') }}</p>
        </div>
    @else
        <div class="rw-champ rw-champ--espace">
            <label class="rw-champ__etiquette" for="audit-ssh-serveur">{{ __('ssh_audit.serveur_cible') }}</label>
            <select id="audit-ssh-serveur" class="rw-saisie rw-saisie--compacte" data-rw="audit-ssh-serveur">
                <option value="">{{ __('ssh_audit.serveur_choisir') }}</option>
                @foreach ($serveurs as $s)
                    <option value="{{ $s->id }}">{{ $s->name }} — {{ $s->ip }}</option>
                @endforeach
            </select>
            @if ($borne)
                <p class="rw-aide" data-rw="audit-ssh-borne">{{ __('ssh_audit.serveur_borne') }}</p>
            @endif
        </div>

        {{-- ⚠ CE COMMENTAIRE DISAIT « LES TROIS GESTES NE SONT PAS PORTES »,
             et il est devenu faux en deux temps : A3 a porte l'affichage de
             `sshd_config`, A4 le releve d'un serveur. Il n'en reste qu'UN non
             porte — le releve de TOUT LE PARC — et sa route n'accepte aucun
             `machine_id` : sa portee EST le parc, production comprise. Elle
             est reservee a l'exploitant.

             Un commentaire qui compte est un compte qui se desynchronise ;
             celui-ci enonce desormais l'etat, pas un nombre. --}}
        <div class="rw-actions--groupe">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    {{-- A4 : marqueur `↗` retire avec sa raison d'etre. --}}
                    data-rw="audit-ssh-relever">{{ __('ssh_audit.btn_relever') }}</button>
            <button type="button" class="rw-bouton rw-bouton--discret"
                    {{-- A3 : le marqueur `↗` est retire avec la raison de
                         l'afficher. Il annoncait un depart vers l'ancien
                         portail ; la lecture est portee. --}}
                    data-rw="audit-ssh-config">{{ __('ssh_audit.btn_config') }}</button>
            <button type="button" class="rw-bouton rw-bouton--avertissement"
                    data-rw="audit-ssh-parc">{{ __('ssh_audit.btn_parc') }} ↗</button>
        </div>
    @endif

    {{-- UN SEUL PANNEAU, AU NIVEAU DE LA PAGE — lecon de F5. Il NOMME sa
         cible : il sert cinq boutons appartenant a des endroits differents. --}}
    <div class="rw-panneau-decision" data-rw="audit-ssh-panneau" hidden>
        <div>
            <p class="rw-panneau-decision__texte" data-rw="audit-ssh-panneau-titre"></p>
            <p class="rw-prose" data-rw="audit-ssh-panneau-texte"></p>
            <ul class="rw-liste-effets" data-rw="audit-ssh-panneau-effets" hidden></ul>
        </div>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="audit-ssh-panneau-fermer">{{ __('ssh_audit.np_fermer') }}</button>
            {{-- A2 : MASQUE PAR DEFAUT. Les panneaux des gestes NON portes
                 n'ont rien a confirmer — seule la planification l'affiche,
                 apres avoir annonce ce qu'elle arme. Et `fermePanneau()`
                 DESARME le rappel : un bouton partage qui garde le geste du
                 panneau precedent agit sur autre chose que ce qu'on a lu. --}}
            <button type="button" class="rw-bouton rw-bouton--avertissement"
                    data-rw="audit-ssh-panneau-confirmer" hidden>{{ __('ssh_audit.planif_valider') }}</button>
            <a class="rw-bouton" data-rw="audit-ssh-panneau-legacy"
               href="{{ $lienLegacy }}" target="_blank" rel="noopener">{{ __('ssh_audit.np_ouvrir') }} ↗</a>
        </div>
    </div>

    {{-- ═══ A3 — LE CONTENU DE `sshd_config`, EN LECTURE SEULE ════════════

         Masque tant qu'aucune lecture n'a abouti. Un cadre vide affiche en
         permanence se lit comme « le fichier est vide » alors qu'il veut dire
         « personne n'a encore demande ».

         La LECTURE SEULE est DITE : l'absence d'un bouton « enregistrer » ne
         se lit pas comme une interdiction, elle se lit comme un oubli. --}}
    {{-- A4 : l'annonce du releve. Region live PRESENTE des le chargement et
         vide — une region `aria-live` ajoutee au moment du message n'est pas
         annoncee. --}}
    <p class="rw-annonce" data-rw="audit-ssh-relever-message" role="status" aria-live="polite"></p>

    <section class="rw-carte rw-carte--pleine" data-rw="audit-ssh-config-bloc" hidden>
        <h3 class="rw-section__entete" data-rw="audit-ssh-config-titre"></h3>
        <p class="rw-aide rw-prose" data-rw="audit-ssh-config-reserve">{{ __('ssh_audit.cfg_lecture_seule') }}</p>
        <div class="rw-tableau-cadre">
            <pre class="rw-journal" data-rw="audit-ssh-config-contenu"></pre>
        </div>
    </section>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('ssh_audit.historique_titre') }}</h2>
    <div data-rw="audit-ssh-historique">
        <p class="rw-vide__texte">{{ __('ssh_audit.historique_choisir') }}</p>
    </div>

    <h2 class="rw-section__entete rw-titre--espace">{{ __('ssh_audit.politique_titre') }}</h2>
    <p class="rw-prose">{{ __('ssh_audit.politique_desc') }}</p>
    {{--
        ⚠ SEC-013 — POURQUOI L'ECRITURE N'EST PAS OFFERTE ICI.

            GET  /ssh-audit/policies  ->  can_audit_ssh + require_machine_access
            POST /ssh-audit/policies  ->  require_role(2) SEUL

        Un role 2 sans la permission ne peut pas LIRE une politique et peut en
        ECRIRE une, sur n'importe quelle machine. La passerelle ne peut pas les
        separer : elle compare des CHEMINS, jamais des methodes.

        On le DIT plutot que de laisser croire a un oubli — une capacite
        absente doit etre declaree, et celle-ci l'est pour une raison.
    --}}
    <p class="rw-aide rw-prose" data-rw="audit-ssh-politique-lecture-seule">{{ __('ssh_audit.politique_lecture_seule') }}</p>
    <div data-rw="audit-ssh-politique">
        <p class="rw-vide__texte">{{ __('ssh_audit.politique_choisir') }}</p>
    </div>

    @if ($administration)
        <h2 class="rw-section__entete rw-titre--espace">{{ __('ssh_audit.flotte_titre') }}</h2>
        {{-- Cette vue N'EST PAS bornee au perimetre : `GET /ssh-audit/fleet`
             porte `@require_role(2)` et lit tout le parc. Le dire, plutot que
             de laisser croire que le tableau suit la meme borne que le
             selecteur juste au-dessus. --}}
        <p class="rw-aide rw-prose" data-rw="audit-ssh-flotte-reserve">{{ __('ssh_audit.flotte_reserve') }}</p>
        <div data-rw="audit-ssh-flotte">
            <p class="rw-vide__texte">{{ __('ssh_audit.chargement') }}</p>
        </div>

        <h2 class="rw-section__entete rw-titre--espace">{{ __('ssh_audit.planifs_titre') }}</h2>
        <div class="rw-actions">
            {{-- A2 : LE MARQUEUR `↗` A DISPARU AVEC LA RAISON DE L'AFFICHER.
                 Il annonçait un lien vers l'ancien portail ; le geste est
                 porté, et laisser la flèche ferait croire qu'on quitte le
                 portail. Un marqueur qui survit à sa cause trahit. --}}
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="audit-ssh-planif-creer">{{ __('ssh_audit.btn_planif') }}</button>
        </div>

        {{-- ═══ A2 — LE FORMULAIRE DE PLANIFICATION ══════════════════════════

             Il ne porte AUCUNE saisie libre en dehors du nom : périodicité,
             portée et valeur de portée sont trois listes fermées. Une entrée
             libre validée se contourne par une requête forgée ; une entrée
             libre absente, non — et ce qu'on arme ici déclenche des sessions
             SSH réelles, répétées, sans personne devant l'écran.

             Le rempart, lui, est côté serveur (`ssh_audit.py:752-800`). Le
             formulaire évite l'erreur ; il ne la refuse pas à la place du
             backend. --}}
        <div class="rw-carte rw-carte--pleine" data-rw="audit-ssh-planif-bloc" hidden>
            <h3 class="rw-section__entete">{{ __('ssh_audit.planif_form_titre') }}</h3>

            {{-- LA CAPACITÉ RÉDUITE EST DITE AVANT LE CHOIX, pas découverte
                 après. Quatre périodicités, et l'ancien portail pour le reste. --}}
            <p class="rw-aide rw-prose" data-rw="audit-ssh-planif-bornee">{{ __('ssh_audit.planif_freq_bornee') }}</p>

            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="audit-ssh-planif-nom">{{ __('ssh_audit.planif_f_nom') }}</label>
                <input class="rw-saisie" type="text" id="audit-ssh-planif-nom" maxlength="100"
                       data-rw="audit-ssh-planif-nom">
                <p class="rw-aide">{{ __('ssh_audit.planif_f_nom_aide') }}</p>
            </div>

            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="audit-ssh-planif-freq">{{ __('ssh_audit.planif_f_freq') }}</label>
                <select class="rw-saisie" id="audit-ssh-planif-freq" data-rw="audit-ssh-planif-freq">
                    @foreach ($frequences as $cle => $cron)
                        <option value="{{ $cron }}">{{ __('ssh_audit.' . $cle) }}</option>
                    @endforeach
                </select>
            </div>

            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="audit-ssh-planif-portee">{{ __('ssh_audit.planif_f_portee') }}</label>
                <select class="rw-saisie" id="audit-ssh-planif-portee" data-rw="audit-ssh-planif-portee">
                    @foreach (\App\Http\Controllers\AuditSshController::PORTEES as $portee)
                        <option value="{{ $portee }}">{{ __('ssh_audit.planif_portee_' . $portee) }}</option>
                    @endforeach
                </select>
            </div>

            {{-- LA VALEUR DE PORTÉE : trois listes fermées, une par type, et
                 masquées tant que leur type n'est pas choisi. Une portée
                 restreinte SANS valeur viserait tout le parc — E-280 — et le
                 bouton reste inerte jusqu'à ce qu'elle soit complète. --}}
            <div class="rw-champ" data-rw="audit-ssh-planif-valeur-bloc" hidden>
                <label class="rw-champ__etiquette" for="audit-ssh-planif-valeur">{{ __('ssh_audit.planif_f_valeur') }}</label>
                <select class="rw-saisie" id="audit-ssh-planif-valeur" data-rw="audit-ssh-planif-valeur"></select>
                <p class="rw-aide rw-erreur" data-rw="audit-ssh-planif-valeur-aide" hidden></p>
            </div>

            {{-- ⚠ `@json` NE PREND QU'UNE VARIABLE DEJA CONSTRUITE, et ce
                 n'est pas une preference de style : son analyseur d'argument
                 ne franchit pas une fonction flechee contenant un tableau.
                 Mon premier jet passait `collect($serveurs)->map(fn ($m) => [...])`,
                 et Blade a compile `json_encode([... collect($serveurs)->` —
                 TRONQUE en pleine expression, gabarit entier en erreur de
                 syntaxe. Les listes se construisent donc dans le controleur,
                 ou cette donnee appartient de toute facon. --}}
            <script id="audit-ssh-planif-listes" type="application/json">@json($planifListes)</script>

            <p class="rw-erreur" data-rw="audit-ssh-planif-message" role="status" aria-live="polite"></p>

            <div class="rw-actions">
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="audit-ssh-planif-annuler">{{ __('ssh_audit.planif_annuler') }}</button>
                <button type="button" class="rw-bouton"
                        data-rw="audit-ssh-planif-valider">{{ __('ssh_audit.planif_valider') }}</button>
            </div>
        </div>
        <div data-rw="audit-ssh-planifs">
            <p class="rw-vide__texte"></p>
        </div>
    @else
        {{-- UNE CAPACITE RESERVEE SE DIT ; ELLE NE DISPARAIT PAS.
             `GET /ssh-audit/fleet` et les quatre `/schedules` portent
             `@require_role(2)`. Ne rien rendre au role 1 laisserait croire que
             la fonction n'existe pas, ou qu'elle a disparu — alors qu'elle
             existe et lui est fermee. Deux phrases valent mieux qu'un silence. --}}
        <div class="rw-carte rw-carte--pleine" data-rw="audit-ssh-reserve-admin">
            <p class="rw-prose">{{ __('ssh_audit.flotte_reserve') }}</p>
            <p class="rw-prose">{{ __('ssh_audit.planifs_reserve') }}</p>
        </div>
    @endif

    <script id="audit-ssh-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/audit-ssh.js?v={{ @filemtime(public_path('js/audit-ssh.js')) ?: '0' }}"></script>
@endsection
