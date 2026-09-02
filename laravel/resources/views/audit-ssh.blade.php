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

        {{-- Les trois gestes distants du module ne sont pas portes en A1.
             Aucun bouton inerte : chacun ouvre un panneau qui dit ce qu'il
             engage. Celui du parc entier est le plus important de la page. --}}
        <div class="rw-actions--groupe">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="audit-ssh-relever">{{ __('ssh_audit.btn_relever') }} ↗</button>
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="audit-ssh-config">{{ __('ssh_audit.btn_config') }} ↗</button>
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
            <a class="rw-bouton" data-rw="audit-ssh-panneau-legacy"
               href="{{ $lienLegacy }}" target="_blank" rel="noopener">{{ __('ssh_audit.np_ouvrir') }} ↗</a>
        </div>
    </div>

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
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="audit-ssh-planif-creer">{{ __('ssh_audit.btn_planif') }} ↗</button>
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
