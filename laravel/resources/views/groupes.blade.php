@extends('layouts.portail', ['titre' => __('nav.groups')])

@section('corps')
    <h1 class="rw-titre">{{ __('groups.titre') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('groups.desc') }}</p>

    {{--
        ═══ CE QUE LA PAGE PEUT FAIRE AUJOURD'HUI ═══════════════════════════

        R1 ne porte que la LECTURE. Le dire en tete plutot que de le laisser
        decouvrir bouton par bouton : une capacite absente doit etre DECLAREE,
        pas devinee.

        La seconde phrase n'est pas une limite du portage, c'est une propriete
        du produit : un role 2 porteur de `can_admin_portal` peut viser tout le
        parc, `srv-zabbix` comprise. Aucune table d'acces par machine
        n'intervient sur ces routes — `check_machine_access` rend `True` des le
        role 2, donc `@require_machine_access` y serait inerte. Ce n'est pas un
        defaut, c'est une decision de conception que la page doit dire.
    --}}
    <div class="rw-carte rw-carte--pleine" data-rw="groupes-portee">
        <h2 class="rw-sous-titre-fort">{{ __('groups.portee_titre') }}</h2>
        <p class="rw-prose">{{ __('groups.portee_texte') }}</p>
        <p class="rw-prose">{{ __('groups.parc_entier') }}</p>
    </div>

    <div class="rw-actions">
        <button type="button" class="rw-bouton rw-bouton--discret"
                data-rw="groupes-nouveau">{{ __('groups.act_nouveau') }}</button>
    </div>

    {{--
        ═══ UN SEUL PANNEAU, AU NIVEAU DE LA PAGE ═══════════════════════════

        Lecon de F5 : un element partage par plusieurs cartes ne vit dans
        AUCUNE d'elles. Le legacy confirme par `confirm()` natif — proscrit
        ici : il recouvre la ligne sur laquelle on decide, ne se style pas, et
        BLOQUE Puppeteer.

        Et le `confirm()` du legacy ne dit ni le nombre de machines, ni leur
        identite, ni si la production en fait partie, ni la difference de
        nature entre les deux actions de masse — le meme texte sert pour un
        geste sans effet distant et pour un geste qui ouvre N sessions SSH et
        envoie N courriels. Ce panneau dit les quatre.
    --}}
    <div class="rw-panneau-decision" data-rw="groupes-panneau" hidden>
        <div>
            <p class="rw-panneau-decision__texte" data-rw="groupes-panneau-titre"></p>
            <p class="rw-prose" data-rw="groupes-panneau-texte"></p>
            {{-- Les precisions chiffrees : nombre de membres, production
                 nommee, et la reserve sur la re-resolution. Vides et masquees
                 tant qu'elles n'ont pas d'objet — une ligne blanche est
                 exactement ce que ce portage reproche au legacy. --}}
            <ul class="rw-liste-effets" data-rw="groupes-panneau-effets" hidden></ul>
        </div>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="groupes-panneau-fermer">{{ __('groups.np_fermer') }}</button>
            {{-- ACTION PRINCIPALE : le lien vers l'ancien portail. Un panneau
                 dont la seule issue serait « Fermer » ne serait pas une
                 decision. Marqueur `↗` comme dans le menu. --}}
            <a class="rw-bouton" data-rw="groupes-panneau-legacy"
               href="{{ $lienLegacy }}" target="_blank" rel="noopener">{{ __('groups.np_ouvrir') }} ↗</a>
        </div>
    </div>

    {{-- La liste est remplie par le script. L'etat de depart est un texte de
         chargement et non une grille vide : une grille vide se lit « aucun
         groupe » avant meme que la requete soit partie. --}}
    <div data-rw="groupes-liste">
        <p class="rw-vide__texte" data-rw="groupes-chargement">{{ __('groups.chargement') }}</p>
    </div>

    <script id="groupes-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/groupes.js?v={{ @filemtime(public_path('js/groupes.js')) ?: '0' }}"></script>
@endsection
