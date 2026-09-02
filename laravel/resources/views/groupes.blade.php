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
        ══ R2 — LE FORMULAIRE DE CREATION ══════════════════════════════════

        ⚠ IL FERME E-274 PAR CONSTRUCTION, ET C'EST SA RAISON D'ETRE.

        `_resolve_dynamic` (`backend/routes/groups.py:77`) termine par `'1=1'`
        quand aucun critere n'est coche : le groupe contient alors LE PARC
        ENTIER, production comprise. Et l'etat par DEFAUT du formulaire du
        legacy est exactement celui-la — saisir un nom et enregistrer suffit,
        sans qu'aucun ecran ne le dise.

        Ici « Enregistrer » n'enregistre pas : il ouvre le panneau de decision,
        qui ANNONCE la portee resolue. **On ne peut donc plus creer un groupe
        sans avoir lu ce qu'il contiendra.** C'est la meme separation que le
        module impose ailleurs entre verifier et agir.

        Aucun champ de saisie LIBRE pour les criteres : ce sont des cases a
        cocher sur des valeurs closes. Une entree libre validee se contourne
        par une requete forgee ; une entree libre absente, non.
    --}}
    <div class="rw-carte rw-carte--pleine" data-rw="groupes-formulaire" hidden>
        <h2 class="rw-sous-titre-fort">{{ __('groups.form_titre') }}</h2>

        <div class="rw-grille-champs">
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="g-nom">{{ __('groups.f_nom') }}</label>
                <input id="g-nom" type="text" maxlength="100" class="rw-saisie" data-rw="groupes-nom">
            </div>
            <div class="rw-champ">
                <label class="rw-champ__etiquette" for="g-desc">{{ __('groups.f_desc') }}</label>
                <input id="g-desc" type="text" maxlength="255" class="rw-saisie" data-rw="groupes-desc">
            </div>
        </div>

        <div class="rw-champ rw-champ--espace">
            <span class="rw-champ__etiquette">{{ __('groups.f_type') }}</span>
            <label class="rw-champ--case">
                <input type="radio" name="g-type" value="dynamic" checked data-rw="groupes-type-dyn">
                <span>{{ __('groups.type_dynamique') }}</span>
            </label>
            <p class="rw-aide">{{ __('groups.type_dyn_aide') }}</p>
            <label class="rw-champ--case">
                <input type="radio" name="g-type" value="static" data-rw="groupes-type-stat">
                <span>{{ __('groups.type_statique') }}</span>
            </label>
            <p class="rw-aide">{{ __('groups.type_stat_aide') }}</p>
        </div>

        {{-- Les quatre enumerations, en cases a cocher : valeurs CLOSES. --}}
        <div data-rw="groupes-filtres">
            <div class="rw-grille-champs">
                @foreach ([
                    'environment'      => ['cle' => 'f_env',    'valeurs' => ['PROD', 'DEV', 'TEST', 'OTHER']],
                    'criticality'      => ['cle' => 'f_crit',   'valeurs' => ['CRITIQUE', 'NON CRITIQUE']],
                    'network_type'     => ['cle' => 'f_reseau', 'valeurs' => ['INTERNE', 'EXTERNE']],
                    'lifecycle_status' => ['cle' => 'f_cycle',  'valeurs' => ['active', 'retiring', 'archived']],
                ] as $colonne => $bloc)
                    <div class="rw-champ">
                        <span class="rw-champ__etiquette">{{ __('groups.' . $bloc['cle']) }}</span>
                        @foreach ($bloc['valeurs'] as $v)
                            <label class="rw-champ--case">
                                <input type="checkbox" class="gf" data-col="{{ $colonne }}" value="{{ $v }}">
                                <span>{{ $v }}</span>
                            </label>
                        @endforeach
                    </div>
                @endforeach
            </div>
        </div>

        <div data-rw="groupes-membres" hidden>
            <span class="rw-champ__etiquette">{{ __('groups.f_membres') }}</span>
            @if (! $parcLisible)
                <p class="rw-vide__texte">{{ __('groups.err_charge') }}</p>
            @else
                <div class="rw-liste-selection">
                    @foreach ($machines as $m)
                        <label class="rw-liste-selection__etiquette">
                            <input type="checkbox" class="gm" value="{{ $m->id }}">
                            <span class="rw-liste-selection__nom">{{ $m->name }}</span>
                            <span class="rw-liste-selection__detail">{{ $m->ip }}</span>
                        </label>
                    @endforeach
                </div>
            @endif
        </div>

        <div class="rw-actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="groupes-annuler">{{ __('groups.btn_annuler') }}</button>
            <button type="button" class="rw-bouton"
                    data-rw="groupes-enregistrer">{{ __('groups.btn_enregistrer') }}</button>
        </div>
        <p class="rw-annonce" role="status" aria-live="polite" data-rw="groupes-form-message"></p>
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
            {{-- R2 : masque par defaut. Les panneaux des gestes NON portes
                 n'ont rien a confirmer — seul l'enregistrement d'un groupe
                 l'affiche, apres avoir annonce la portee resolue. --}}
            <button type="button" class="rw-bouton rw-bouton--succes"
                    data-rw="groupes-panneau-confirmer" hidden>{{ __('groups.btn_enregistrer') }}</button>
            {{-- ACTION PRINCIPALE : le lien vers l'ancien portail. Un panneau
                 dont la seule issue serait « Fermer » ne serait pas une
                 decision. Marqueur `↗` comme dans le menu. --}}
            <a class="rw-bouton" data-rw="groupes-panneau-legacy"
               href="{{ $lienLegacy }}" target="_blank" rel="noopener">{{ __('groups.np_ouvrir') }} ↗</a>
        </div>
    </div>

    {{-- L'ANNONCE DU GESTE — region live PRESENTE DES LE CHARGEMENT, et vide.
         Une region `aria-live` ajoutee au DOM au moment du message n'est pas
         annoncee : elle doit etre dans l'arbre AVANT l'insertion. Idiome de
         `comptes` et de vingt-cinq autres vues, repris tel quel plutot que
         reinvente. --}}
    <p class="rw-annonce" data-rw="groupes-annonce" role="status" aria-live="polite"></p>

    {{-- La liste est remplie par le script. L'etat de depart est un texte de
         chargement et non une grille vide : une grille vide se lit « aucun
         groupe » avant meme que la requete soit partie. --}}
    <div data-rw="groupes-liste">
        <p class="rw-vide__texte" data-rw="groupes-chargement">{{ __('groups.chargement') }}</p>
    </div>

    <script id="groupes-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/groupes.js?v={{ @filemtime(public_path('js/groupes.js')) ?: '0' }}"></script>
@endsection
