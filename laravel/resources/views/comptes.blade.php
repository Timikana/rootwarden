@extends('layouts.portail', ['titre' => __('comptes.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('comptes.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('comptes.desc') }}</p>

    @include('composants.onglets-adm', ['courant' => 'comptes'])

    {{-- LE POINT D'ENTREE DES CLES D'API. Le legacy le pose dans l'en-tête de
         sa page d'administration (`admin_page.php:153`) ; la page n'est dans
         AUCUN menu, ni le sien ni celui du portage. Sans ce lien, elle ne
         s'atteindrait qu'en tapant son adresse. Réservée au rôle 3 : l'afficher
         plus bas mènerait à un 403. --}}
    @if ((int) session('role_id', 0) >= 3)
        <p>
            <a class="rw-bouton rw-bouton--discret" data-rw="comptes-lien-cles-api"
               href="{{ route('cles-api') }}">{{ __('comptes.lien_cles_api') }}</a>
        </p>
    @endif

    {{-- LE BLOC « CAPACITE NON PORTEE » A ETE RETIRE ICI, ET C'EST LE POINT.
         Il disait « ne reste que l'import CSV » et renvoyait vers
         `admin_page.php`. L'import est porte depuis D6c : le laisser aurait fait
         d'un ecran qui OFFRE la capacite un ecran qui la declare absente.

         C'est la classe de defaut la plus repetee de ce chantier — une
         declaration VRAIE quand elle a ete ecrite et FAUSSE quand la capacite a
         ete portee, sans que rien ne la touche. Elle part avec ses trois cles. --}}

    <p class="rw-annonce" data-rw="comptes-annonce" role="status" aria-live="polite">
        @if (session('succes')){{ session('succes') }}@endif
        @if (session('erreur')){{ session('erreur') }}@endif
    </p>

    {{-- Le mot de passe genere s'affiche ICI, une fois, et n'est jamais rendu
         par le serveur dans le HTML de la page : il arrive dans la reponse du
         geste qui l'a demande. Le legacy le place dans la page, d'ou il part
         dans l'historique du navigateur (E-113). --}}
    <div class="rw-panneau-decision" data-rw="comptes-secret" hidden>
        <p class="rw-panneau-decision__texte">{{ __('comptes.secret_titre') }}</p>
        <p><code class="rw-code" data-rw="comptes-secret-valeur"></code></p>
        <p class="rw-aide">{{ __('comptes.secret_aide') }}</p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton" data-rw="comptes-secret-fermer">{{ __('comptes.compris') }}</button>
        </div>
    </div>

    @if (($secretsImport ?? []) !== [])
        {{-- ⚠ DIVERGENCE DECLAREE AVEC LA NORME DE CET ECRAN, JUSTE AU-DESSUS.
             Le panneau `comptes-secret` ne met JAMAIS un secret dans le HTML de
             la page : il arrive par la reponse d'un geste AJAX et le JS l'injecte
             (E-113 — le legacy le placait dans la page, d'ou il partait dans
             l'historique du navigateur).

             Ici les secrets sont N, et ils SONT dans le HTML — mais dans le corps
             d'une reponse a un POST, qui n'entre pas dans l'historique comme une
             URL rejouable. C'est le motif de `ClesApiController`, choisi pour la
             meme raison que lui : un message de session les deposerait sur le
             disque du conteneur (pilote `file`).

             Le prix est celui de ce motif : recharger repropose le formulaire, et
             les secrets disparaissent. C'est voulu.

             ⚠ CE BLOC SERT LES DEUX CHEMINS DE CREATION — l'import CSV et la
             creation unitaire. Il s'appelait `comptes-import-secrets` quand il
             n'en servait qu'un ; ce nom serait devenu faux. --}}
        <section class="rw-carte rw-carte--pleine" data-rw="comptes-secrets-remis">
            <h2 class="rw-sous-titre">{{ __('comptes.imp_secrets_titre') }}</h2>
            <p class="rw-prose rw-alerte rw-alerte--attention">{{ __('comptes.imp_mdp_avert') }}</p>
            <div class="rw-tableau-cadre">
                <table class="rw-tableau">
                    <thead>
                        <tr><th>{{ __('comptes.col_nom') }}</th><th>{{ __('comptes.secret_titre') }}</th></tr>
                    </thead>
                    <tbody>
                        @foreach ($secretsImport as $s)
                            <tr>
                                <td>{{ $s['nom'] }}</td>
                                <td><code class="rw-code">{{ $s['mdp'] }}</code></td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </section>
    @endif

    @if (($import ?? null) !== null)
        <section class="rw-carte rw-carte--pleine" data-rw="comptes-import-bilan">
            <h2 class="rw-sous-titre">{{ __('comptes.imp_bilan_titre') }}</h2>
            @if ($import['manquantes'] !== [])
                <p class="rw-prose rw-erreur" data-rw="comptes-import-manquantes">
                    {{ __('comptes.imp_manquantes', ['colonnes' => implode(', ', $import['manquantes'])]) }}
                </p>
            @else
                <p data-rw="comptes-import-compte">
                    {{ __('comptes.imp_crees', ['n' => $import['crees']]) }}
                    {{ __('comptes.imp_lues', ['n' => $import['lignes']]) }}
                </p>
                @if ($import['tronque'])
                    {{-- Une coupe se DIT. Un bilan qui annonce 500 lignes lues sans
                         dire que le fichier en portait plus se lit comme complet. --}}
                    <p class="rw-prose rw-erreur" data-rw="comptes-import-tronque">
                        {{ __('comptes.imp_tronque', ['max' => \App\Services\Comptes::IMPORT_MAX_LIGNES]) }}
                    </p>
                @endif
                @if ($import['erreurs'] !== [])
                    <p><strong data-rw="comptes-import-erreurs">{{ __('comptes.imp_erreurs_titre', ['n' => count($import['erreurs'])]) }}</strong></p>
                    <ul>
                        @foreach ($import['erreurs'] as $e)
                            <li class="rw-prose">
                                <strong>{{ __('comptes.imp_ligne', ['n' => $e['ligne']]) }}</strong>
                                @if ($e['nom'] !== '') — {{ $e['nom'] }} @endif
                                — {{ $e['texte'] }}
                            </li>
                        @endforeach
                    </ul>
                @endif
            @endif
        </section>
    @endif

    <section class="rw-carte rw-carte--pleine">
        <details data-rw="comptes-import-bloc">
            <summary class="rw-sous-titre-fort">{{ __('comptes.imp_titre') }}</summary>

            <p class="rw-prose rw-aide">{{ __('comptes.imp_aide', [
                'colonnes' => implode(', ', $importColonnes ?? []),
                'facultatives' => 'role, ssh_key, active, sudo',
            ]) }}</p>
            <p class="rw-prose rw-aide">{{ __('comptes.imp_roles_aide', ['roles' => implode(', ', $importRoles ?? [])]) }}</p>
            <p class="rw-prose rw-aide" data-rw="comptes-import-courriel">{{ __('comptes.imp_courriel_exige') }}</p>
            <p class="rw-prose rw-alerte rw-alerte--attention" data-rw="comptes-import-mdp">{{ __('comptes.imp_mdp_avert') }}</p>

            <form method="POST" action="{{ route('comptes.importer') }}"
                  enctype="multipart/form-data" data-rw="comptes-import-formulaire">
                @csrf
                <label class="rw-champ">
                    <span class="rw-champ__etiquette" for="comptes-import-fichier">
                        {{ __('comptes.imp_fichier', ['ko' => $importMaxKo ?? 512]) }}
                    </span>
                    <input class="rw-saisie" type="file" name="fichier" id="comptes-import-fichier"
                           accept=".csv,text/csv,text/plain" required
                           data-rw="comptes-import-fichier">
                </label>
                <div class="rw-actions">
                    <button type="submit" class="rw-bouton"
                            data-rw="comptes-import-valider">{{ __('comptes.imp_valider') }}</button>
                </div>
            </form>
        </details>
    </section>

    <section class="rw-carte rw-carte--pleine">
        <details data-rw="comptes-creation-bloc">
            <summary class="rw-sous-titre-fort">{{ __('comptes.creer_titre') }}</summary>
            <form method="POST" action="{{ route('comptes.creer') }}" class="rw-barre-filtres">
                @csrf
                <label class="rw-filtre">
                    <span class="rw-filtre__etiquette">{{ __('comptes.col_nom') }}</span>
                    <input type="text" name="name" required maxlength="255"
                           class="rw-saisie rw-saisie--compacte" data-rw="compte-nom">
                </label>
                <label class="rw-filtre">
                    <span class="rw-filtre__etiquette">{{ __('comptes.col_courriel') }}</span>
                    <input type="email" name="email" maxlength="255"
                           class="rw-saisie rw-saisie--compacte" data-rw="compte-courriel">
                </label>
                <label class="rw-filtre">
                    <span class="rw-filtre__etiquette">{{ __('comptes.col_societe') }}</span>
                    <input type="text" name="company" maxlength="255"
                           class="rw-saisie rw-saisie--compacte" data-rw="compte-societe">
                </label>
                <label class="rw-filtre">
                    <span class="rw-filtre__etiquette">{{ __('comptes.col_role') }}</span>
                    <select name="role_id" class="rw-saisie rw-saisie--compacte" data-rw="compte-role">
                        @foreach ($roles as $r)
                            <option value="{{ $r }}">{{ __('comptes.role_' . $r) }}</option>
                        @endforeach
                    </select>
                </label>
                <button type="submit" class="rw-bouton" data-rw="compte-creer">{{ __('comptes.creer') }}</button>
            </form>
        </details>
    </section>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau">
            <thead>
                <tr>
                    <th>{{ __('comptes.col_nom') }}</th>
                    <th class="rw-colonne-secondaire">{{ __('comptes.col_courriel') }}</th>
                    <th>{{ __('comptes.col_role') }}</th>
                    <th>{{ __('comptes.col_etat') }}</th>
                    <th>{{ __('comptes.col_mdp') }}</th>
                    <th>{{ __('comptes.col_actions') }}</th>
                </tr>
            </thead>
            <tbody data-rw="comptes-corps">
                @foreach ($comptes as $c)
                    <tr data-rw="compte-ligne-{{ $c['id'] }}">
                        <td class="rw-tableau__fort">{{ $c['name'] }}</td>
                        <td class="rw-colonne-secondaire">{{ $c['email'] ?? '—' }}</td>
                        <td>{{ __('comptes.role_' . $c['role_id']) }}</td>
                        <td>
                            @if ((int) $c['active'] === 1)
                                <span class="rw-badge rw-badge--ok">{{ __('comptes.actif') }}</span>
                            @else
                                <span class="rw-badge rw-badge--neutre">{{ __('comptes.inactif') }}</span>
                            @endif
                            @if (empty($c['totp_secret']))
                                <span class="rw-badge rw-badge--attention"
                                      title="{{ __('comptes.sans_2fa_aide') }}">{{ __('comptes.sans_2fa') }}</span>
                            @endif
                            @if (! empty($c['locked_until']))
                                <span class="rw-badge rw-badge--alerte">{{ __('comptes.verrouille') }}</span>
                            @endif
                        </td>
                        <td>
                            {{-- Un champ par ligne, jamais « le premier de la page ». --}}
                            <input type="password" class="rw-saisie rw-saisie--compacte"
                                   data-rw="compte-mdp" data-id="{{ $c['id'] }}"
                                   autocomplete="new-password"
                                   placeholder="{{ __('comptes.mdp_placeholder', ['minimum' => $longueurMinimale]) }}">
                            <button type="button" class="rw-bouton rw-bouton--minuscule"
                                    data-rw="compte-mdp-poser-{{ $c['id'] }}"
                                    data-id="{{ $c['id'] }}">{{ __('comptes.mdp_poser') }}</button>
                            <button type="button" class="rw-bouton rw-bouton--minuscule rw-bouton--discret"
                                    data-rw="compte-mdp-generer-{{ $c['id'] }}"
                                    data-id="{{ $c['id'] }}">{{ __('comptes.mdp_generer') }}</button>
                        </td>
                        <td class="rw-tableau__actions">
                            {{--
                                L'EXEMPTION D'EXPIRATION — superadministrateur
                                seulement, et JAMAIS sur son propre compte.

                                ⚠ LE CONTROLE N'EST PAS RENDU SUR SA PROPRE LIGNE.
                                Le serveur refuse deja ce cas (`exp_pas_soi`), mais
                                offrir un selecteur qui rendra 403 apprend seulement
                                que le produit se contredit. **Un geste qu'on ne
                                rend pas ne se contourne pas ; un geste qu'on rend
                                et que le serveur refuse est une promesse rompue.**

                                Liste FERMEE : trois choix, pas une saisie libre.
                                Le legacy accepte n'importe quel entier, negatif
                                compris — et `-1` poserait une echeance dans le
                                PASSE, donc un compte expire a l'instant meme.
                            --}}
                            @if ($estSuperadmin && (int) $c['id'] !== (int) session('utilisateur_id'))
                                <label class="rw-visuellement-cache"
                                       for="exp-{{ $c['id'] }}">{{ __('comptes.exp_titre') }}</label>
                                <select id="exp-{{ $c['id'] }}" class="rw-saisie rw-saisie--compacte"
                                        data-rw="compte-expiration-{{ $c['id'] }}" data-id="{{ $c['id'] }}">
                                    <option value=""@selected($c['password_expiry_override'] === null)>{{ __('comptes.exp_globale') }}</option>
                                    <option value="0"@selected((int) $c['password_expiry_override'] === 0 && $c['password_expiry_override'] !== null)>{{ __('comptes.exp_exempte') }}</option>
                                    @foreach ([30, 60, 90, 180, 365] as $j)
                                        <option value="{{ $j }}"@selected((int) $c['password_expiry_override'] === $j)>{{ $j }} j</option>
                                    @endforeach
                                </select>
                            @endif
                            @if (! empty($c['locked_until']))
                                <button type="button" class="rw-bouton rw-bouton--minuscule"
                                        data-rw="compte-deverrouiller-{{ $c['id'] }}"
                                        data-id="{{ $c['id'] }}">{{ __('comptes.deverrouiller') }}</button>
                            @endif
                            {{-- LES DEUX GESTES COTE A COTE. Le legacy n'en offre
                                 qu'un — le destructeur — alors qu'il PORTE
                                 l'anonymisation, gardee et commentee, sans aucun
                                 appelant (E-117).
                                 DEBORDEMENT MESURE ET NON RESOLU : ces deux
                                 boutons portent le tableau au-dela du cadre a
                                 1400 px, et « Anonymiser » y est coupe. Le cadre
                                 defile et le signale, mais la regle du chantier
                                 veut que la colonne actionnable ne cede jamais.
                                 A reprendre avec D5, qui rendra ce tableau a sa
                                 largeur en sortant les colonnes d'appoint. --}}
                            @if ($estSuperadmin)
                                <button type="button" class="rw-bouton rw-bouton--minuscule rw-bouton--danger"
                                        data-rw="compte-supprimer-{{ $c['id'] }}"
                                        data-id="{{ $c['id'] }}"
                                        data-nom="{{ $c['name'] }}">{{ __('comptes.supprimer') }}</button>
                                <button type="button" class="rw-bouton rw-bouton--minuscule rw-bouton--avertissement"
                                        data-rw="compte-anonymiser-{{ $c['id'] }}"
                                        data-id="{{ $c['id'] }}"
                                        data-nom="{{ $c['name'] }}">{{ __('comptes.anonymiser') }}</button>
                            @endif
                            @if ($estSuperadmin && ! empty($c['totp_secret']))
                                {{-- AUCUNE BOITE NATIVE : la decision se prend en page.
                                     Le legacy pose un `confirm()` dont le texte francais
                                     contient une apostrophe qui casse le script — la
                                     confirmation ne s'affiche donc jamais et l'action part
                                     quand meme (E-114). --}}
                                <button type="button" class="rw-bouton rw-bouton--minuscule rw-bouton--avertissement"
                                        data-rw="compte-totp-{{ $c['id'] }}"
                                        data-id="{{ $c['id'] }}"
                                        data-nom="{{ $c['name'] }}">{{ __('comptes.totp_reinitialiser') }}</button>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    {{-- Le panneau de decision du second facteur : il NOMME le compte et dit ce
         que le geste engage. Un `confirm()` ne peut ni l'un ni l'autre. --}}
    <div class="rw-panneau-decision" data-rw="comptes-panneau-totp" hidden>
        <p class="rw-panneau-decision__texte" data-rw="comptes-panneau-totp-texte"></p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="comptes-totp-annuler">{{ __('comptes.annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="comptes-totp-confirmer">{{ __('comptes.totp_confirmer') }}</button>
        </div>
    </div>

    {{-- Le panneau de decision de la SUPPRESSION. Il dit ce que le geste emporte,
         et il EMPECHE plutot que de reprocher : la confirmation naît desactivee
         et ne s'active qu'a la saisie exacte du nom du compte. --}}
    <div class="rw-panneau-decision" data-rw="comptes-panneau-suppression" hidden>
        <p class="rw-panneau-decision__texte" data-rw="comptes-suppression-texte"></p>
        <p class="rw-aide" data-rw="comptes-suppression-detail"></p>
        <label class="rw-champ">
            <span class="rw-champ__etiquette" data-rw="comptes-suppression-consigne"></span>
            <input type="text" class="rw-saisie rw-saisie--compacte"
                   data-rw="comptes-suppression-saisie" autocomplete="off">
        </label>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="comptes-suppression-annuler">{{ __('comptes.annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--avertissement"
                    data-rw="comptes-suppression-anonymiser" hidden>{{ __('comptes.anonymiser_plutot') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="comptes-suppression-confirmer" disabled>{{ __('comptes.supprimer') }}</button>
        </div>
    </div>

    {{-- LE PANNEAU DE STEP-UP, differe par le sous-lot A5 « a son premier
         consommateur ». Le voici : D4 est ce consommateur. Le legacy fait la
         meme chose dans un modal pose par une surcouche de `window.fetch` — ici
         c'est un panneau en page, qui ne recouvre pas ce sur quoi on decide. --}}
    <div class="rw-panneau-decision" data-rw="comptes-panneau-stepup" hidden>
        <p class="rw-panneau-decision__texte">{{ __('comptes.step_up_titre') }}</p>
        <p class="rw-aide">{{ __('comptes.step_up_aide') }}</p>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('comptes.step_up_code') }}</span>
            <input type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code"
                   class="rw-saisie rw-saisie--code" data-rw="comptes-stepup-code">
        </label>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="comptes-stepup-annuler">{{ __('comptes.annuler') }}</button>
            <button type="button" class="rw-bouton"
                    data-rw="comptes-stepup-valider">{{ __('comptes.step_up_valider') }}</button>
        </div>
    </div>

    @php($libelles = ['err_reseau' => __('comptes.err_reseau'), 'totp_question' => __('comptes.totp_question'), 'mdp_vide' => __('comptes.err_mdp_vide'), 'suppr_question' => __('comptes.suppr_question'), 'suppr_sans_journal' => __('comptes.suppr_sans_journal'), 'suppr_avec_journal' => __('comptes.suppr_avec_journal'), 'suppr_consigne' => __('comptes.suppr_consigne'), 'anon_question' => __('comptes.anon_question')])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="comptes-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/comptes.js?v={{ @filemtime(public_path('js/comptes.js')) ?: '0' }}"></script>
@endsection
