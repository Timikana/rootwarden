@extends('layouts.portail', ['titre' => __('perms.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('perms.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('perms.desc') }}</p>

    @include('composants.onglets-adm', ['courant' => 'permissions'])

    {{-- UNE SEULE LISTE, ET ELLE VIENT DU SCHEMA. Le legacy en porte trois — 18
         colonnes, 14 posables a la creation, 16 basculables — et les ecarts se
         croisent : une permission s'accorde sans se reprendre, une autre
         n'existe ni a la creation ni a la bascule (PARITE E-118). --}}

    {{-- CES NOTES SONT RENDUES UNE FOIS, PAS PAR COMPTE. La section
         « acces » vit dans la boucle des comptes ; y placer ces avertissements
         les repeterait autant de fois qu'il y a de comptes. L'equivalence root
         d'apt reste visible ; le reste se replie. --}}
    <div class="rw-encart" data-rw="perms-sudo-notes">
        <p class="rw-prose rw-aide">{{ __('perms.acces_aide') }}</p>
        <p class="rw-prose rw-aide" data-rw="perms-cles-aide">{{ __('perms.cles_aide') }}</p>
        <p class="rw-prose rw-alerte rw-alerte--attention" data-rw="perms-sudo-apt">
            {{ __('perms.acces_apt_avert') }}
        </p>
        <details class="rw-details">
            <summary>{{ __('perms.acces_details') }}</summary>
            <p class="rw-prose" data-rw="perms-sudo-nopasswd">{{ __('perms.acces_nopasswd_derive') }}</p>
            <p class="rw-prose" data-rw="perms-sudo-absents">{{ __('perms.acces_absents') }}</p>
        </details>
    </div>

    {{-- Les gestes qui RECHARGENT la page (ajout ou retrait d'une cle) y
         laissent leur message en session : il s'affiche ici, au meme endroit
         que celui des gestes sans rechargement. --}}
    <p class="rw-annonce @if (session('succes')) rw-annonce--ok @endif @if (session('erreur')) rw-annonce--echec @endif"
       data-rw="perms-annonce" role="status" aria-live="polite">@if (session('succes')){{ session('succes') }}@endif @if (session('erreur')){{ session('erreur') }}@endif</p>

    {{-- Le panneau de re-authentification, le MEME que D4. C'est lui qui rend la
         garde franchissable : le legacy l'exige et n'offre aucun moyen d'y
         repondre (E-119). --}}

    {{-- ═══ Permissions TEMPORAIRES — sous-lot D5b ═══════════════════════════
         `manage_permissions.php:184-267` porte cette moitié depuis toujours ;
         D5 a porté le fichier en la laissant dehors (E-134). Un octroi
         temporaire ouvre pourtant les pages comme un droit permanent — la
         lecture est portée depuis `v1.37.73`, l'écriture arrive ici.

         L'OCTROI PASSE PAR LA PASSERELLE, et c'est la seule raison qui vaille :
         `POST /admin/temp_permissions` NOTIFIE le compte concerné. Réécrire
         l'insertion ici priverait la personne de son avertissement.

         LA RÉVOCATION est un formulaire : elle n'a aucun effet de bord, et un
         formulaire n'a pas de plomberie à oublier. --}}
    <section class="rw-carte rw-carte--pleine" data-rw="perms-temporaires">
        <h2 class="rw-sous-titre-fort">{{ __('perms.temp_titre') }}</h2>
        <p class="rw-aide rw-prose">{{ __('perms.temp_desc') }}</p>

        <details data-rw="perms-temp-bloc">
            <summary class="rw-sous-titre-fort">{{ __('perms.temp_accorder') }}</summary>

            <div class="rw-grille">
                <label class="rw-champ">
                    <span class="rw-etiquette">{{ __('perms.temp_compte') }}</span>
                    <select class="rw-saisie rw-saisie--compacte" data-rw="temp-compte">
                        @foreach ($comptes as $c)
                            <option value="{{ $c['id'] }}">{{ $c['name'] }} — {{ __('perms.role_' . $c['role_id']) }}</option>
                        @endforeach
                    </select>
                </label>
                <label class="rw-champ">
                    <span class="rw-etiquette">{{ __('perms.temp_permission') }}</span>
                    <select class="rw-saisie rw-saisie--compacte" data-rw="temp-permission">
                        @foreach ($permissions as $p)
                            <option value="{{ $p }}">{{ __('perms.p_' . $p) }}</option>
                        @endforeach
                    </select>
                </label>
                <label class="rw-champ">
                    <span class="rw-etiquette">{{ __('perms.temp_duree') }}</span>
                    <select class="rw-saisie rw-saisie--compacte" data-rw="temp-duree">
                        @foreach ($dureesTemporaires as $h)
                            <option value="{{ $h }}">{{ __('perms.temp_heures', ['n' => $h]) }}</option>
                        @endforeach
                    </select>
                </label>
                <label class="rw-champ">
                    <span class="rw-etiquette">{{ __('perms.temp_raison') }}</span>
                    <input type="text" maxlength="255" class="rw-saisie rw-saisie--compacte"
                           data-rw="temp-raison" placeholder="{{ __('perms.temp_raison_indice') }}">
                    {{-- LA RAISON N'EST PAS OBLIGATOIRE CÔTÉ BACKEND, et on ne la
                         rend pas obligatoire ici non plus — mais on dit à quoi
                         elle sert, sinon personne ne la remplit. --}}
                    <span class="rw-aide">{{ __('perms.temp_raison_aide') }}</span>
                </label>
            </div>

            <div class="rw-actions">
                <span class="rw-actions__gauche rw-aide">{{ __('perms.temp_avertissement') }}</span>
                <button type="button" class="rw-bouton" data-rw="temp-accorder">{{ __('perms.temp_btn_accorder') }}</button>
            </div>
            <p class="rw-aide" data-rw="temp-etat" role="status" aria-live="polite"></p>
        </details>

        {{-- LES OCTROIS EXPIRÉS NE SONT PAS MONTRÉS : la table les garde jusqu'à
             ce que le planificateur les purge, et les afficher laisserait croire
             à des droits qui n'agissent plus. --}}
        @forelse ($temporaires as $t)
            <div class="rw-ligne-note" data-rw="temp-ligne" data-id="{{ $t['id'] }}">
                <strong>{{ $t['compte'] }}</strong>
                <span>{{ __('perms.p_' . $t['permission']) === 'perms.p_' . $t['permission'] ? $t['permission'] : __('perms.p_' . $t['permission']) }}</span>
                <span class="rw-badge rw-badge--attention">{{ __('perms.temp_jusqua', ['date' => $t['expires_at']]) }}</span>
                @if ($t['machine'])
                    {{-- `machine_id` est DÉCLARÉ et jamais filtré par la
                         vérification (E-134) : un octroi « limité » à une machine
                         vaut partout. On l'affiche donc comme une note, jamais
                         comme une portée. --}}
                    <span class="rw-aide">{{ __('perms.temp_machine_sans_effet', ['machine' => $t['machine']]) }}</span>
                @endif
                @if ($t['reason'])<span class="rw-aide">{{ $t['reason'] }}</span>@endif
                <span class="rw-aide">{{ __('perms.temp_par', ['qui' => $t['accorde_par'] ?? '—']) }}</span>
                <form method="POST" action="{{ route('permissions.temp.revoquer', ['id' => $t['id']]) }}"
                      class="rw-ligne-note__forme">
                    @csrf
                    <button type="submit" class="rw-bouton rw-bouton--minuscule rw-bouton--danger"
                            data-rw="temp-revoquer" data-id="{{ $t['id'] }}">{{ __('perms.temp_btn_revoquer') }}</button>
                </form>
            </div>
        @empty
            <p class="rw-aide" data-rw="temp-vide">{{ __('perms.temp_vide') }}</p>
        @endforelse
    </section>

    <div class="rw-panneau-decision" data-rw="perms-panneau-stepup" hidden>
        <p class="rw-panneau-decision__texte">{{ __('perms.step_up_titre') }}</p>
        <p class="rw-aide">{{ __('perms.step_up_aide') }}</p>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('perms.step_up_code') }}</span>
            <input type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code"
                   class="rw-saisie rw-saisie--code" data-rw="perms-stepup-code">
        </label>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="perms-stepup-annuler">{{ __('perms.annuler') }}</button>
            <button type="button" class="rw-bouton"
                    data-rw="perms-stepup-valider">{{ __('perms.step_up_valider') }}</button>
        </div>
    </div>

    @foreach ($comptes as $c)
        {{-- QUI A TOUS LES DROITS PAR SON ROLE N'A PAS DE CASES. Le rôle 3 passe
             toute garde de permission (`ExigePermission`, et `require_permission`
             côté backend) : ses cases ne décident de rien. Elles s'affichaient
             décochées, sous un résumé « 0 droit(s) », pour un compte qui peut
             tout — et les cocher était refusé (rang égal, ou soi-même). --}}
        @php($parRole = (int) $c['role_id'] >= 3)
        @php($droitsFiges = $parRole || $c['id'] === $moi || (int) $c['role_id'] >= $monRole)
        <section class="rw-carte rw-carte--pleine">
            <details data-rw="perms-carte-{{ $c['id'] }}" data-user-id="{{ $c['id'] }}">
                <summary class="rw-sous-titre-fort">
                    {{ $c['name'] }}
                    <span class="rw-badge rw-badge--neutre">{{ __('perms.role_' . $c['role_id']) }}</span>
                    @if ($c['id'] === $moi)<span class="rw-badge rw-badge--neutre">{{ __('perms.vous') }}</span>@endif
                    <span class="rw-tableau__discret" data-rw="perms-resume-{{ $c['id'] }}"><span data-rw="perms-resume-droits">{{ $parRole
                            ? __('perms.resume_droits_role')
                            : __('perms.resume_droits', ['n' => count(array_filter($droits[$c['id']])), 'total' => count($permissions)]) }}</span>
                        · <span data-rw="perms-resume-machines">{{ __('perms.resume_machines', ['n' => count($acces[$c['id']]), 'total' => count($machines)]) }}</span></span>
                </summary>

                <h3 class="rw-perms__titre">{{ __('perms.droits') }}</h3>
                @if ($droitsFiges)
                    <p class="rw-aide rw-prose" data-rw="perms-droits-figes-{{ $c['id'] }}">
                        {{ $parRole ? __('perms.droits_par_role') : __('perms.err_rang') }}
                    </p>
                @else
                    <div class="rw-perms__droits">
                        @foreach ($permissions as $perm)
                            <label class="rw-perms__droit">
                                <input type="checkbox"
                                       data-rw="perm-{{ $perm }}-{{ $c['id'] }}"
                                       data-user-id="{{ $c['id'] }}"
                                       data-permission="{{ $perm }}"
                                       @checked($droits[$c['id']][$perm])>
                                <span>{{ __('perms.p_' . $perm) === 'perms.p_' . $perm ? $perm : __('perms.p_' . $perm) }}</span>
                            </label>
                        @endforeach
                    </div>
                @endif

                <h3 class="rw-perms__titre">{{ __('perms.acces') }}</h3>
                {{-- UN SEUL CONTROLE POUR TOUT L'ETAT. Une case a cocher plus une
                     liste de prereglages autoriseraient une combinaison
                     impossible — coche sans prereglage, ou prereglage sans
                     acces. Ici « pas d'acces » est une valeur de la liste, et
                     il n'y a pas d'etat inexprimable.

                     Le prereglage AFFICHE est celui de la base. Une ligne
                     d'acces creee sans prereglage vaut `none`
                     (`NOT NULL DEFAULT 'none'`, migration 051) : l'ecran
                     disait « acces accorde » sans dire que le deploiement
                     RETIRERAIT le sudo. Il le dit desormais.

                     UNE LIGNE PAR MACHINE, le nom à gauche et la liste à droite,
                     au lieu d'une liste empilée sous son nom : la liste était
                     tronquée (« Accès + sudo complet, sans ») et la grille de 33
                     machines tenait sur deux écrans. `data-preset` porte l'état
                     confirmé — vide quand il n'y a pas d'accès — et la feuille de
                     style s'en sert pour griser les machines fermées et signaler
                     apt, équivalent root. --}}
                <ul class="rw-perms__acces">
                    @foreach ($machines as $m)
                        @php($aAcces = in_array((int) $m->id, $acces[$c['id']], true))
                        @php($actuel = $aAcces ? ($presets[$c['id']][(int) $m->id] ?? 'none') : '')
                        <li class="rw-perms__machine" data-preset="{{ $actuel }}">
                            <label class="rw-perms__nom" for="acces-{{ $m->id }}-{{ $c['id'] }}">{{ $m->name }}</label>
                            <select class="rw-saisie rw-saisie--compacte rw-perms__liste"
                                    id="acces-{{ $m->id }}-{{ $c['id'] }}"
                                    data-rw="acces-{{ $m->id }}-{{ $c['id'] }}"
                                    data-user-id="{{ $c['id'] }}"
                                    data-machine-id="{{ $m->id }}"
                                    data-actuel="{{ $actuel }}">
                                <option value="" @selected(! $aAcces)>{{ __('perms.acces_aucun') }}</option>
                                @foreach ($presetsProposes as $pr)
                                    <option value="{{ $pr }}" @selected($actuel === $pr)>{{ __('perms.preset_' . $pr) }}</option>
                                @endforeach
                            </select>
                            {{-- LES CLES DU COMPTE SUR CETTE MACHINE — la vue inverse du
                                 profil, qui les range par cle. Rendue pour les seules
                                 machines OUVERTES : une portee ne peut designer qu'une
                                 machine accessible. Une cle posee partout est cochee et
                                 figee : la restreindre changerait aussi son sens pour
                                 les machines a venir, ce choix se fait dans le profil. --}}
                            @if ($aAcces && $cles[$c['id']] !== [])
                                @php($ici = array_filter($cles[$c['id']], fn ($k) => $k['toutes_machines']
                                    || in_array((int) $m->id, array_column($k['machines'], 'id'), true)))
                                <details class="rw-perms__cles" data-rw="cles-{{ $m->id }}-{{ $c['id'] }}">
                                    <summary class="rw-aide">{{ __('perms.cles_resume', ['n' => count($ici), 'total' => count($cles[$c['id']])]) }}</summary>
                                    @foreach ($cles[$c['id']] as $i => $k)
                                        <label class="rw-perms__droit">
                                            <input type="checkbox"
                                                   data-rw="cle-{{ $k['id'] }}-{{ $m->id }}"
                                                   data-user-id="{{ $c['id'] }}"
                                                   data-cle-id="{{ $k['id'] }}"
                                                   data-cle-machine="{{ $m->id }}"
                                                   @checked(isset($ici[$i]))
                                                   @disabled($k['toutes_machines'])>
                                            <span>{{ $k['libelle'] }}
                                                <span class="rw-tableau__discret rw-tableau__mono">{{ $k['algo'] }} SHA256:{{ \Illuminate\Support\Str::limit($k['empreinte'], 12, '…') }}</span>
                                                @if ($k['toutes_machines'])<span class="rw-badge rw-badge--neutre">{{ __('perms.cles_partout') }}</span>@endif
                                            </span>
                                        </label>
                                    @endforeach
                                </details>
                            @endif
                        </li>
                    @endforeach
                </ul>

                {{-- LES CLES DU COMPTE : les lister, en retirer une, en ajouter une.
                     Le geste du legacy (`manage_users.php`, superadmin) que le
                     portage n'exposait sur aucun ecran. Memes refus que les
                     droits : ni soi-meme (le profil sert a ca), ni un rang egal
                     ou superieur — une cle posee ouvre une connexion SSH sous le
                     nom du compte. --}}
                @php($clesFigees = $c['id'] === $moi || (int) $c['role_id'] >= $monRole)
                @php($ouvertes = array_values(array_filter($machines, fn ($m) => in_array((int) $m->id, $acces[$c['id']], true))))
                <h3 class="rw-perms__titre">{{ __('perms.cles_titre') }}</h3>
                @if ($cles[$c['id']] === [])
                    <p class="rw-aide" data-rw="perms-cles-vide-{{ $c['id'] }}">{{ __('perms.cles_aucune') }}</p>
                @else
                    <div class="rw-tableau-cadre">
                        <table class="rw-tableau" data-rw="perms-cles-{{ $c['id'] }}">
                            <thead>
                                <tr>
                                    <th>{{ __('profil.cles_th_nom') }}</th>
                                    <th>{{ __('profil.cles_th_empreinte') }}</th>
                                    <th>{{ __('profil.cles_th_portee') }}</th>
                                    @unless ($clesFigees)<th></th>@endunless
                                </tr>
                            </thead>
                            <tbody>
                                @foreach ($cles[$c['id']] as $k)
                                    <tr>
                                        <td>{{ $k['libelle'] }}</td>
                                        <td class="rw-tableau__mono">{{ $k['algo'] }} SHA256:{{ $k['empreinte'] }}</td>
                                        <td>{{ $k['toutes_machines'] ? __('perms.cle_portee_toutes') : implode(', ', array_column($k['machines'], 'name')) }}</td>
                                        @unless ($clesFigees)
                                            <td>
                                                <button type="button" class="rw-bouton rw-bouton--minuscule rw-bouton--danger"
                                                        data-rw="cle-retirer" data-user-id="{{ $c['id'] }}"
                                                        data-cle-id="{{ $k['id'] }}">{{ __('perms.cle_btn_retirer') }}</button>
                                            </td>
                                        @endunless
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>
                @endif

                @if ($clesFigees)
                    <p class="rw-aide rw-prose" data-rw="perms-cles-figees-{{ $c['id'] }}">
                        {{ $c['id'] === $moi ? __('perms.cles_figees_soi') : __('perms.err_rang') }}
                    </p>
                @else
                    <details class="rw-perms__ajout-cle" data-rw="cle-ajout-{{ $c['id'] }}">
                        <summary class="rw-sous-titre-fort">{{ __('perms.cle_ajout_titre') }}</summary>
                        <label class="rw-champ">
                            <span>{{ __('perms.cle_libelle') }}</span>
                            <input class="rw-saisie" type="text" maxlength="100" data-champ="libelle"
                                   placeholder="{{ __('profil.cles_nom_exemple') }}">
                        </label>
                        <label class="rw-champ">
                            <span>{{ __('perms.cle_cle') }}</span>
                            <textarea class="rw-saisie" rows="3" data-champ="cle_ssh"></textarea>
                        </label>
                        <div class="rw-champ rw-champ--espace">
                            <span class="rw-champ__etiquette">{{ __('profil.cles_th_portee') }}</span>
                            <label class="rw-champ--case">
                                <input type="radio" name="portee-{{ $c['id'] }}" value="toutes" data-champ="portee" checked>
                                <span>{{ __('perms.cle_portee_toutes') }}</span>
                            </label>
                            <label class="rw-champ--case">
                                <input type="radio" name="portee-{{ $c['id'] }}" value="machines" data-champ="portee">
                                <span>{{ __('perms.cle_portee_machines') }}</span>
                            </label>
                            @if ($ouvertes === [])
                                <p class="rw-aide">{{ __('perms.cle_sans_machine') }}</p>
                            @else
                                <ul class="rw-liste-selection">
                                    @foreach ($ouvertes as $m)
                                        <li class="rw-liste-selection__ligne">
                                            <label class="rw-liste-selection__etiquette">
                                                <input type="checkbox" class="rw-case" value="{{ $m->id }}" data-champ="machines">
                                                <span class="rw-liste-selection__nom">{{ $m->name }}</span>
                                            </label>
                                        </li>
                                    @endforeach
                                </ul>
                            @endif
                        </div>
                        <div class="rw-actions">
                            <span class="rw-actions__gauche rw-aide">{{ __('perms.cle_avertissement') }}</span>
                            <button type="button" class="rw-bouton" data-rw="cle-ajouter"
                                    data-user-id="{{ $c['id'] }}">{{ __('perms.cle_btn_ajouter') }}</button>
                        </div>
                    </details>
                @endif
            </details>
        </section>
    @endforeach

    @php($libelles = [
        'err_reseau' => __('perms.err_reseau'),
        // Le résumé se recompte après chaque geste : un résumé figé au
        // chargement contredirait la grille juste en dessous.
        'resume_droits' => __('perms.resume_droits'),
        'resume_machines' => __('perms.resume_machines'),
        'cles_resume' => __('perms.cles_resume'),
        // Sous-lot D5b : l'octroi passe par la passerelle, donc par le JS.
        'temp_en_cours' => __('perms.temp_en_cours'),
        'temp_accorde' => __('perms.temp_accorde'),
        'temp_echec' => __('perms.temp_echec'),
    ])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="perms-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/permissions.js?v={{ @filemtime(public_path('js/permissions.js')) ?: '0' }}"></script>
@endsection
