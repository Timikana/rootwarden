@extends('layouts.portail', ['titre' => __('perms.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('perms.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('perms.desc') }}</p>

    @include('composants.onglets-adm', ['courant' => 'permissions'])

    {{-- UNE SEULE LISTE, ET ELLE VIENT DU SCHEMA. Le legacy en porte trois — 18
         colonnes, 14 posables a la creation, 16 basculables — et les ecarts se
         croisent : une permission s'accorde sans se reprendre, une autre
         n'existe ni a la creation ni a la bascule (PARITE E-118). --}}
    <div class="rw-encart" data-rw="perms-source">
        <p class="rw-prose">{{ __('perms.source', ['nombre' => count($permissions)]) }}</p>
    </div>

    {{-- CES TROIS NOTES SONT RENDUES UNE FOIS, PAS PAR COMPTE. La section
         « acces » vit dans la boucle des comptes ; y placer ces avertissements
         les repeterait autant de fois qu'il y a de comptes — c'est le defaut
         des « 31 fois ancien portail » vu a l'image sur le menu. --}}
    <div class="rw-encart" data-rw="perms-sudo-notes">
        <p class="rw-prose rw-aide">{{ __('perms.acces_aide') }}</p>
        <p class="rw-prose rw-alerte rw-alerte--attention" data-rw="perms-sudo-apt">
            {{ __('perms.acces_apt_avert') }}
        </p>
        <p class="rw-prose rw-aide" data-rw="perms-sudo-absents">{{ __('perms.acces_absents') }}</p>
        <p class="rw-prose rw-aide" data-rw="perms-sudo-nopasswd">{{ __('perms.acces_nopasswd_derive') }}</p>
    </div>

    <p class="rw-annonce" data-rw="perms-annonce" role="status" aria-live="polite"></p>

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
                <code class="rw-code">{{ $t['permission'] }}</code>
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
        <section class="rw-carte rw-carte--pleine">
            <details data-rw="perms-carte-{{ $c['id'] }}">
                <summary class="rw-sous-titre-fort">
                    {{ $c['name'] }}
                    <span class="rw-badge rw-badge--neutre">{{ __('perms.role_' . $c['role_id']) }}</span>
                    <span class="rw-tableau__discret">{{ __('perms.compte_resume', [
                        'droits' => count(array_filter($droits[$c['id']])),
                        'machines' => count($acces[$c['id']]),
                    ]) }}</span>
                </summary>

                <p class="rw-sous-titre-fort">{{ __('perms.droits') }}</p>
                <div class="rw-grille rw-grille--compacte">
                    @foreach ($permissions as $perm)
                        <label class="rw-liste-selection__etiquette">
                            <input type="checkbox"
                                   data-rw="perm-{{ $perm }}-{{ $c['id'] }}"
                                   data-user-id="{{ $c['id'] }}"
                                   data-permission="{{ $perm }}"
                                   @checked($droits[$c['id']][$perm])>
                            <span class="rw-liste-selection__nom">
                                {{ __('perms.p_' . $perm) === 'perms.p_' . $perm ? $perm : __('perms.p_' . $perm) }}
                            </span>
                        </label>
                    @endforeach
                </div>

                <p class="rw-sous-titre-fort">{{ __('perms.acces') }}</p>
                <div class="rw-grille rw-grille--compacte">
                    {{-- UN SEUL CONTROLE POUR TOUT L'ETAT. Une case a cocher plus une
                         liste de prereglages autoriseraient une combinaison
                         impossible — coche sans prereglage, ou prereglage sans
                         acces. Ici « pas d'acces » est une valeur de la liste, et
                         il n'y a pas d'etat inexprimable.

                         Le prereglage AFFICHE est celui de la base. Une ligne
                         d'acces creee sans prereglage vaut `none`
                         (`NOT NULL DEFAULT 'none'`, migration 051) : l'ecran
                         disait « acces accorde » sans dire que le deploiement
                         RETIRERAIT le sudo. Il le dit desormais. --}}
                    @foreach ($machines as $m)
                        @php($aAcces = in_array((int) $m->id, $acces[$c['id']], true))
                        <label class="rw-liste-selection__etiquette">
                            <span class="rw-liste-selection__nom">{{ $m->name }}</span>
                            <select class="rw-saisie rw-saisie--compacte"
                                    data-rw="acces-{{ $m->id }}-{{ $c['id'] }}"
                                    data-user-id="{{ $c['id'] }}"
                                    data-machine-id="{{ $m->id }}"
                                    data-actuel="{{ $aAcces ? ($presets[$c['id']][(int) $m->id] ?? 'none') : '' }}"
                                    aria-label="{{ $m->name }}">
                                <option value="" @selected(! $aAcces)>{{ __('perms.acces_aucun') }}</option>
                                @foreach ($presetsProposes as $pr)
                                    <option value="{{ $pr }}"
                                            @selected($aAcces && ($presets[$c['id']][(int) $m->id] ?? 'none') === $pr)>{{ __('perms.preset_' . $pr) }}</option>
                                @endforeach
                            </select>
                        </label>
                    @endforeach
                </div>
            </details>
        </section>
    @endforeach

    @php($libelles = [
        'err_reseau' => __('perms.err_reseau'),
        // Sous-lot D5b : l'octroi passe par la passerelle, donc par le JS.
        'temp_en_cours' => __('perms.temp_en_cours'),
        'temp_accorde' => __('perms.temp_accorde'),
        'temp_echec' => __('perms.temp_echec'),
    ])
    {{-- @json sur UNE SEULE ligne : multiligne, il casse le PHP compile. --}}
    <script id="perms-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/permissions.js?v={{ @filemtime(public_path('js/permissions.js')) ?: '0' }}"></script>
@endsection
