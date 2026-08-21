@extends('layouts.portail', ['titre' => __('ssh.titre')])

@section('corps')
    <section class="rw-section">
        <div class="rw-entete-page">
            <div>
                <h2 class="rw-titre">{{ __('ssh.titre') }}</h2>
                {{-- LE COMPTEUR EST SUBSTITUE. Le legacy ecrit `count($machines)`
                     PUIS `t('ssh.servers_available')`, dont la valeur est
                     « :count serveur(s) disponible(s) » : le jeton n'est jamais
                     remplace et l'ecran porte « 3 :count serveur(s)
                     disponible(s) ». Aucun controle d'i18n ne le voyait — ils
                     cherchent des identifiants `module.cle`, pas des jetons. --}}
                <p class="rw-aide">{{ __('ssh.serveurs_disponibles', ['nombre' => count($machines)]) }}</p>
                <p class="rw-aide rw-prose">{{ __('ssh.description') }}</p>
            </div>
        </div>

        <article class="rw-carte rw-carte--pleine">
            @if (count($machines) === 0)
                <div class="rw-vide">
                    <p class="rw-vide__titre">{{ __('ssh.aucun_serveur') }}</p>
                    <p class="rw-vide__texte rw-prose">{{ __('ssh.aucun_serveur_aide') }}</p>
                </div>
            @else
                {{-- LES FILTRES. Leur vocabulaire est DERIVE des machines visibles,
                     tags compris : le legacy cloisonne la liste des machines mais
                     interroge `machine_tags` sans filtre, deux lignes plus haut
                     qu'un `$allEnvs` qui, lui, derive de la liste deja filtree. --}}
                <div class="rw-barre-filtres" data-rw="ssh-filtres">
                    @if (count($tags) > 0)
                        <label class="rw-etiquette-champ">
                            <span class="rw-etiquette">{{ __('ssh.filtre_tag') }}</span>
                            <select class="rw-saisie rw-saisie--compacte" id="filter-tag">
                                <option value="">{{ __('ssh.tous_tags') }}</option>
                                @foreach ($tags as $tag)
                                    <option value="{{ $tag }}">{{ $tag }}</option>
                                @endforeach
                            </select>
                        </label>
                    @endif
                    @if (count($environnements) > 0)
                        <label class="rw-etiquette-champ">
                            <span class="rw-etiquette">{{ __('ssh.filtre_env') }}</span>
                            <select class="rw-saisie rw-saisie--compacte" id="filter-env">
                                <option value="">{{ __('ssh.tous_envs') }}</option>
                                @foreach ($environnements as $env)
                                    <option value="{{ $env }}">{{ $env }}</option>
                                @endforeach
                            </select>
                        </label>
                    @endif
                    <button type="button" class="rw-bouton rw-bouton--discret"
                            data-rw="ssh-cocher-filtre">{{ __('ssh.cocher_filtre') }}</button>
                    <button type="button" class="rw-bouton rw-bouton--discret"
                            data-rw="ssh-cocher-tout">{{ __('ssh.cocher_tout') }}</button>
                    <button type="button" class="rw-bouton rw-bouton--discret"
                            data-rw="ssh-decocher-tout">{{ __('ssh.decocher_tout') }}</button>
                </div>

                <form id="deploy-form" onsubmit="return false">
                    <ul class="rw-liste-selection">
                        @foreach ($machines as $m)
                            @php($mesTags = $tagsParMachine[(int) $m->id] ?? [])
                            <li class="machine-item rw-liste-selection__ligne"
                                data-rw="machine-{{ $m->id }}"
                                data-tags="{{ implode(',', $mesTags) }}"
                                data-env="{{ $m->environment }}">
                                <label class="rw-liste-selection__etiquette">
                                    <input type="checkbox" name="selected_machines[]"
                                           value="{{ $m->id }}" class="rw-case">
                                    <span class="rw-liste-selection__corps">
                                        <span class="rw-liste-selection__nom">
                                            {{-- Le nom dans son propre element : le
                                                 script le relit pour nommer les
                                                 cibles dans la decision, et il ne
                                                 doit pas y ramasser la pastille
                                                 d'environnement au passage. --}}
                                            <span data-rw="ssh-nom">{{ $m->name }}</span>
                                            @if ($m->environment)
                                                <span class="rw-pastille rw-pastille--neutre">{{ $m->environment }}</span>
                                            @endif
                                        </span>
                                        <span class="rw-liste-selection__detail">
                                            {{ $m->ip }}:{{ $m->port }}
                                            @foreach ($mesTags as $tag)
                                                <span class="rw-badge">{{ $tag }}</span>
                                            @endforeach
                                        </span>
                                    </span>
                                </label>
                            </li>
                        @endforeach
                    </ul>
                </form>

                <div class="rw-actions">
                    <p class="rw-aide rw-actions__gauche" id="ssh-compte-selection"
                       aria-live="polite">{{ __('ssh.aucune_selection') }}</p>
                    {{-- LE BOUTON NAIT DESACTIVE, et il ouvre une DECISION.
                         Le legacy fait `onclick="deploySSH()"` : trois routes en
                         cascade, sans reprise de main et sans confirmation
                         d'aucune sorte. Ce que cela engage, sur CHAQUE machine
                         cochee et en root : `apt-get install sudo`, `useradd`,
                         l'ECRASEMENT d'`authorized_keys`, l'installation d'une
                         politique sudoers — et la REVOCATION des cles de tout
                         compte ayant perdu son habilitation. `srv-zabbix` est en
                         PRODUCTION et figure dans la liste. --}}
                    <button type="button" class="rw-bouton rw-bouton--danger"
                            id="deploy-btn" data-rw="ssh-deployer"
                            disabled>{{ __('ssh.deployer') }}</button>
                </div>

                <div class="rw-panneau-decision" id="deploy-panneau" hidden>
                    <div class="rw-panneau-decision__texte">
                        <strong>{{ __('ssh.confirmer_titre') }}</strong>
                        <p class="rw-aide" id="deploy-cibles"></p>
                        <p class="rw-aide">{{ __('ssh.confirmer_avertissement') }}</p>
                        {{-- K4 N'EST PAS PORTE : le declenchement reste sur l'ancien
                             portail, et la page le DIT plutot que d'offrir un bouton
                             qui ne fait rien. --}}
                        <p class="rw-aide">{{ __('ssh.non_porte') }}</p>
                    </div>
                    {{-- Action principale a DROITE, secondaire a gauche. Un panneau
                         dont la seule action serait « Annuler » ne serait pas une
                         decision : il faut pouvoir aller au bout du geste, et ici
                         cela veut dire l'ancien portail — dit comme tel, avec le
                         marqueur des entrees non portees et une nouvelle fenetre. --}}
                    <div class="rw-panneau-decision__actions">
                        <button type="button" class="rw-bouton rw-bouton--discret"
                                data-rw="ssh-annuler">{{ __('ssh.annuler') }}</button>
                        <a class="rw-bouton" data-rw="ssh-vers-legacy"
                           href="{{ config('app.url_legacy') }}/ssh/"
                           target="_blank" rel="noopener"
                           title="{{ __('ssh.non_porte') }}">{{ __('ssh.non_porte_lien') }} ↗</a>
                    </div>
                </div>
            @endif
        </article>
    </section>

    <script id="ssh-libelles" type="application/json">@json($libelles)</script>
    <script src="{{ asset('js/cles-ssh.js') }}" defer></script>
@endsection
