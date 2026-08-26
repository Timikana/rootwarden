@extends('layouts.portail', ['titre' => __('politiques.titre')])

@section('corps')
@php
    $portee = \App\Services\Politiques::PORTEE;
    $machineCourante = collect($machines)->firstWhere('id', $machine);
    $compteCourant = collect($comptes)->firstWhere('id', $compte);
@endphp

<div class="rw-entete-page">
    <h1 class="rw-titre">{{ __('politiques.titre') }}</h1>
</div>

<div class="rw-encart">
    <p class="rw-sous-titre-fort">{{ __('politiques.intro_titre') }}</p>
    <p class="rw-prose">{{ __('politiques.intro') }}</p>
</div>

<div class="rw-section">
    <form method="get" action="{{ route('politiques') }}" class="rw-barre-filtres" data-rw="politique-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('politiques.machine') }}</span>
            <select name="machine" class="rw-saisie rw-saisie--compacte"
                    data-rw="politique-machine" onchange="this.form.submit()">
                @foreach ($machines as $m)
                    <option value="{{ $m->id }}" @selected($m->id === $machine)>
                        {{ $m->name }} ({{ $m->ip }})
                    </option>
                @endforeach
            </select>
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('politiques.compte') }}</span>
            <select name="compte" class="rw-saisie rw-saisie--compacte"
                    data-rw="politique-compte" onchange="this.form.submit()"
                    @disabled(count($comptes) === 0)>
                @forelse ($comptes as $c)
                    <option value="{{ $c->id }}" @selected($c->id === $compte)>{{ $c->username }}</option>
                @empty
                    <option value="">{{ __('politiques.aucun_compte') }}</option>
                @endforelse
            </select>
        </label>
    </form>
</div>

@if (count($comptes) === 0)
    {{-- Un etat vide dit ce qui manque ET par ou le combler. --}}
    <div class="rw-vide" data-rw="politique-vide">
        <p class="rw-vide__titre">{{ __('politiques.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('politiques.vide_texte') }}</p>
        <a class="rw-bouton rw-vide__action"
           href="{{ route('comptes-distants', ['machine' => $machine]) }}">{{ __('politiques.vide_action') }}</a>
    </div>
@else
<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('politiques.choix') }}</h2>

    <form id="politique-form" data-rw="politique-form"
          data-machine="{{ $machine }}" data-compte="{{ $compte }}"
          data-nom-machine="{{ $machineCourante->name ?? '' }}"
          data-nom-compte="{{ $compteCourant->username ?? '' }}">
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('politiques.prereglage') }}</span>
            <select name="preset" class="rw-saisie" data-rw="politique-prereglage">
                @foreach (\App\Services\Politiques::PREREGLAGES as $p)
                    <option value="{{ $p }}" @selected($prereglage === $p)
                            data-portee="{{ $portee[$p] }}">
                        {{ __('politiques.preset_' . $p) }}@if ($portee[$p] === 'root') — {{ __('politiques.portee_root') }}@endif
                    </option>
                @endforeach
            </select>
        </label>

        {{--
            L'AIDE ET SON MARQUEUR DE PORTEE.

            Le legacy affichait ici « Il ne peut pas toucher au reste du systeme »
            sous un prereglage que son propre module documente comme EQUIVALENT
            ROOT — et c'etait le prereglage par defaut. Voir `Politiques::PORTEE`.
        --}}
        <div class="rw-avertissement" data-rw="politique-portee" hidden></div>
        <p class="rw-aide" data-rw="politique-aide"></p>

        <div class="rw-champ" data-rw="politique-bloc-regles" hidden>
            <label class="rw-champ__etiquette" for="politique-regles">{{ __('politiques.regles_libres') }}</label>
            <textarea id="politique-regles" name="custom_rules" rows="5" class="rw-saisie"
                      data-rw="politique-regles"
                      placeholder="ALL=(root) NOPASSWD: /usr/bin/docker ps">{{ $politique->custom_rules ?? '' }}</textarea>
            <p class="rw-aide">{{ __('politiques.regles_aide') }}</p>
        </div>

        <div class="rw-champ" data-rw="politique-bloc-services" hidden>
            <label class="rw-champ__etiquette" for="politique-services">{{ __('politiques.services') }}</label>
            <input type="text" id="politique-services" name="services" class="rw-saisie"
                   data-rw="politique-services" placeholder="nginx, php8.2-fpm, redis-server">
            <p class="rw-aide">{{ __('politiques.services_aide') }}</p>
        </div>

        {{--
            L'AIDE VIT DANS LA CASE, pas sous le champ suivant.

            Premiere redaction : les deux champs dans un `.rw-inline` — qui vaut
            `display: inline` et sert a du TEXTE, pas a une rangee de champs. Ils
            s'empilaient donc, et l'aide de la case atterrissait sous « Executer
            en tant que », ou elle se lisait comme l'aide de CE champ-la. Vu a
            l'image, invisible a toute assertion DOM.

            `.rw-champ--case > span` est deja une colonne prevue pour porter un
            libelle ET son aide : c'est la structure a employer.
        --}}
        <label class="rw-champ rw-champ--case">
            <input type="checkbox" name="nopasswd" class="rw-case" data-rw="politique-nopasswd"
                   @checked((bool) ($politique->nopasswd ?? false))>
            <span>
                <span>{{ __('politiques.nopasswd') }}</span>
                <span class="rw-aide">{{ __('politiques.nopasswd_aide') }}</span>
            </span>
        </label>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('politiques.runas') }}</span>
            <input type="text" name="runas" class="rw-saisie rw-saisie--compacte"
                   data-rw="politique-runas" value="{{ $politique->runas ?? 'root' }}">
        </label>

        {{--
            L'action principale est a DROITE, et les deux gestes qui ECRIVENT
            portent des points de suspension : ils ouvrent une confirmation, ils
            n'agissent pas. Le legacy deployait au premier clic et ne demandait
            confirmation que pour RETIRER — la garde etait sur le geste
            restauratif, pas sur celui qui accorde.
        --}}
        <div class="rw-actions">
            <div class="rw-actions__gauche">
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="politique-auditer"
                        title="{{ __('politiques.aide_auditer') }}">{{ __('politiques.auditer') }}</button>
                <button type="button" class="rw-bouton rw-bouton--danger"
                        data-rw="politique-retirer"
                        title="{{ __('politiques.aide_retirer') }}">{{ __('politiques.retirer') }}</button>
            </div>
            <button type="button" class="rw-bouton"
                    data-rw="politique-deployer"
                    title="{{ __('politiques.aide_deployer') }}">{{ __('politiques.deployer') }}</button>
        </div>
    </form>

    {{-- LA CONFIRMATION QUI MANQUAIT. Elle nomme la machine, le compte et la portee. --}}
    <div class="rw-panneau-decision" data-rw="politique-panneau" hidden>
        <p class="rw-panneau-decision__texte">
            <strong data-rw="politique-panneau-titre"></strong>
            <span class="rw-aide" data-rw="politique-panneau-texte"></span>
        </p>
        <p class="rw-prose" data-rw="politique-panneau-detail"></p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="politique-annuler">{{ __('politiques.confirmer_annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="politique-confirmer"></button>
        </div>
    </div>

    @if ($politique)
        <p class="rw-aide" data-rw="politique-derniere">
            {{ __('politiques.derniere') }} :
            {{ $politique->last_deployed_at ?? __('politiques.jamais') }}
        </p>
    @endif

    <div class="rw-resultat" data-rw="politique-resultat" hidden>
        <p class="rw-resultat__titre">{{ __('politiques.resultat') }}</p>
        <pre class="rw-code rw-code--fichier" data-rw="politique-sortie"></pre>
    </div>
</div>

<details class="rw-repliable">
    <summary>{{ __('politiques.historique') }}</summary>
    @if (count($historique) === 0)
        <p class="rw-vide__texte">{{ __('politiques.hist_vide') }}</p>
    @else
        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th>{{ __('politiques.hist_date') }}</th>
                        <th>{{ __('politiques.hist_auteur') }}</th>
                        <th>{{ __('politiques.hist_etat') }}</th>
                        <th>{{ __('politiques.hist_regle') }}</th>
                        <th><span class="rw-visuellement-cache">{{ __('politiques.rollback_titre') }}</span></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($historique as $h)
                        <tr>
                            <td>{{ $h->deployed_at }}</td>
                            <td>{{ $h->auteur ?? '—' }}</td>
                            <td>
                                <span class="rw-pastille rw-pastille--{{ $h->status === 'applied' ? 'ok' : ($h->status === 'failed' ? 'echec' : 'neutre') }}">
                                    {{ __('politiques.etat_' . $h->status) }}
                                </span>
                            </td>
                            {{--
                                LA REGLE REELLEMENT ECRITE, pas une description
                                de ce qu'elle etait censee etre. C'est la seule
                                source de verite du depot sur ce qui a ete
                                accorde, et elle vient du backend.
                            --}}
                            <td><code class="rw-code">{{ $h->new_file_content }}</code></td>
                            {{--
                                UNE CAPACITE NON PORTEE N'EST PAS UN BOUTON
                                INERTE. L'annulation reecrit un sudoers sur la
                                machine ; elle n'est pas portee, et le dire vaut
                                mieux que d'offrir un bouton qui ne fait rien.
                                Marqueur `↗` et nouvel onglet : un lien qui
                                change de portail sans le dire trahit celui qui
                                le suit.
                            --}}
                            <td class="rw-tableau__actions">
                                @if (in_array($h->status, ['applied', 'superseded'], true))
                                    <a class="rw-lien" data-rw="politique-rollback-legacy"
                                       href="{{ rtrim(config('app.url_legacy'), '/') }}/adm/server_user_sudo.php?server={{ $machine }}&user={{ $compte }}"
                                       target="_blank" rel="noopener"
                                       title="{{ __('politiques.rollback_texte') }}">{{ __('politiques.rollback_lien') }} ↗</a>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endif
</details>
@endif

    <script id="politiques-libelles" type="application/json">@json($libelles)</script>
    <script src="/js/politiques.js?v={{ @filemtime(public_path('js/politiques.js')) ?: '0' }}"></script>
@endsection
