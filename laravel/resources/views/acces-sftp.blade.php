@extends('layouts.portail', ['titre' => __('sftp.titre')])

@section('corps')
@php
    use App\Services\AccesSftp;
    $effets = AccesSftp::REGLAGES;
    $machineCourante = collect($machines)->firstWhere('id', $machine);
    $compteCourant = collect($comptes)->firstWhere('id', $compte);
    // Le libelle et l'aide de chaque reglage, dans l'ordre d'affichage. La cle
    // i18n est courte (`f_tcp`) la ou la colonne l'est moins : la table dit
    // laquelle va avec laquelle, une seule fois.
    $champs = [
        'sftp_only'              => 'sftp_only',
        'allow_password_auth'    => 'password',
        'allow_tcp_forwarding'   => 'tcp',
        'allow_agent_forwarding' => 'agent',
        'x11_forwarding'         => 'x11',
    ];
@endphp

<h1 class="rw-titre">{{ __('sftp.titre') }}</h1>

<div class="rw-encart">
    <p class="rw-sous-titre-fort">{{ __('sftp.intro_titre') }}</p>
    <p class="rw-prose">{{ __('sftp.intro') }}</p>
</div>

<div class="rw-section">
    <form method="get" action="{{ route('acces-sftp') }}" class="rw-barre-filtres" data-rw="sftp-filtres">
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('sftp.machine') }}</span>
            <select name="machine" class="rw-saisie rw-saisie--compacte"
                    data-rw="sftp-machine" onchange="this.form.submit()">
                @foreach ($machines as $m)
                    <option value="{{ $m->id }}" @selected($m->id === $machine)>
                        {{ $m->name }} ({{ $m->ip }})
                    </option>
                @endforeach
            </select>
        </label>
        <label class="rw-filtre">
            <span class="rw-filtre__etiquette">{{ __('sftp.compte') }}</span>
            <select name="compte" class="rw-saisie rw-saisie--compacte"
                    data-rw="sftp-compte" onchange="this.form.submit()"
                    @disabled(count($comptes) === 0)>
                @forelse ($comptes as $c)
                    <option value="{{ $c->id }}" @selected($c->id === $compte)>{{ $c->username }}</option>
                @empty
                    <option value="">{{ __('sftp.aucun_compte') }}</option>
                @endforelse
            </select>
        </label>
    </form>
</div>

@if (count($comptes) === 0)
    <div class="rw-vide" data-rw="sftp-vide">
        <p class="rw-vide__titre">{{ __('sftp.vide_titre') }}</p>
        <p class="rw-vide__texte">{{ __('sftp.vide_texte') }}</p>
        <a class="rw-bouton rw-vide__action"
           href="{{ route('comptes-distants', ['machine' => $machine]) }}">{{ __('sftp.vide_action') }}</a>
    </div>
@else
<div class="rw-section">
    <h2 class="rw-section__entete">{{ __('sftp.options') }}</h2>

    @if ($neuve)
        {{--
            L'ETAT DE DEPART S'ENONCE, ET SA RAISON AVEC.

            Le legacy livrait trois cases cochees dont ses propres aides
            recommandaient de les decocher. Le portage part de la position
            fermee — et le dit, parce qu'un etat initial qu'on ne s'explique
            pas se change au hasard.
        --}}
        <div class="rw-encart" data-rw="sftp-neuve">
            <p class="rw-sous-titre-fort">{{ __('sftp.neuve_titre') }}</p>
            <p class="rw-prose">{{ __('sftp.neuve_texte') }}</p>
        </div>
    @endif

    <form data-rw="sftp-form"
          data-machine="{{ $machine }}" data-compte="{{ $compte }}"
          data-nom-machine="{{ $machineCourante->name ?? '' }}"
          data-nom-compte="{{ $compteCourant->username ?? '' }}">

        @foreach ($champs as $colonne => $cle)
            {{--
                LA CASE ET SON AIDE DANS LE MEME BLOC, l'aide DANS l'etiquette.

                Ce n'est pas qu'une question de mise en page : la suite remonte
                de chaque case a son bloc pour lire l'aide qui l'accompagne, et
                refuse qu'une aide recommandant de fermer accompagne une case
                ouverte. Une aide posee ailleurs dans le document ne serait
                appariee a rien.
            --}}
            <div class="rw-champ" data-rw="sftp-bloc-{{ $cle }}">
                <label class="rw-champ rw-champ--case">
                    <input type="checkbox" name="{{ $colonne }}" class="rw-case"
                           data-rw="sftp-{{ $cle }}" data-effet="{{ $effets[$colonne] }}"
                           @checked($etat[$colonne])>
                    <span>
                        {{--
                            LE BADGE SUR LA MEME LIGNE QUE LE TITRE.

                            Pose apres l'etiquette, il tombait SOUS l'aide —
                            `.rw-champ` n'est qu'une marge — et se lisait comme
                            s'il qualifiait le reglage SUIVANT. Vu a l'image,
                            invisible a toute assertion DOM. Meme travers que le
                            `.rw-inline` de D9a.
                        --}}
                        <span><span data-rw="sftp-titre-{{ $cle }}">{{ __('sftp.f_' . $cle) }}</span>
                            @if ($effets[$colonne] === 'ouvre')
                                <span class="rw-badge rw-badge--attention"
                                      data-rw="sftp-effet-{{ $cle }}">{{ __('sftp.ouvre') }}</span>
                            @endif
                        </span>
                        <span class="rw-aide">{{ __('sftp.h_' . $cle) }}</span>
                    </span>
                </label>
            </div>
        @endforeach

        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('sftp.f_chroot') }}</span>
            <input type="text" name="chroot_dir" class="rw-saisie" data-rw="sftp-chroot"
                   placeholder="/srv/sftp/jean" value="{{ $politique->chroot_dir ?? '' }}">
            <span class="rw-aide">{{ __('sftp.h_chroot') }}</span>
        </label>

        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('sftp.f_working') }}</span>
            <input type="text" name="working_dir" class="rw-saisie" data-rw="sftp-working"
                   placeholder="/upload" value="{{ $politique->working_dir ?? '' }}">
            <span class="rw-aide">{{ __('sftp.h_working') }}</span>
        </label>

        {{--
            Action principale a DROITE, et les deux gestes qui ECRIVENT portent
            des points de suspension : ils ouvrent une confirmation, ils n'agissent
            pas. Le legacy deployait au premier clic.
        --}}
        <div class="rw-actions">
            <div class="rw-actions__gauche">
                <button type="button" class="rw-bouton rw-bouton--discret"
                        data-rw="sftp-auditer"
                        title="{{ __('sftp.aide_auditer') }}">{{ __('sftp.auditer') }}</button>
                <button type="button" class="rw-bouton rw-bouton--danger"
                        data-rw="sftp-retirer"
                        title="{{ __('sftp.aide_retirer') }}">{{ __('sftp.retirer') }}</button>
            </div>
            <button type="button" class="rw-bouton"
                    data-rw="sftp-deployer"
                    title="{{ __('sftp.aide_deployer') }}">{{ __('sftp.deployer') }}</button>
        </div>
    </form>

    <div class="rw-panneau-decision" data-rw="sftp-panneau" hidden>
        <p class="rw-panneau-decision__texte">
            <strong data-rw="sftp-panneau-titre"></strong>
            <span class="rw-aide" data-rw="sftp-panneau-texte"></span>
        </p>
        <p class="rw-prose" data-rw="sftp-panneau-detail"></p>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="sftp-annuler">{{ __('sftp.confirmer_annuler') }}</button>
            <button type="button" class="rw-bouton rw-bouton--danger"
                    data-rw="sftp-confirmer"></button>
        </div>
    </div>

    @if ($politique)
        <p class="rw-aide" data-rw="sftp-derniere">
            {{ __('sftp.derniere') }} : {{ $politique->last_deployed_at ?? __('sftp.jamais') }}
        </p>
    @endif

    <div class="rw-resultat" data-rw="sftp-resultat" hidden>
        <p class="rw-resultat__titre">{{ __('sftp.resultat') }}</p>
        <pre class="rw-code rw-code--fichier" data-rw="sftp-sortie"></pre>
    </div>
</div>

<details class="rw-repliable">
    <summary>{{ __('sftp.historique') }}</summary>
    @if (count($historique) === 0)
        <p class="rw-vide__texte">{{ __('sftp.hist_vide') }}</p>
    @else
        <div class="rw-tableau-cadre">
            <table class="rw-tableau">
                <thead>
                    <tr>
                        <th>{{ __('sftp.hist_date') }}</th>
                        <th>{{ __('sftp.hist_auteur') }}</th>
                        <th>{{ __('sftp.hist_etat') }}</th>
                        <th>{{ __('sftp.hist_bloc') }}</th>
                        <th><span class="rw-visuellement-cache">{{ __('sftp.rollback_titre') }}</span></th>
                    </tr>
                </thead>
                <tbody>
                    @foreach ($historique as $h)
                        <tr>
                            <td>{{ $h->deployed_at }}</td>
                            <td>{{ $h->auteur ?? '—' }}</td>
                            <td>
                                <span class="rw-pastille rw-pastille--{{ $h->status === 'applied' ? 'ok' : ($h->status === 'failed' ? 'echec' : 'neutre') }}">
                                    {{ __('sftp.etat_' . $h->status) }}
                                </span>
                            </td>
                            {{-- Le bloc REELLEMENT ecrit, pas une description. --}}
                            <td><code class="rw-code">{{ $h->new_file_content }}</code></td>
                            {{--
                                Une capacite non portee n'est pas un bouton
                                inerte : l'annulation reecrit un bloc SSH sur la
                                machine, elle n'est pas portee, et le dire vaut
                                mieux qu'un bouton qui ne fait rien.
                            --}}
                            <td class="rw-tableau__actions">
                                @if (in_array($h->status, ['applied', 'superseded'], true))
                                    <a class="rw-lien" data-rw="sftp-rollback-legacy"
                                       href="{{ rtrim(config('app.url_legacy'), '/') }}/adm/server_user_sftp.php?server={{ $machine }}&user={{ $compte }}"
                                       target="_blank" rel="noopener"
                                       title="{{ __('sftp.rollback_texte') }}">{{ __('sftp.rollback_lien') }} ↗</a>
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


    {{-- ═══ LE DEFI DE RE-AUTHENTIFICATION — A5, SON DEUXIEME CONSOMMATEUR ══

         Les gestes de cette page (`deploy`, `remove`) figurent dans
         `RoutesBackend::MOTIFS_STEP_UP` : la passerelle les refuse par un
         `403` qui porte `step_up_required` ET `action`. Sans ce panneau,
         l'utilisateur recevait le refus et n'avait AUCUN moyen de le lever —
         le message lui disait d'aller sur l'ancien portail, qui n'existera
         plus apres la bascule.

         Le panneau vit EN PAGE et ne recouvre pas ce sur quoi on decide : le
         legacy pose un modal par une surcouche de `window.fetch`, et on
         confirme alors sans voir la regle qu'on ecrit. --}}
    <div class="rw-panneau-decision" data-rw="sftp-panneau-stepup" hidden>
        <p class="rw-panneau-decision__texte">{{ __('step_up.panneau_titre') }}</p>
        <p class="rw-aide rw-prose">{{ __('step_up.panneau_aide') }}</p>
        <label class="rw-champ">
            <span class="rw-champ__etiquette">{{ __('step_up.panneau_code') }}</span>
            <input type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code"
                   class="rw-saisie rw-saisie--code" data-rw="sftp-stepup-code">
        </label>
        <div class="rw-panneau-decision__actions">
            <button type="button" class="rw-bouton rw-bouton--discret"
                    data-rw="sftp-stepup-annuler">{{ __('step_up.panneau_annuler') }}</button>
            <button type="button" class="rw-bouton"
                    data-rw="sftp-stepup-valider">{{ __('step_up.panneau_valider') }}</button>
        </div>
    </div>

    {{-- Les libelles du defi, depuis le catalogue PARTAGE : `step-up.js` sert
         deux pages, et un libelle recopie par page divergerait. --}}
    <script id="sftp-stepup-libelles" type="application/json">@json(__('step_up'))</script>
    <script id="sftp-libelles" type="application/json">@json($libelles)</script>
    {{-- LE MODULE PARTAGE D'ABORD : le script de page l'INSTALLE, donc il doit
         etre defini quand celui-la s'execute. --}}
    <script src="/js/step-up.js?v={{ @filemtime(public_path('js/step-up.js')) ?: '0' }}"></script>
    <script src="/js/acces-sftp.js?v={{ @filemtime(public_path('js/acces-sftp.js')) ?: '0' }}"></script>
@endsection
