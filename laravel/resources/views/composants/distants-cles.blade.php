@extends('layouts.portail', ['titre' => __('distants.cles_titre', ['nom' => $username])])

@section('corps')
    <h1 class="rw-titre">{{ __('distants.cles_titre', ['nom' => $username]) }}</h1>
    {{-- ON N'AFFICHE QUE L'EMPREINTE, et la table ne stocke rien d'autre. Une
         clé publique n'est pas un secret, mais la lister en clair dans une page
         d'administration n'apporte rien qu'une empreinte n'apporte déjà. --}}
    <p class="rw-sous-titre rw-prose">{{ __('distants.cles_desc') }}</p>

    <section class="rw-carte rw-carte--pleine">
        <div class="rw-tableau-cadre">
            <table class="rw-tableau" data-rw="distants-cles-liste"
                   data-machine="{{ $machine }}" data-username="{{ $username }}">
                <thead>
                    <tr>
                        <th>{{ __('distants.col_type') }}</th>
                        <th>{{ __('distants.col_empreinte') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('distants.col_commentaire') }}</th>
                        <th>{{ __('distants.col_origine') }}</th>
                        <th>{{ __('distants.col_action') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse ($cles as $k)
                        <tr data-rw="distants-cle-ligne">
                            <td><code class="rw-code">{{ $k['key_type'] }}</code></td>
                            <td><code class="rw-code">{{ $k['fingerprint_sha256'] }}</code></td>
                            <td class="rw-colonne-secondaire">{{ $k['comment'] ?: '—' }}</td>
                            <td>
                                @if ($k['is_platform_key'])
                                    <span class="rw-badge rw-badge--ok">{{ __('distants.cle_plateforme') }}</span>
                                @else
                                    <span class="rw-badge rw-badge--neutre">{{ __('distants.cle_tierce') }}</span>
                                @endif
                            </td>
                            {{--
                                ⛔ LE BOUTON N'EST PAS RENDU SUR LA CLE PLATEFORME.
                                Le backend refuse ce retrait sans un `force` explicite
                                (`ssh.py:2474`, « ne pas se locker hors du serveur »), et
                                ce portage n'envoie jamais ce champ. Rendre le bouton ici
                                produirait donc un 400 a chaque clic — et un bouton qui
                                echoue toujours au meme endroit apprend a l'operateur que
                                les echecs sont normaux.
                            --}}
                            <td data-rw="distants-cle-action">
                                @unless ($k['is_platform_key'])
                                    <button type="button" class="rw-bouton rw-bouton--danger rw-bouton--minuscule"
                                            data-rw="distants-cle-retirer"
                                            data-empreinte="{{ $k['fingerprint_sha256'] }}">{{ __('distants.cle_retirer') }}</button>
                                @endunless
                                <span data-rw="distants-cle-verdict"></span>
                            </td>
                        </tr>
                    @empty
                        <tr><td colspan="5"><p class="rw-aide">{{ __('distants.aucune_cle') }}</p></td></tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </section>

    <script id="distants-cles-libelles" type="application/json">@json($libellesCles ?? [])</script>
    <script src="/js/distants-cles.js?v={{ @filemtime(public_path('js/distants-cles.js')) ?: '0' }}"></script>
@endsection
