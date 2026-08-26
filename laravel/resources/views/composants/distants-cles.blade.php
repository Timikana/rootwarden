@extends('layouts.portail', ['titre' => __('distants.cles_titre', ['nom' => $username])])

@section('corps')
    <h1 class="rw-titre">{{ __('distants.cles_titre', ['nom' => $username]) }}</h1>
    {{-- ON N'AFFICHE QUE L'EMPREINTE, et la table ne stocke rien d'autre. Une
         clé publique n'est pas un secret, mais la lister en clair dans une page
         d'administration n'apporte rien qu'une empreinte n'apporte déjà. --}}
    <p class="rw-sous-titre rw-prose">{{ __('distants.cles_desc') }}</p>

    <section class="rw-carte rw-carte--pleine">
        <div class="rw-tableau-cadre">
            <table class="rw-tableau" data-rw="distants-cles-liste">
                <thead>
                    <tr>
                        <th>{{ __('distants.col_type') }}</th>
                        <th>{{ __('distants.col_empreinte') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('distants.col_commentaire') }}</th>
                        <th>{{ __('distants.col_origine') }}</th>
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
                        </tr>
                    @empty
                        <tr><td colspan="4"><p class="rw-aide">{{ __('distants.aucune_cle') }}</p></td></tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </section>
@endsection
