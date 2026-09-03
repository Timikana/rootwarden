@extends('layouts.portail', ['titre' => __('autorisations.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('autorisations.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('autorisations.desc') }}</p>

    {{-- ── CE QUE LA PAGE N'EST PAS, DIT AVANT SON CONTENU ─────────────────

         Un titre qui promettrait une reference d'API serait la meme faute un
         etage plus haut que celle qu'on vient de retirer. La reserve est donc
         posee AVANT les tableaux, pas en note de bas de page. --}}
    <div class="rw-encart" data-rw="passerelle-pas-reference">
        <p class="rw-sous-titre-fort">{{ __('autorisations.pas_reference_titre') }}</p>
        <p class="rw-prose">{{ __('autorisations.pas_reference_texte') }}</p>
    </div>

    {{-- ── LES TROIS COUCHES, ET CELLE QUE LA PAGE DECRIT ──────────────────

         Trois couches d'autorisation ont deja diverge dans ce produit. Une page
         qui les melangerait refabriquerait le defaut qu'elle documente : chaque
         enonce nomme donc la sienne, et la troisieme est declaree INVISIBLE
         plutot que devinee. --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.couches_titre') }}</h2>
    <ol class="rw-liste-effets rw-liste-effets--ordonnee rw-prose" data-rw="passerelle-couches">
        <li>{{ __('autorisations.couche_1') }}</li>
        <li><strong>{{ __('autorisations.couche_2') }}</strong></li>
        <li>{{ __('autorisations.couche_3') }}</li>
    </ol>
    <p class="rw-aide rw-prose">{{ __('autorisations.couches_aide') }}</p>

    {{-- ── LES COMPTEURS, TOUS DERIVES ─────────────────────────────────── --}}
    <div class="rw-grille rw-titre--espace">
        @foreach ([
            ['blanche', $compteurs['liste_blanche'], 'compte_blanche'],
            ['espaces', $compteurs['espaces'], 'compte_espaces'],
            ['admin', $compteurs['admin'], 'compte_admin'],
            ['flux', $compteurs['flux'], 'compte_flux'],
            ['reauth', $compteurs['motifs_reauth'], 'compte_reauth'],
        ] as [$cle, $valeur, $libelle])
            <div class="rw-tuile" data-rw="passerelle-compte-{{ $cle }}">
                <span class="rw-tuile__valeur">{{ $valeur }}</span>
                <p class="rw-tuile__texte">{{ __('autorisations.' . $libelle) }}</p>
            </div>
        @endforeach
    </div>

    {{-- ── POURQUOI CETTE PAGE REMPLACE UN FICHIER AU LIEU DE LE PORTER ─── --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.remplace_titre') }}</h2>
    <p class="rw-prose">{{ __('autorisations.remplace_texte') }}</p>
    <p class="rw-prose">{{ __('autorisations.remplace_detail') }}</p>
    <p class="rw-prose">{{ __('autorisations.remplace_raison') }}</p>
    {{-- LE SILENCE HERITE EST NOMME. Une page derivee qui ne dirait rien des 64
         routes non documentees heriterait du silence du fichier qu'elle
         remplace — et un document qui omet ce qu'il ne sait pas est plus
         trompeur qu'un document date. --}}
    <p class="rw-aide rw-prose" data-rw="passerelle-silence">{{ __('autorisations.remplace_silence') }}</p>

    {{-- ── LA LISTE BLANCHE ────────────────────────────────────────────── --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.blanche_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('autorisations.blanche_aide') }}</p>

    <div class="rw-tableau-cadre">
        <table class="rw-tableau" data-rw="passerelle-blanche">
            <thead>
                <tr>
                    <th>{{ __('autorisations.th_motif') }}</th>
                    <th>{{ __('autorisations.th_portee') }}</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($listeBlanche as $e)
                    <tr>
                        <td class="rw-tableau__mono">{{ $e['motif'] }}</td>
                        <td>
                            {{-- LA PORTEE S'ECRIT EN MOT, et son sens est dans le
                                 `title` : « espace de noms » sans explication ne
                                 dit pas qu'un prefixe suffit a passer. --}}
                            <span class="rw-pastille rw-pastille--{{ $e['espace'] ? 'attente' : 'neutre' }}"
                                  title="{{ $e['espace'] ? __('autorisations.portee_espace_aide') : __('autorisations.portee_route_aide') }}">
                                {{ $e['espace'] ? __('autorisations.portee_espace') : __('autorisations.portee_route') }}
                            </span>
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    {{-- ── LA RESERVE A L'ADMINISTRATION ───────────────────────────────── --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.admin_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('autorisations.admin_aide') }}</p>

    @if ($compteurs['admin_orphelines'] === 0)
        {{-- UN COMPTEUR A ZERO S'ENONCE. « Aucune entree sans objet » dit
             quelque chose ; l'absence de section ne dit rien. --}}
        <p class="rw-annonce rw-annonce--ok" data-rw="passerelle-admin-aucune-orpheline">
            {{ __('autorisations.admin_aucune_orpheline') }}
        </p>
    @endif

    <div class="rw-tableau-cadre">
        <table class="rw-tableau" data-rw="passerelle-admin">
            <tbody>
                @foreach ($reserveAdmin as $e)
                    <tr>
                        <td class="rw-tableau__mono">{{ $e['motif'] }}</td>
                        <td>
                            @if ($e['couverte'])
                                <span class="rw-tableau__discret">{{ __('autorisations.admin_couverte') }}</span>
                            @else
                                <span class="rw-badge rw-badge--alerte">{{ __('autorisations.admin_orpheline') }}</span>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </div>

    {{-- ── LE RELAIS EN FLUX ───────────────────────────────────────────── --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.flux_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('autorisations.flux_aide') }}</p>
    <p class="rw-aide rw-prose" data-rw="passerelle-flux-espace">{{ __('autorisations.flux_par_espace') }}</p>

    <ul class="rw-liste-effets rw-prose" data-rw="passerelle-flux">
        @foreach ($flux as $f)
            <li>
                <code class="rw-code">{{ $f['chemin'] }}</code>
                @unless ($f['autorise'])
                    <span class="rw-badge rw-badge--alerte">{{ __('autorisations.flux_hors_liste') }}</span>
                @endunless
            </li>
        @endforeach
    </ul>

    {{-- ── LA RE-AUTHENTIFICATION ──────────────────────────────────────── --}}
    <h2 class="rw-section__entete rw-titre--espace">{{ __('autorisations.reauth_titre') }}</h2>
    <p class="rw-aide rw-prose">{{ __('autorisations.reauth_aide') }}</p>

    @if (count($motifsReauth) === 0)
        <p class="rw-aide" data-rw="passerelle-reauth-aucune">{{ __('autorisations.reauth_aucune') }}</p>
    @else
        <ul class="rw-liste-effets rw-prose" data-rw="passerelle-reauth">
            @foreach ($motifsReauth as $m)
                <li><code class="rw-code">{{ $m }}</code></li>
            @endforeach
        </ul>
    @endif
@endsection
