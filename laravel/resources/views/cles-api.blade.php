@extends('layouts.portail', ['titre' => __('cles.title')])

@section('corps')
    <h1 class="rw-titre">{{ __('cles.title') }}</h1>
    <p class="rw-sous-titre rw-prose">{{ __('cles.desc') }}</p>

    <p class="rw-annonce @if ($succesDirect || session('succes')) rw-annonce--ok @endif @if ($erreurDirecte || session('erreur')) rw-annonce--echec @endif"
       data-rw="cles-annonce" role="status" aria-live="polite">
        {{ $succesDirect ?? $erreurDirecte ?? session('succes') ?? session('erreur') ?? '' }}
    </p>

    {{-- ═══ La clé, une seule fois ═══════════════════════════════════════════
         `$cleUnique` arrive DIRECTEMENT de la réponse au POST — jamais d'un
         message de session, dont le pilote est `file` et déposerait la valeur
         sur le disque. Elle n'est ni relue, ni réaffichée : recharger la page
         fait disparaître ce bloc, et il n'existe aucun chemin pour le
         retrouver, la table ne stockant qu'un haché. --}}
    @if ($cleUnique)
        <div class="rw-panneau-decision" data-rw="cle-api-panneau">
            <p class="rw-panneau-decision__texte">{{ __('cles.unique_titre') }}</p>
            <p><code class="rw-code" data-rw="cle-api-valeur">{{ $cleUnique }}</code></p>
            <p class="rw-aide rw-prose">{{ __('cles.unique_aide') }}</p>
        </div>
    @endif

    {{-- ═══ Création ═════════════════════════════════════════════════════════
         PAS DE CHAMP LIBRE POUR LA PORTÉE, et c'est la décision du sous-lot.
         Le legacy en offre un (« Avancé : éditer les regex manuellement ») ;
         il est validé en PCRE et appliqué en Python (E-135), et il n'ancre
         rien (E-136). Une entrée libre validée se contourne ; une entrée libre
         absente, non. --}}
    <section class="rw-carte rw-carte--pleine">
        <details data-rw="cle-api-bloc" @if ($erreurDirecte) open @endif>
            <summary class="rw-sous-titre-fort">{{ __('cles.creer_titre') }}</summary>

            <form method="POST" action="{{ route('cles-api.creer') }}" data-rw="cle-api-form">
                @csrf
                <div class="rw-grille">
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('cles.champ_nom') }} *</span>
                        <input type="text" name="nom" required maxlength="100"
                               pattern="[a-zA-Z0-9_-]{3,100}" placeholder="supervision-nagios"
                               class="rw-saisie rw-saisie--compacte" data-rw="cle-api-nom">
                        <span class="rw-aide">{{ __('cles.aide_nom') }}</span>
                    </label>
                    <label class="rw-champ">
                        <span class="rw-etiquette">{{ __('cles.champ_indice') }}</span>
                        <input type="text" name="indice" maxlength="200"
                               placeholder="{{ __('cles.indice_placeholder') }}"
                               class="rw-saisie rw-saisie--compacte" data-rw="cle-api-indice">
                        <span class="rw-aide">{{ __('cles.aide_indice') }}</span>
                    </label>
                </div>

                <p class="rw-etiquette">{{ __('cles.portee_titre') }} *</p>
                <p class="rw-aide rw-prose">{{ __('cles.portee_aide') }}</p>
                <div class="rw-liste-selection" data-rw="cle-api-portees">
                    @foreach ($modules as $module)
                        <label class="rw-liste-selection__ligne">
                            <input type="checkbox" name="modules[]" value="{{ $module }}"
                                   data-rw="cle-api-module" data-module="{{ $module }}">
                            <span>
                                <span class="rw-etiquette">{{ __('cles.module_' . $module) }}</span>
                                {{-- LES MOTIFS SONT MONTRÉS. Une portée qu'on
                                     coche sans voir ce qu'elle couvre n'est pas
                                     une décision. --}}
                                <code class="rw-aide">{{ implode('  ', $motifsParModule[$module]) }}</code>
                            </span>
                        </label>
                    @endforeach
                </div>

                <div class="rw-actions">
                    <span class="rw-actions__gauche rw-aide">{{ __('cles.requis') }}</span>
                    <button type="submit" class="rw-bouton" data-rw="cle-api-creer">{{ __('cles.btn_creer') }}</button>
                </div>
            </form>
        </details>
    </section>

    {{-- ═══ Les clés existantes ══════════════════════════════════════════════ --}}
    <section class="rw-carte rw-carte--pleine">
        <p class="rw-etiquette">{{ __('cles.liste_titre', ['n' => count($cles)]) }}</p>

        <div class="rw-tableau-cadre">
            <table class="rw-tableau" data-rw="cles-tableau">
                <thead>
                    <tr>
                        <th>{{ __('cles.col_nom') }}</th>
                        {{-- LE PREFIXE S'EFFACE AVANT L'ACTION. Au 390 px, c'est
                             lui qui cedait la place a « Révoquer » — or c'est un
                             appoint d'identification, pas un geste. La colonne
                             ACTIONNABLE ne cede jamais. --}}
                        <th class="rw-colonne-secondaire">{{ __('cles.col_prefixe') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('cles.col_portee') }}</th>
                        <th class="rw-colonne-secondaire">{{ __('cles.col_usage') }}</th>
                        <th>{{ __('cles.col_etat') }}</th>
                        <th>{{ __('cles.col_action') }}</th>
                    </tr>
                </thead>
                <tbody>
                    @forelse ($cles as $c)
                        @php
                            $motifs = $c['scope_json'] ? (json_decode($c['scope_json'], true) ?: []) : [];
                        @endphp
                        <tr data-rw="cle-api-ligne" data-nom="{{ $c['name'] }}">
                            <td>
                                <strong>{{ $c['name'] }}</strong>
                                @if ($c['auto_generated'])
                                    <span class="rw-badge rw-badge--neutre">{{ __('cles.auto') }}</span>
                                @endif
                                @if ($c['consumer_hint'])
                                    <span class="rw-aide">{{ $c['consumer_hint'] }}</span>
                                @endif
                            </td>
                            {{-- LE PRÉFIXE, JAMAIS LE HACHÉ. Le service ne le
                                 sélectionne même pas : il n'a aucune raison de
                                 traverser l'application. --}}
                            <td class="rw-colonne-secondaire"><code class="rw-code">{{ $c['key_prefix'] }}</code></td>
                            <td class="rw-colonne-secondaire">
                                @if ($motifs === [])
                                    {{-- UNE PORTÉE VIDE VAUT TOUTES LES ROUTES
                                         côté backend (`helpers.py:72`). Le dire
                                         plutôt que de laisser une case vide. --}}
                                    <span class="rw-badge rw-badge--attention">{{ __('cles.portee_totale') }}</span>
                                @else
                                    <code class="rw-aide">{{ implode('  ', $motifs) }}</code>
                                @endif
                            </td>
                            <td class="rw-colonne-secondaire">
                                @if ($c['last_used_at'])
                                    {{ $c['last_used_at'] }}
                                    @if ($c['last_used_ip'])<span class="rw-aide">{{ $c['last_used_ip'] }}</span>@endif
                                @else
                                    <span class="rw-aide">{{ __('cles.jamais_utilisee') }}</span>
                                @endif
                            </td>
                            <td>
                                @if ($c['revoked_at'])
                                    <span class="rw-pastille rw-pastille--echec">{{ __('cles.revoquee_etat') }}</span>
                                @else
                                    <span class="rw-pastille rw-pastille--ok">{{ __('cles.active') }}</span>
                                @endif
                            </td>
                            <td>
                                @if (! $c['revoked_at'])
                                    <form method="POST" action="{{ route('cles-api.revoquer', ['id' => $c['id']]) }}">
                                        @csrf
                                        <button type="submit" class="rw-bouton rw-bouton--danger rw-bouton--minuscule"
                                                data-rw="cle-api-revoquer" data-id="{{ $c['id'] }}">
                                            {{ __('cles.btn_revoquer') }}
                                        </button>
                                    </form>
                                @endif
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="6">
                                <div class="rw-vide" data-rw="cles-vide">
                                    <p><strong>{{ __('cles.vide') }}</strong></p>
                                    <p class="rw-prose">{{ __('cles.vide_aide') }}</p>
                                </div>
                            </td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </section>
@endsection
