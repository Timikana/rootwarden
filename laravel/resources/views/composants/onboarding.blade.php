{{--
    L'ASSISTANT DE PREMIERE CONFIGURATION.

    ⚠ CE BLOC NE SERA PROBABLEMENT JAMAIS VU PAR L'EQUIPE. Le produit est
    auto-heberge : cet assistant sert des deploiements neufs, et sur toute
    installation deja configuree il est vide ou masque. **On ne peut donc pas le
    valider par ce qu'on voit** — c'est le service qui porte la logique, et sa
    table de verite force les huit etats un par un.

    Rendu seulement si `$onboarding !== null` : le controleur decide, le gabarit
    n'a aucun predicat de role a recopier.
--}}
<section class="rw-carte rw-carte--pleine" data-rw="onboarding">
    <div class="rw-entete-avec-action">
        <div>
            <h2 class="rw-sous-titre-fort">{{ __('onboarding.titre') }}</h2>
            <p class="rw-prose rw-aide">{{ __('onboarding.sous_titre') }}</p>
        </div>
        {{-- UN FORMULAIRE, PAS UN SCRIPT. Le geste est idempotent et sans
             consequence : il ne merite ni compte rendu ni mise a jour
             partielle. --}}
        <form method="POST" action="{{ route('onboarding.masquer') }}">
            @csrf
            <button type="submit" class="rw-bouton rw-bouton--discret"
                    data-rw="onboarding-masquer">{{ __('onboarding.masquer') }}</button>
        </form>
    </div>

    {{-- L'AVANCEMENT EST DIT EN CHIFFRES **ET** EN BARRE. Une barre seule se
         lit a l'oeil et ne se mesure pas ; un test qui l'asserterait mesurerait
         un style. Le compte, lui, est du texte. --}}
    <p class="rw-prose" data-rw="onboarding-avancement">
        {{ __('onboarding.avancement', ['faites' => $onboarding['faites'], 'total' => $onboarding['total']]) }}
    </p>
    <div class="rw-jauge" role="progressbar" aria-valuemin="0" aria-valuemax="100"
         aria-valuenow="{{ $onboarding['pourcent'] }}"
         aria-label="{{ __('onboarding.avancement', ['faites' => $onboarding['faites'], 'total' => $onboarding['total']]) }}">
        <div class="rw-jauge__part" style="width: {{ $onboarding['pourcent'] }}%"></div>
    </div>

    @if ($onboarding['terminee'])
        <div class="rw-annonce rw-annonce--ok" data-rw="onboarding-termine">
            <strong>{{ __('onboarding.termine_titre') }}</strong>
            <p class="rw-prose">{{ __('onboarding.termine_desc') }}</p>
            <form method="POST" action="{{ route('onboarding.masquer') }}">
                @csrf
                <button type="submit" class="rw-bouton"
                        data-rw="onboarding-masquer-definitif">{{ __('onboarding.termine_cta') }}</button>
            </form>
        </div>
    @endif

    <ol class="rw-liste-etapes" data-rw="onboarding-etapes">
        @foreach ($onboarding['etapes'] as $i => $etape)
            <li class="rw-liste-etapes__ligne{{ $etape['faite'] ? ' rw-liste-etapes__ligne--faite' : '' }}"
                data-rw="onboarding-etape" data-cle="{{ $etape['cle'] }}"
                data-faite="{{ $etape['faite'] ? '1' : '0' }}">
                {{-- LE MARQUEUR PORTE UN TEXTE, pas seulement une couleur et un
                     signe. Un « ✓ » vert et un chiffre bleu ne disent rien a qui
                     ne distingue pas les deux teintes. --}}
                <span class="rw-liste-etapes__rang" aria-hidden="true">{{ $etape['faite'] ? '✓' : $i + 1 }}</span>
                <span class="rw-visuellement-cache">{{ $etape['faite'] ? __('onboarding.fait') : __('onboarding.a_faire') }}</span>

                <div class="rw-liste-etapes__corps">
                    <p class="rw-liste-etapes__titre">{{ __('onboarding.etape_' . $etape['cle'] . '_titre') }}</p>
                    <p class="rw-aide rw-prose">{{ __('onboarding.etape_' . $etape['cle'] . '_desc') }}</p>

                    @if ($etape['cle'] === 'cle_plateforme')
                        {{-- LA DIVERGENCE DE DETECTION SE DIT A L'ECRAN. Le legacy
                             compte une table qui n'existe pas ; on lit les serveurs
                             qui portent la cle. Qui lit l'assistant doit savoir sur
                             quoi il se fonde. --}}
                        <p class="rw-aide" data-rw="onboarding-source">{{ __('onboarding.cle_plateforme_source') }}</p>
                    @endif

                    @if ($etape['avertit'])
                        <p class="rw-alerte rw-alerte--attention rw-prose"
                           data-rw="onboarding-avertissement">{{ __('onboarding.avert_sans_cle') }}</p>
                    @endif
                </div>

                {{-- LE LIEN N'EXISTE QUE SI L'ETAPE RESTE A FAIRE **ET** SI LA PAGE
                     EST OUVERTE AU COMPTE. `$etape['lien']` est resolu par le menu
                     dans le controleur : une page fermee ne produit aucun lien,
                     plutot qu'un lien vers un 403. --}}
                @if (! $etape['faite'] && $etape['lien'] !== null)
                    <a class="rw-bouton rw-bouton--discret rw-liste-etapes__action"
                       data-rw="onboarding-cta" href="{{ $etape['lien'] }}"
                       @if ($etape['externe']) target="_blank" rel="noopener" @endif>
                        {{ __('onboarding.etape_' . $etape['cle'] . '_cta') }}@if ($etape['externe']) ↗ @endif
                    </a>
                @endif
            </li>
        @endforeach
    </ol>
</section>
