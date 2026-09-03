{{--
  Selecteur de langue. Un seul rendu, utilise par le gabarit du portail ET par
  les ecrans d'authentification.

  Le lien conserve la page courante et n'ajoute que `lang` : basculer de langue
  ne doit pas faire perdre l'ecran ou l'on se trouve. `request()->fullUrlWithQuery`
  remplace le parametre s'il existe deja, au lieu de l'empiler.
--}}
<span class="rw-langues" role="group" aria-label="{{ __('nav.langue') }}">
    @foreach (\App\Http\Middleware\Langue::LANGUES as $code)
        @if ($code === app()->getLocale())
            <span class="rw-langues__actif" aria-current="true">{{ strtoupper($code) }}</span>
        @else
            <a class="rw-langues__lien"
               href="{{ request()->fullUrlWithQuery(['lang' => $code]) }}"
               data-rw="langue-{{ $code }}"
               title="{{ __('nav.langue_basculer', ['langue' => __('nav.langue_' . $code)]) }}">{{ strtoupper($code) }}</a>
        @endif
    @endforeach
</span>
