{{--
  Les entrees du menu. UN SEUL rendu, utilise par la barre laterale ET par le
  tiroir. Le legacy decrit son menu deux fois, avec la logique de droits
  recopiee : c'est ce qu'on ne refait pas ici.

  Attend :
    $menu      tableau section => entrees, deja filtre par Navigation::pour()
    $variante  'laterale' | 'tiroir' — n'agit que sur l'habillage
--}}
@php($courant = request()->path())

@foreach ($menu as $section => $entrees)
    <div class="rw-menu__section">{{ __('nav.section_' . $section) }}</div>

    @foreach ($entrees as $entree)
        @if (isset($entree['route']))
            {{-- Page PORTEE : lien interne. --}}
            @php($cible = route($entree['route']))
            <a class="rw-menu__lien @if (trim(parse_url($cible, PHP_URL_PATH) ?? '', '/') === $courant) rw-menu__lien--actif @endif"
               href="{{ $cible }}">
                <span class="rw-menu__libelle">{{ __('nav.' . $entree['cle']) }}</span>
            </a>
        @else
            {{--
              Page NON PORTEE : lien vers l'ancien portail, dans un nouvel
              onglet, avec un marqueur visible. Un lien qui change de portail
              sans le dire est un lien qui trahit l'utilisateur.
            --}}
            <a class="rw-menu__lien rw-menu__lien--externe"
               href="{{ rtrim(config('app.url_legacy'), '/') . $entree['legacy'] }}"
               target="_blank" rel="noopener"
               title="{{ __('nav.non_porte_titre') }}">
                <span class="rw-menu__libelle">{{ __('nav.' . $entree['cle']) }}</span>
                <span class="rw-menu__marqueur">{{ __('nav.non_porte') }} ↗</span>
            </a>
        @endif
    @endforeach
@endforeach
